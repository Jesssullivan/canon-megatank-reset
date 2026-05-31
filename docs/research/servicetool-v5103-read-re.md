# Canon Service Tool v5103 — read/send wire commands (Lane A read-path)

**Binary:** `ServiceTool_v5103.exe` (sha `98ca97…`). · **Date:** 2026-05-31.
Decompiler output: `.ghidra-work/out/v5103/{recv,transport,readbody}.txt`
(gitignored). Recovered via zero-disk project reuse
(`GhidraProject.openProject` + read-only `openProgram`) — no re-import.

This pins the **read** and confirms the **send** wire commands, closing the
"read (cmd,arg) is PENDING" gap from `servicetool-v5103-static-re.md` — by static
RE, no capture, no guessing.

## The transport object is an EncCommService instance

- `FUN_0040f4f0()` returns `&DAT_00494ee0` — the transport object the dispatcher
  (`FUN_0040ac60`) drives.
- `FUN_0046c330` initializes it: `FUN_0042aa20(&DAT_00494ee0)`, and `FUN_0042aa20`
  is the **`EncCommService` constructor** (`*param_1 = EncCommService::vftable`).
- ∴ `DAT_00494ee0` **is an `EncCommService`**; its send/recv methods reach the
  usbscan IOCTL primitive `FUN_004302c0(this, cmd, arg, mode, buf, len, outlen,
  timeout)` — passthrough (no payload transform; see the static-re doc).

## READ — cmd 0x86, RECV, 20-byte status frame

`FUN_0040f500` is the status **read poll loop**. Its core (decompiler-verbatim):

```c
while (FUN_0042b030(param_1[1], 0x86, 0, 1, local_44, 0x14, &local_60, 3000) == 0) {
    ...                         // (handle, cmd, arg, mode=1 RECV, buf, len=0x14, outlen, timeout)
    (**(code **)(*param_1 + 4))(...);   // parse the 20-byte frame
}
```

`FUN_0042b030` forwards to the EncCommService method → `FUN_004302c0`. Decoded:

| field | value | meaning |
|---|---|---|
| cmd | **`0x86`** | generic RECV (matches Finding A) |
| arg | **`0x0000`** | |
| mode | `1` | RECV → IOCTL `0x22003c` |
| len | **`0x14` (20)** | status frame size |
| timeout | 3000 ms | polled in a loop |

So the **status read is `[0x86][0x00][0x00]` → read 20 bytes**.

## SEND — cmd 0x85 (re-confirms the reset header)

`FUN_0040fa60` is the send wrapper:
```c
FUN_0042b030(iStack_14, 0x85, 0, 0, auStack_5c, 0x14, &puStack_74, 3000);
//           (handle,  cmd, arg, mode=0 SEND, buf, len, ...)
```
**cmd `0x85`, arg `0x0000`, mode 0 (SEND)** — independently re-confirms the
reset header we derived (`85 00 00` + payload), from a second function.

## What this gives us — and the honest caveat

**KNOWN now (static, no key, no capture):**
- Status READ command: `cmd=0x86, arg=0x0000`, RECV, 20-byte frame.
- SEND command: `cmd=0x85, arg=0x0000` (re-confirmed).
- Both ride the same EncCommService passthrough transport.

**CAVEAT (do not overclaim):** `0x86/0x0000` is the **generic status RECV** — a
20-byte frame the tool polls. It is the read *transport command* (validated safe
to issue), **not yet** a proven "absorber counter is at offset N of this frame"
decode. Whether the absorber value rides in this status frame directly, or
whether a SEND must first select the counter (as the reset SEND selects
`idx=0x07`), is the remaining open question — resolved by either (a) decoding the
20-byte frame parser `(*param_1 + 4)` in `FUN_0040f500`, or (b) the live read on
the real G6020 (Tier-1: now possible since we have a real, non-guessed read
command) cross-checked against the panel's reported counter.

## Wired in
- `ops.ABSORBER_READ_CMD=0x86`, `ABSORBER_READ_ARG=0x0000`, `STATUS_READ_LEN=0x14`
  (was PENDING/None). `read_counter` default `length` → 20.

## Live attempt + the SEND-then-poll discovery (2026-05-31)

A live `[0x86][00][00]` cold RECV on the real G6020 (mbp-13) **timed out**
(errno 110) — the write reached the device, but a bare RECV returned nothing.
Tracing the sole caller `FUN_0040fb40` (the command sequencer) explains why:

```c
... FUN_0042b030(param_2, 0x85, 0, 0, local_2c0, dwBytes, .., 3000);   // line 606: SEND query (0x85 + body)
... AfxBeginThread(FUN_0040f500, ...);                                  // line 691: THEN poll RECV (0x86) on a thread
```

So a read is **SEND `[0x85][00][00][query_body]` → poll RECV `[0x86]` → 20-byte
reply** — not a bare RECV. The cold RECV timed out because no query SEND armed
it. (`FUN_0040fb40` is heavily laced with TOOL_0006 anti-tamper noise —
`uStack_* = 0x4c4f4f54` "TOOL"/"_000"/"_6_0"/"02" license-token strings +
`thunk_FUN_0042d390` self-checks — interleaved to obscure the real flow; the
operative calls are lines 606 + 691.)

**Risk-tier consequence:** the read is no longer a pure no-write RECV — it needs
a **query SEND** to the maintenance interface first. That SEND is read-intent
(it's how the tool reads) and does NOT write EEPROM, but it is a write to iface 4,
so it sits above Tier-0 (claim-only) on the safety ladder. The `query_body`
(`local_2c0`) is built earlier in `FUN_0040fb40` under the anti-tamper noise —
recovering its exact bytes is the next RE step, OR a usbmon capture of the free
WICReset read would show the SEND+RECV pair directly (separate VM lane).

**Status:** transport + read/send commands recovered; the read **session
prologue (query SEND body)** is the remaining gap for a live read.
