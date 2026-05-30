# Canon Service Tool v5103 — static RE of the absorber-reset path (Lane A)

**Binary:** `ServiceTool_v5103.exe` · **sha256 (verified):**
`98ca97b37a36a73d1a91630b8bde455b7dd109960073a0369295e34be6317c48` (matches the
pin in `maintenance.yaml::service_tool_versions.v5103.exe_sha256`). · **Date:**
2026-05-30. Binary + Ghidra project are **not** committed (no Canon
redistribution — ADR 0007); analysis artifacts live under `.ghidra-work/`
(gitignored). Extractor: `ghidra/v5103_absorber_extract.py`; raw decompiler
output: `.ghidra-work/out/v5103/absorber.txt` (3543 functions analyzed).

This completes the Service-Tool side of the literal-byte recovery that WICReset
could not provide (WICReset is cloud-fed — see `wicreset-static-re.md` T4). Every
value below is quoted from the decompiler/`getBytes` output; nothing is inferred
beyond what the disassembly shows.

## 1. The absorber "Set" handler — payload assembly (CONFIRMED)

`FUN_0040b6c0` (and its twin `FUN_0040d140`) build the group-7 payload on the
stack, exactly as Finding E predicted — now confirmed by decompiler output:

```c
LVar1 = SendMessageA(combo @ +0x2114, CB_GETCURSEL=0x147, 0, 0);  // sel
local_18 = 0;                                                      // [0] = 0x00
local_17 = 3;                                                      // [1] = 0x03
local_16 = 1;                                                      // [2] = flags, base 0x01
LVar2 = SendMessageA(checkbox @ +0x1d78, BM_GETCHECK=0xf0, 0, 0);  // checkbox
local_14 = (&DAT_0048295c)[LVar1 * 8];                            // [4] = idx (table lookup)
local_16 = local_16 | (LVar2 != 1) - 1U & 0x80;                  // flags |= 0x80 if checked
local_15 = 3;                                                      // [3] = 0x03
FUN_0040ac60(param_1, 7, &local_18);                             // dispatch group 7
```

**Payload (5 bytes, stack order `local_18,17,16,15,14`):**
```
[ 0x00 ][ 0x03 ][ flags ][ 0x03 ][ idx ]
flags = 0x01            (checkbox unchecked)
      = 0x81            (checkbox checked: 0x01 | 0x80)
```
This matches the SSOT `pre_transform_payload` byte-for-byte. The
`(LVar2 != 1) - 1U & 0x80` idiom: checked (`LVar2==1`) → `0 & 0x80 = 0`… wait —
checked yields `(1!=1)-1 = -1 = 0xFFFFFFFF`, `& 0x80 = 0x80`; unchecked yields
`(0!=1)-1 = 0`, `& 0x80 = 0`. So **checked → 0x81, unchecked → 0x01**. Confirmed.

## 2. The idx table `DAT_0048295c` (LITERAL VALUES RECOVERED)

`getBytes(0x48295c, 128)` — an array of `{ u32 idx; ptr label }` structs
(stride 8). The Set handler indexes `(&DAT_0048295c)[sel*8]` → since the array is
typed as bytes in the decompile, `sel*8` lands on the `u32 idx` low byte of each
struct. Recovered table:

| sel | idx | sel | idx |
|----:|:---:|----:|:---:|
| 0 | `0x00` | 8 | `0x01` |
| 1 | `0x01` | 9 | `0x03` |
| 2 | `0x03` | 10 | `0x04` |
| 3 | `0x04` | 11 | `0x05` |
| 4 | `0x05` | 12 | `0x06` |
| 5 | `0x06` | 13 | `0x02` |
| 6 | `0x07` | 14 | `0x00` |
| 7 | `0x00` | 15 | `0x01` |

Raw (first 64 bytes):
```
+000  00 00 00 00 94 1c 47 00  01 00 00 00 a8 1c 47 00
+010  03 00 00 00 b4 1c 47 00  04 00 00 00 c0 1c 47 00
+020  05 00 00 00 cc 1c 47 00  06 00 00 00 d8 1c 47 00
+030  07 00 00 00 8c 1c 47 00  00 00 00 00 94 1c 47 00
```
The absorber selectors use **idx ∈ {0x00..0x07}**.

### idx labels RESOLVED (follow-up, 2026-05-30)

`ghidra/v5103_followup_extract.py` dereferenced each row's label pointer (the
second u32 of the `{u32 idx; char* label}` struct). The `sel → (idx, name)` map:

| sel | idx | label | | sel | idx | label |
|----:|:---:|---|---|----:|:---:|---|
| 0 | `0x00` | **Platen** | | 6 | `0x07` | **Main** |
| 1 | `0x01` | **Main_Black** | | 12 | `0x06` | **Main&Platen** |
| 2 | `0x03` | **Main_Color** | | 5 | `0x06` | All |
| 3 | `0x04` | Platen_Away | | 13 | `0x02` | "0" |
| 4 | `0x05` | Platen_Home | | 14/15 | … | "10"/"20" (numeric, other dialog) |

**CORRECTION:** the earlier "candidate main idx=0x00" guess was WRONG — `0x00` is
the **Platen**, not the main absorber. The **5B00 main ink absorber is `idx=0x07`
("Main")**; `Main_Black=0x01`, `Main_Color=0x03`, `Main&Platen=0x06`. So the
absorber-reset payload for the main counter is:

```
[ 0x00, 0x03, flags, 0x03, 0x07 ]      flags = 0x01 (or 0x81 with checkbox)
```

This is the literal G-series-family payload for the 5B00 main-absorber reset
(label-confirmed). G6020-applicability is still the family hypothesis (§6).

## 3. EncCommService is the TRANSPORT class — NOT a payload obfuscator (KEY FINDING)

Finding F called `EncCommService` an "obfuscation ceiling." The v5103 decompile
**corrects that**: `EncCommService` is the class that owns the device handle and
issues the usbscan IOCTL. Its low-level primitive `FUN_004302c0` (the
`vtable[0x48]` transmit target) shows the payload is written to the wire
**verbatim — no transform**:

```c
// FUN_004302c0(this, cmd, arg, mode=0, payload*, len, outlen*, timeout)
param_3 = param_5 + 3;                    // total = 3-byte header + payload len
local_4 = 0x220038;                       // SEND IOCTL
lpInBuffer = GlobalAlloc(0x40, param_3);
puVar4 = lpInBuffer + 3;
for (... param_5 >> 2 ...) *puVar4 = *param_4;   // word copy of payload, UNCHANGED
for (... param_5 & 3  ...) *puVar4 = *param_4;   // byte tail copy, UNCHANGED
lpInBuffer[0] = cmd;                      // header
lpInBuffer[1] = arg >> 8;                 // arg_hi (big-endian)
lpInBuffer[2] = arg;                      // arg_lo
DeviceIoControl(handle, 0x220038, lpInBuffer, 3+len, NULL, 0, outlen, overlapped);
```

There is **no XOR / table / scramble** applied to the payload bytes on this path.
The `[00,03,flags,03,idx]` block reaches the wire unmodified. The RECV branch
(`mode != 0`) uses `0x22003c` with a bare 3-byte header — identical to the model.

> **Verdict: PASSTHROUGH for the group-7 absorber path.** The "EncComm" name
> refers to the transport/command service object (`EncCommService::vftable` at
> `FUN_0042aa20`), and the `FUN_0040fb40` "anti-tamper" wrapping (TOOL_0006 license
> strings) gates *whether* a command runs, not *what bytes* it sends. So the exact
> wire bytes are statically derivable — no dynamic capture needed to learn the
> transform, because there isn't one on this path. (Confidence: high for the
> payload-passthrough claim, from the verbatim memcpy in `FUN_004302c0`.)

## 4. The transmit preamble (`vtable[0x44]`, 6-byte mode block)

Before the payload transmit, `FUN_0040ac60` sends a 6-byte preamble via
`vtable[0x44]` when the prior mode differs:
```c
uStack_20 = DAT_004921f8;  uStack_1f = DAT_004921f9;
(**(code**)(*lParam + 0x44))(DAT_00494ca0, dev, &preamble, 6);
```
`getBytes(0x4921f8, 16)`:
```
+000  12 34 00 00 01 00 00 00  d4 57 47 00 00 00 00 00
```
So the preamble mode block begins `12 34 00 00 01 00` (the first 6 bytes). This is
a session/mode set, sent once per mode change, ahead of the group-7 payload.

## 5. cmd / arg for the group-7 transmit (PARTIAL)

`FUN_0040ac60(this, 7, &payload)` dispatches; the final transmit is
`(**(code**)(*lParam + 0x48))(DAT_00494ca0, dev, param_2, retaddr)` where `param_2`
points at the payload struct. The literal `(cmd, arg)` passed into
`FUN_004302c0`'s `param_1`/`param_2` are set by an intermediate wrapper not fully
resolved in this dump (the `*lParam` vtable slot 0x48 target). Finding A's generic
framing gives `cmd = 0x85` (SEND) with the operation identity carried in the
payload; that is consistent with the passthrough finding but the **exact cmd/arg
for group 7 is not yet pinned from v5103** — a follow-up decompile of the slot-0x48
wrapper will close it.

## 6. Coverage caveat — v5103 stops at G4010 (family hypothesis UNVALIDATED)

String anchors in this binary: **`G3010 series` and `G4010 series` are present;
`G6000` and `G6020` are absent** (0 hits each). So v5103 has no G6020-specific
model entry. The recovered idx table + payload structure are the **G-series
MegaTank family** encoding (G3010/G4010 era). Using them for the G6020 rests on the
**family-shared-protocol hypothesis** (ADR 0007) — plausible (same MegaTank
architecture generation) but **NOT confirmed for the G6020**. The independent
confirmation comes from Lane C (firmware dispatch-table cross-check) and, finally,
the physical reset on the real unit (after pads).

## 7. What this gives the T3 model (and what's still PENDING)

**Now KNOWN (static, no key, no cloud):**
- Payload: `[00, 03, flags, 03, idx]`, `flags ∈ {0x01, 0x81}`, `idx ∈ {0x00..0x07}`.
- **Main-absorber `idx = 0x07` ("Main")** — label-confirmed (follow-up). So the
  5B00 main-counter reset payload is `[00, 03, 0x01, 03, 0x07]` (or flags 0x81).
- Transport: payload is **passthrough** (no EncCommService transform on group 7);
  frame = `[cmd][arg_hi][arg_lo][00,03,flags,03,idx]`, big-endian arg, `0x220038`.
- 6-byte session preamble `12 34 00 00 01 00` precedes the transmit.

**Still PENDING:**
1. **Exact `(cmd, arg)`** — the transmit is a C++ **virtual** call
   (`(*lParam + 0x48)(...)`), and `FUN_004302c0` (the IOCTL primitive) has **0
   direct callers** (reached only through the vtable), so the literal `(cmd, arg)`
   can't be read by a direct caller decompile. The documented design is that
   **operation identity rides in the payload, not the cmd byte** (maintenance.yaml
   `command_protocol.wire_frame.note`), with the generic SEND `cmd=0x85, arg=0`.
   So `cmd=0x85, arg=0x0000` is the working value; pinning it byte-exact needs
   either resolving the concrete EncCommService vtable instance or the eventual
   usbmon confirmation. **Not a blocker** — the payload (incl. idx=0x07) is the
   operative content.
2. ~~Label-confirm the main-absorber idx~~ — **DONE**: idx=0x07 = "Main".
3. **G6020 confirmation** — family hypothesis (§6); resolved by Lane C firmware
   cross-check + the eventual physical reset.

The reset payload is now fully recovered for the G-series family; only the
(non-operative) header cmd/arg and the G6020-vs-family question remain, neither
requiring the key.
