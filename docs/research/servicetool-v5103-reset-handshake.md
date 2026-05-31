# Canon Service Tool v5103 — reset session handshake (Lane A static RE)

**Binary:** `ServiceTool_v5103.exe` (sha `98ca97…`). · **Date:** 2026-05-31.
Evidence: `.ghidra-work/out/v5103/{handshake,vtable2,slotchains,memprobe}.txt`
(gitignored). Read-only project reuse, no re-import.

Recovers the **structure** of the open-session handshake the dispatcher
`FUN_0040ac60` runs before the group-7 payload SEND. **Honest boundary: the
structure is solid; several literal bytes are runtime-sourced and therefore NOT
statically recoverable** — see §"What's UNKNOWN". This is what makes the Lane B
wire capture necessary.

## Transport object + vtable

- `FUN_0040f4f0()` → `&DAT_00494ee0` (the transport object), an **EncCommService**
  instance (ctor `FUN_0042aa20` sets `*obj = EncCommService::vftable @ 0x471dec`).
- Object layout: vtable at object+0 (cross-checked: slot 0x48 reaches the known
  group-7 SEND, cmd 0x85).
- The IOCTL primitive `FUN_004302c0(this, cmd, arg, mode, buf, len, outlen, to)`:
  `mode==0` → SEND `0x220038` (header `[cmd][arg_hi][arg_lo]` + payload);
  `mode!=0` → RECV `0x22003c`. **Passthrough** (payload copied verbatim).

## The dispatcher sequence (FUN_0040ac60), in order

```
lParam = FUN_0040f4f0()                       // transport (EncCommService)
[vtable+0x5c]()                  abort if !=0  // open/init   — in-memory/handle setup, NO bulk frame
[vtable+0x20]()                  abort if !=0  //   "
[vtable+0x24]()                  abort if !=0  //   "
[vtable+0x28]()                  abort if !=0  //   "
[vtable+0x40](DAT_00494ca0)      abort if !=0  // SEND cmd 0x81 + RECV cmd 0x82 (64B)  [see UNKNOWN]
// if mode not already set (and model != 'G'):
uStack_20 = DAT_004921f8; uStack_1f = DAT_004921f9;   // preamble bytes
[vtable+0x44](DAT_00494ca0, dev, &preamble, 6)        // 6-byte MODE preamble SEND (cmd 0x85) + poll
[vtable+0x48](DAT_00494ca0, dev, payload, ...)        // group-7 reset payload SEND (cmd 0x85) ← we sent ONLY this
```

Resolved slot targets (base `0x471dec`): 0x5c→`FUN_0042ad30`, 0x20→`FUN_0042c130`,
0x24→`FUN_0042c360`, 0x28→`FUN_0042c680`, 0x40→`FUN_0042c4e0`, 0x44→`FUN_0040f880`,
0x48→`FUN_0040fb40`. (Resolved via the vftable `pointer[27]` Data components — raw
`getBytes` returns zeros because the program is opened read-only and `.rdata`/
`.data` annotations carry the values.)

## What's KNOWN vs UNKNOWN (the honest line)

**KNOWN (high confidence):**
- The ordered call sequence above.
- Slots 0x5c/0x20/0x24/0x28 do **no bulk I/O** (in-memory/handle setup).
- There is a **mode-preamble SEND before the payload** (cmd 0x85), and its body
  **starts** `12 34 00 00 01` (the dispatcher copies `DAT_004921f8/9` into the
  first 2 bytes of a stack buffer passed with len 6).
- The payload SEND is cmd 0x85 (re-confirms our derived `85 00 00` + payload).

**UNKNOWN — statically unrecoverable (runtime-sourced):**
- **Preamble byte 5+**: `12 34 00 00 01 ?? ?? ??`. The `.data` at `0x4921f8` reads
  **all zeros at rest** (`memprobe.txt`) — the real bytes are written at runtime.
  Static RE cannot pin them.
- **The 0x40-slot frame**: SEND cmd `0x81` carries a 1-byte payload from
  `DAT_00494ca0` (runtime global, 0 at rest, 26 runtime writers) + a RECV cmd
  `0x82` 64-byte reply. The literal `0x81` payload byte is runtime-sourced.
- The 14-byte tail of the 20-byte `0x85` frames; RECV ack semantics.

## Conclusion → Lane B is necessary

Static RE has reached its structural ceiling: the *shape* is recovered, but the
*literal runtime bytes* (preamble tail, the 0x81 frame's payload) are written at
runtime and zero at rest, so they cannot be derived from the binary. A **usbmon
capture of one real reset** (Lane B) is required to obtain them; this static map
tells us exactly what frames to expect and in what order, so the capture is
interpretable frame-by-frame and we know precisely which bytes we're filling in.
