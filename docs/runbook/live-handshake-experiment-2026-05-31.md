# Live handshake experiment — Lane A candidate sequence (2026-05-31)

Tested Lane A's recovered reset handshake live on the debug G6020, instrumented
with usbmon. **Result: every bulk-OUT is ACKed, but every bulk-IN returns 0
bytes — the device gates reads on a session state we are not reaching.** 5B00
persists. This is the honest ceiling of replicate-from-static-RE; the wire
capture (Lane B) is now confirmed necessary.

## What we sent (candidate, with GUESS bytes)

Per `docs/research/servicetool-v5103-reset-handshake.md`, the dispatcher order:
`0x40-frame → preamble → group-7 payload`. We sent
(`scripts/experiment-handshake-reset.py`):
```
81 00 00 00              0x40-frame SEND  (cmd 0x81, GUESS payload 0x00)
  -> read cmd 0x82, 64B  (Lane A: should return 64B)
85 00 00 12 34 00 00 01 00   preamble SEND (cmd 0x85, GUESS byte5=00)
  -> poll cmd 0x86, 20B
85 00 00 00 03 01 03 07  group-7 payload SEND (cmd 0x85, KNOWN)
  -> poll cmd 0x86, 20B
```

## usbmon capture (`captures/live/handshake-exp-20260531-062747.pcapng`)

```
13 ep03 S 4  81000000          14 ep03 C 0   (SEND ACKed)
15 ep03 S 3  820000            16 ep03 C 0   (RECV header ACKed)
17 ep86 S 0                    18 ep86 C 0   ← IN returned 0 BYTES
19 ep03 S 9  850000123400000100 20 ep03 C 0  (preamble ACKed)
21 ep03 S 3  860000            22 ep03 C 0
23 ep86 S 0                    24 ep86 C 0   ← IN returned 0 BYTES
25 ep03 S 8  8500000003010307  26 ep03 C 0   (payload ACKed)
27 ep03 S 3  860000            28 ep03 C 0
29 ep86 S 0                    30 ep86 C 0   ← IN returned 0 BYTES
```

Every `0x03` (OUT) SEND completes cleanly; every `0x86` (IN) read completes with
**`data_len 0`** (→ the errno 110 timeout the tool reports).

## Diagnosis — what's actually missing

The device **accepts writes but won't return any read data** in our session. This
means Lane A's "in-memory only" slots (`0x5c/0x20/0x24/0x28`) are **not no-ops at
the protocol level** — one of them performs the real device-side session open,
which the Service Tool does via its `CreateFileW(\\.\UsbscanN)` + usbscan
open/IOCTL path, NOT the bulk-scan primitive `FUN_004302c0`. Our `ClaimedDevice`
opens the USB interface directly (libusb), which is a *different* open than the
usbscan session the firmware expects before it will reply.

Two consequences:
1. The reads need a **session the device recognizes** — likely a specific
   open/init exchange (control transfer or a distinct IOCTL) we haven't
   replicated. Guessing it is not tractable (it's the part static RE marked
   runtime/handle-level).
2. There may also be an **overlapped/event timing** expectation (`FUN_004302c0`
   waits on an OVERLAPPED event) that a plain libusb bulk read doesn't satisfy.

## Conclusion → Lane B (wire capture) is the path

Static RE gave us the full frame *vocabulary and order* (cmds 0x81/0x82/0x85/0x86,
the sequence, the payload) — but the *session-open semantics* and the *runtime
byte values* are not statically recoverable, and the live device confirms it by
refusing to reply. A **usbmon capture of one real Service-Tool/WICReset reset**
(Lane B headless VM) gives the exact open→preamble→payload→reply byte stream,
including whatever session-open frames precede everything. We replay that
verbatim. This experiment was worth 0 extra budget risk (read-mostly; the one
group-7 SEND was already in our budget) and **decisively scoped the remaining
unknown to the session-open exchange.**
