# Live reset write #1 — derived bytes on the debug G6020 (2026-05-31)

**First write of a maintenance command from our native tool to the real printer.**
Dedicated debug/RE unit (non-functional, 5B00-locked, purpose-built for this).
Instrumented with usbmon. Captures: `captures/live/reset-derived-*.pcapng`.

## What ran

`just reset --execute --accept-derived --skip-eeprom-dump` on mbp-13, via the
operator override (the SSOT status stays honest at `derived-unvalidated`; the
override is logged loudly). All other gates enforced: UUID verified, write-budget
charged, lockfile held (in the staging dir via `CANON_RUN_DIR`).

```
reset.override  accept_derived=true skip_eeprom_dump=true
reset.ok        frame=8500000003010307 executed=true
                summary="SENT frame=8500000003010307 [accept_derived OVERRIDE]"
```

## USB-level result: the write COMPLETED

usbmon capture (`reset-derived-20260531-052948.pcapng`):
```
frame 9  ep 0x03 (bulk OUT)  urb='S' (submit)      8 bytes  8500000003010307
frame 10 ep 0x03 (bulk OUT)  urb='C' (complete)    0 bytes  (no error)
```
The 8-byte derived reset frame went out on the maintenance lane (iface 4, EP
`0x03`) and the URB **completed cleanly** — the device accepted the bulk write.
No `0x86` reply (a SEND is fire-and-forget). Contrast the earlier cold read,
which timed out: the SEND does not.

## Printer state AFTER the write (pre power-cycle): 5B00 STILL PRESENT

IPP `get-printer-attributes` (ipp-usb restored):
```
printer-state          = stopped
printer-state-reasons  = marker-waste-full-error
printer-alert          = code=markerWasteInkReceptacleFull
firmware               = 1.070
```
The error has **not** cleared. `printer-state-change-time=15` (≈boot) suggests
the state may be the cached boot value.

## Interpretation — two live hypotheses (honest)

1. **Reset needs a power-cycle to take effect.** EEPROM-counter resets commonly
   write the value but only re-evaluate the lock on reboot; the IPP state would
   read stale until then. → **discriminator: power-cycle the printer, re-check.**
2. **Accepted-but-ineffective.** The device ACKed 8 bytes but the command wasn't
   a complete reset — e.g. it needs `execute_set_session` (the 6-byte preamble
   `12 34 00 00 01 00` via vtable[0x44]) first, exactly as the READ needed an
   arming SEND. The bare group-7 SEND with no session prologue may be a no-op.

## Next (in order)

1. **Power-cycle the G6020 + re-run the state check** (`scripts/`-style IPP read).
   If 5B00 clears → derived bytes VALIDATED; promote SSOT
   `derived-unvalidated → verified-captured`. If not → hypothesis 2.
2. If not cleared: recover + prepend the **session prologue** (the
   `execute_set_session` / 6-byte mode block) before the group-7 SEND, then
   re-run. This is the same "needs a prior SEND" pattern the read exhibited.

No EEPROM write was confirmed either way; the write budget was charged (1 use).

## UPDATE — power-cycled, 5B00 PERSISTS → hypothesis 2 confirmed

Post power-cycle IPP read: `marker-waste-full-error` still present, and
`printer-state-change-time` advanced (39, fresh boot) — so it's **not** a stale
cache. The bare group-7 SEND was **accepted-but-ineffective**. Hypothesis 2 holds:
**the reset needs the session-open handshake the Service Tool runs before the
payload SEND.**

### The full reset sequence (from FUN_0040ac60, the dispatcher)

The dispatcher drives a chain of EncCommService vtable methods on the transport
object (`lParam = FUN_0040f4f0()`) BEFORE the payload SEND — we sent only the
last step:

```
[vtable+0x5c]  open/init session         (abort on nonzero)
[vtable+0x20]  ?                          (abort on nonzero)
[vtable+0x24]  ?                          (abort on nonzero)
[vtable+0x28]  ?                          (abort on nonzero)
[vtable+0x40]  (DAT_00494ca0)             (abort on nonzero)
[vtable+0x44]  (dev, &preamble, 6)        ← 6-byte MODE block 12 34 00 00 01 00
                                            (DAT_004921f8/9), sent on mode change
[vtable+0x48]  (dev, payload, ...)        ← the group-7 reset payload  ← WE SENT ONLY THIS
```

So a working reset is: **open session (0x5c) → 0x20/0x24/0x28/0x40 init steps →
6-byte mode preamble (0x44) → group-7 payload SEND (0x48)**. Each `0x5c/0x20/...`
slot is an EncCommService method; several are likely their own usbscan IOCTLs
(open-pipe / set-mode), not just in-memory state.

### Decision point

Replicating the full handshake by static RE means decompiling + reproducing
5–6 vtable methods (each possibly its own IOCTL) under the TOOL_0006 anti-tamper
noise — doable but expensive. The cheaper, definitive alternative is a **usbmon
capture of the Service Tool (or WICReset) performing one real reset**: it shows
the EXACT open→preamble→payload byte sequence on the wire, which we replay
verbatim. That capture needs the Windows tool running with USB passthrough (the
QEMU VM lane). Either way the missing piece is now precisely scoped: the
**session-open prologue**, not the payload (which is correct + ACKed).
