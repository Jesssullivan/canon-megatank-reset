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
