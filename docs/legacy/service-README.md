# services/canon-tool

Linux-native open-source equivalent of Canon's Windows-only Service Tool,
scoped to fleet refurb of Canon PIXMA G-series MegaTank printers
(G6020 first; G3000/G4000/G7000 generalization in Phase C).

**Status:** Phase A in flight — protocol bytes not yet captured. The
scaffolding here is the receiving structure for evidence from R1
(Wine+usbmon) and R2 (QEMU+Win11+USBPcap) capture spikes. Once a
byte sequence for absorber-reset is locked in `printers/canon-g6020/
maintenance.yaml`, this service replays it via pyusb against the named
test unit.

See:
- `docs/adr/0007-canon-tool-reverse-engineering.md` — the locked plan
- `docs/runbook/canon-tool-r1-cheap-spike.md` — Wine path
- `docs/runbook/canon-tool-r2-qemu-spike.md` — QEMU path
- `printers/canon-g6020/maintenance.yaml` — protocol fingerprint + SSOT

## Module layout (planned)

```
src/printstack_canon/
├── __init__.py
├── main.py             # systemd entrypoint + signal handling
├── cli.py              # CLI for ad-hoc ops (capture-replay, dump, ping)
├── types.py            # typed exceptions + dataclasses
├── usb.py              # pyusb wrapper with vendor-id allowlist (safe-by-default)
├── fingerprint.py      # loads maintenance.yaml + verifies runtime fingerprint match
├── ping.py             # the "ping suite" — known-safe ops (status, fw-version, nozzle-check)
├── eeprom.py           # pre-flight dump + checksum + verify (mandatory before any write)
├── ops.py              # maintenance ops keyed by firmware fingerprint
├── replay.py           # pcap → live; differential capture detector
└── lockfile.py         # /run/canon-tool/in-progress write-cycle guard
```

Phase A milestone: a green `pytest services/canon-tool/tests/` against
the named test unit, with `services/canon-tool/captures/*.pcapng`
fixtures pinned to firmware version `1.070`.

## Safety enforcement

This service is **walk-up-only** and **physical-button-confirmation-gated**
at the HTTP layer (see `src/routes/maintenance/+server.ts`). The Python
layer additionally enforces:

1. Pre-flight ping suite must succeed; any drift aborts.
2. Pre-flight EEPROM dump + checksum mandatory before any write.
3. Write-cycle budget capped at 50 per test unit (counter in
   `printers/canon-g6020/maintenance.yaml::write_budget.consumed`).
4. Refused on any UUID that isn't the named `test_unit`.
5. Lockfile in `/run/canon-tool/in-progress` prevents systemd restart
   mid-write.

If you bypass these guards in code, you will eventually brick a printer.

## Not in scope

- Other printer vendors (Snapmaker, Sovol, Bambu) — separate services.
- Canon firmware reflash / update — pixma firmware decryption lives in
  the vendored `jesssullivan/pixma` fork; this service does not write
  firmware.
- Print/scan paths — those are CUPS + paperless, handled at the host
  level.

## Why USB and not a print-protocol command?

Canon's IPP-USB layer (the `ipp-usb` bridge running at loopback :60001)
exposes IPP attributes (firmware, status, alerts) but not maintenance
operations. The absorber-reset opcode is in Canon's IVEC1-type-4 IJP
sub-protocol carried over the USB bulk-OUT endpoint — not over IPP.
This service must claim the bulk endpoint directly (hence the udev
rule + printstack group).

Concurrency note: while this service has the bulk endpoint claimed,
CUPS can't print via `ipp-usb`. The systemd unit's `ExecStartPost`
releases the device on idle; `ExecStop` always closes.
