# services/canon-tool — agent contract

Read `printstack/AGENTS.md` first.

## Critical rules for this service

1. **Never bypass the safety guards in `fingerprint.py` / `eeprom.py` /
   `lockfile.py`.** These are the only thing between the test unit and
   a brick. If a test requires bypassing them, change the test, not the
   guards.
2. **Every captured byte sequence MUST be pinned to a specific firmware
   version + Service Tool version.** Drift detection refuses to replay
   a sequence captured against fw X on a printer running fw Y unless
   explicitly overridden with `--accept-firmware-drift`. The override
   is human-only; code must never set it.
3. **Hardware writes are budgeted.** The 50-write cap per test unit is
   a hard limit. Exhausted budget → manual review + new test unit.
4. **One named test unit only.** Until the protocol is locked,
   `maintenance.yaml::test_unit.uuid` is the only printer that may
   receive a write. Refuse all others.
5. **Pcap fixtures are committed evidence.** Every successful op has a
   gzipped pcapng + `.meta.yaml` sidecar in `captures/`. Regression
   suite replays against fixtures, not live hardware.

## Pattern for adding a new operation

When a new op (e.g. `head_clean_counter_reset`) is captured + locked:

1. Add the byte sequence + metadata under `supported:` in
   `printers/canon-g6020/maintenance.yaml`.
2. Add an entry in `ops.py::OPERATIONS` mapping op name → builder
   function that returns the bytes (parameterized if needed).
3. Add a pcap fixture + .meta.yaml under
   `services/canon-tool/captures/`.
4. Add a regression test in `tests/test_replay_against_fixtures.py`
   that replays the fixture and asserts the expected printer response.
5. NEVER add an op without a fixture. The fixture IS the spec.

## Things this service does NOT do

- Firmware flash (handled by separate path; out of scope).
- Vendor protocol exploration (that's Wine/QEMU + Wireshark + Ghidra;
  the service consumes the result).
- Decryption of pixma firmware blobs (that's vendored
  `jesssullivan/pixma`).
- Any I/O that isn't routed through `usb.py::ClaimedDevice` — direct
  pyusb calls are forbidden outside that module.

## Logging convention

- structlog, JSON output, request_id from caller's context if present
  (matches `src/lib/log.ts` request_id field).
- Every op logs: `printer_uuid`, `firmware`, `op_name`, `outcome`,
  `elapsed_ms`. No bytes in logs (PII concern at scale, performance
  concern always).
- Errors logged with `level=error` and `err_type` field for prom-client
  counter labels.
