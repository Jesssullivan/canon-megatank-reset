# Protocol spec (formal model)

The formal specification of the Canon MegaTank service-mode maintenance protocol —
the hardware-validated 5B00 reset, recovered from the RE oracles.

- **[`megatank-maintenance-protocol.md`](megatank-maintenance-protocol.md)** — the
  validated protocol: the usbprint vendor **control-transfer** transport
  (`0x41` SET / `0xC1` GET), the four-step keyed session
  (`set_session` → `get_keyword` → `set_command` → clean power-button commit), the
  functor-3 envelope + functor-2 role-swap write cipher (23/23 byte-exact), the
  `APP.BIN` → `devices.xml` template provenance, and the cloud-is-licensing-only
  finding. Implementation modules + tests are cross-referenced inline.
- **Executable invariants** — `src/canon_megatank/protocol/model.py` (the legacy
  normal-mode grammar model) + `tests/test_protocol_model.py` (Hypothesis) assert the
  still-valid generic invariants: frame round-trip + determinism, big-endian `arg`,
  reset idempotency, UUID write-gating, write-budget monotonicity, and no SSOT drift.
  Run with `just model`.

Status: **hardware-validated** on a real G6020. See `docs/adr/0007` and the
model-agnostic [field guide](../research/canon-service-mode-field-guide.md).
