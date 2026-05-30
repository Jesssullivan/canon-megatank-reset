# Protocol spec (formal model) — T3

The **formal, provable, logically-modellable** specification of the Canon MegaTank
maintenance protocol, derived from the RE oracles and validated against a real
captured reset (T4).

Contents:

- **[`megatank-maintenance-protocol.md`](megatank-maintenance-protocol.md)** — message
  grammar (`[cmd:u8][arg_hi:u8][arg_lo:u8][payload…]`), transport binding (usbscan
  IOCTL on Windows ↔ pyusb bulk on interface 4, OUT `0x03` / IN `0x86`), the read +
  reset message sequences, the **reset-derivation function** as a state machine, and an
  explicit **known-vs-pending** boundary with the T4 validation contract.
- **Executable reference model** — `src/canon_megatank/protocol/model.py`, with
  Hypothesis property tests in `tests/test_protocol_model.py` asserting the invariants:
  frame round-trip + determinism, big-endian `arg`, absorber payload shape, reset
  idempotency, UUID write-gating, write-budget monotonicity, and **no SSOT drift**.
  Run with `just model`.

Status: transport + grammar **two-tool corroborated** (Service Tool + WICReset); the
literal G6020 reset bytes are **pending T4 ground-truth**. Until T4 validates the
model, no native write path is enabled. See `docs/adr/0007` and the research notes
under `docs/research/`.
