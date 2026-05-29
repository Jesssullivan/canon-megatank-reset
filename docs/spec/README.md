# Protocol spec (formal model) — T3

This directory will hold the **formal, provable, logically-modellable** specification
of the Canon MegaTank maintenance protocol, derived from the RE oracles and validated
against a real captured reset (T4).

Planned contents:

- `megatank-maintenance-protocol.md` — message grammar
  (`[cmd:u8][arg_hi:u8][arg_lo:u8][payload…]`), transport binding (usbscan IOCTL on
  Windows ↔ pyusb bulk on interface 4, OUT `0x03` / IN `0x86`), the read + reset
  message sequences, and the **reset-derivation function** (key/state → reset packet)
  as a state machine + sequence diagrams.
- An **executable reference model** in `src/canon_megatank/protocol/model.py` with
  Hypothesis property tests asserting the invariants: transform determinism per command,
  reset idempotency, fingerprint/UUID gating, write-budget monotonicity.
- Optional: a `model/` TLA+ or Alloy spec of the reset state machine if the logic
  warrants machine-checked proof.

Until this exists and is validated (T4), no native write path is enabled.
See `docs/adr/0007` and the current research notes under `docs/research/`.
