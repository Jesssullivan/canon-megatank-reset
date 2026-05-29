# Interop & upstream plan

## pixma firmware-decrypt lineage (`leecher1337/pixma`)

The "doomed encryption" firmware work (Context IS) and the `leecher1337/pixma`
tools (`pixma_decrypt`, `pixma_unpack`, `dec_sdata`) are the reference for decoding
Canon MegaTank firmware, which carries the on-printer command **dispatch table** —
our independent cross-check for any reset opcode we recover from the host-side tools.

- Our working fork: `jesssullivan/pixma` (branch `tin-1698-pixma-build-tooling` adds a
  reproducible `Makefile` + portability fix; binaries gitignored).
- We do **not** vendor pixma source here. We reference it as an external dependency
  (clone alongside, or add as a submodule under `third_party/pixma/` when the
  cross-check workflow lands in T2/T3).
- Firmware sourcing for the G6020 is currently **blocked** (panel/internet-only, CDN
  404s) — see `docs/research/canon-tool-firmware-sourcing.md`. The dispatch-table
  cross-check is therefore optional/secondary to the WIC + Service Tool oracles.

## Future upstream / collaboration (T6)

Once the protocol is verified and the native tool works:
1. Publish the **protocol spec** (`docs/spec/`) and RE notes cleanly (clean-room,
   interop/right-to-repair framing — see `SECURITY.md`).
2. Offer the firmware-decrypt improvements + MegaTank findings **upstream to the pixma
   lineage** (PRs from `jesssullivan/pixma`).
3. Engage **OctoInkjet** (WICReset distributor) and the pixma maintainers for proper,
   collaborative publication rather than a silent fork.
4. Mirror to `tinyland-inc` per the standard canonical/mirror topology.
