# canon-megatank-reset

**Linux-first, fleet-reproducible reset of the Canon MegaTank waste-ink / ink-absorber
counter** ("5B00 — ink absorber is full"), built on a reverse-engineered, formally
modelled understanding of the printer's maintenance protocol.

Canon's MegaTank G-series printers refuse to print once an internal counter decides the
waste-ink absorber is "full" — even after the absorber is physically serviced. The
official remedy is a service-centre visit; the unofficial ones are a Windows-only Service
Tool or a commercial resetter (WICReset) that charges a **single-use key per printer**.
Neither is acceptable for a Linux fleet doing its own right-to-repair refurb.

This project recovers the reset protocol from those tools (as **RE oracles**) and
reimplements it as an **open, native Linux pyusb tool** — no Wine, no per-unit keys, no
vendor cloud — behind strict safety gates, deployable across a fleet via Ansible.

> **Status:** the native, key-free, cloud-free 5B00 reset is **recovered and
> hardware-validated.** The usbprint vendor transport, the session protocol, and the
> write cipher are all cracked (**23/23** byte-exact against a genuine captured frame),
> and the native libusb clear **cleared 5B00 on a real G6020** — the printer rebooted
> out of service mode to normal `04a9:1865` after a clean power-button shutdown. The
> tool is **dry-run by default**; `--execute` is gated behind test-unit UUID isolation,
> a mandatory pre-flight EEPROM dump, a persisted write budget, and a lockfile, and
> while the SSOT status is `derived-unvalidated` it hard-stops unless you also pass
> `--accept-derived` for a single run on the locked debug unit. **This is a debug/RE
> tool for hardware you own, with waste pads installed** — service the absorber before
> resetting. It is not a press-button-anywhere resetter. Full validated procedure:
> `docs/runbook/g6020-native-reset.md`.

## Fixing another Canon? Start with the field guide

Unbricking a **different** Canon (any PIXMA / MegaTank / G-series stuck on
**5B00 / "waste ink absorber full"** or another service code)? Read the
model-agnostic [**Canon service-mode RE field guide**](docs/research/canon-service-mode-field-guide.md)
— it generalizes the validated G6020 work (service-mode entry, the vendor
control-transfer transport, the session/keyword handshake, the EEPROM counter and
commit-on-power-button behavior, the cipher to expect, and the usbmon↔Frida↔Ghidra
method) into a reusable guide for *your* model, with links to the concrete evidence.

## What's here

| Path | What |
|---|---|
| `src/canon_megatank/` | the tool — safety gates + USB + pcap analysis (reset ops land in T5) |
| `printers/canon-g6020/maintenance.yaml` | SSOT — fingerprint, supported ops, write budget, recovered protocol |
| `ghidra/` | model-agnostic Ghidra headless RE scripts (Canon Service Tool + WICReset) |
| `scripts/` | usbmon capture harnesses (Wine + WICReset, headless) |
| `docs/` | ADR, research (RE findings), runbooks, spec (formal protocol model), legacy notes |
| `host/` | Ansible — capture/RE host setup (`canon_tool_dev`) + future fleet deploy |

## Quick start

```sh
direnv allow        # loads the Nix devShell
just --list         # all operations (Justfile is the sole entrypoint)
just check          # lint + typecheck
just test           # pytest + protocol property tests
```

## Safety

The lead test unit is the only printer that may receive a write until the protocol is
locked. Every write passes: test-unit UUID isolation, a persisted write budget, a
mandatory pre-flight EEPROM dump, a ping-suite baseline check, and a lockfile guard. See
`AGENTS.md` → Safety Model.

## License

Dual-licensed by split:

- **Code** (everything outside `docs/`) — **zlib/libpng License** (SPDX: `Zlib`).
  See [`LICENSE`](LICENSE).
- **Documentation + the academic paper** (`docs/`, including `docs/paper/`) —
  **Creative Commons Attribution 4.0 International** (`CC-BY-4.0`). See
  [`LICENSE-docs`](LICENSE-docs).

Copyright (c) 2026 Jess Sullivan.

## Lineage & interop

Builds on the "doomed encryption" firmware lineage (`leecher1337/pixma` via
`jesssullivan/pixma`) for firmware cross-checks. See `INTEROP.md`. Extracted from
`tinyland`'s `printstack` repo (history preserved). Right-to-repair; see `SECURITY.md`.
