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

> **Status:** early. Protocol RE in progress (transport + wire framing + dispatch
> recovered; reset payload/key derivation is the open target). The native reset path is
> gated behind validation against a real captured reset. See `docs/adr/0007` and the
> tranche plan. **Do not point this at a printer yet.**

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

## Lineage & interop

Builds on the "doomed encryption" firmware lineage (`leecher1337/pixma` via
`jesssullivan/pixma`) for firmware cross-checks. See `INTEROP.md`. Extracted from
`tinyland`'s `printstack` repo (history preserved). Right-to-repair; see `SECURITY.md`.
