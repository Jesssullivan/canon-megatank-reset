# Agent Notes — canon-megatank-reset

Working contract for coding agents and humans. Read this first. `README.md`
captures product intent; this file captures operating conventions.

## Repo Role

`canon-megatank-reset` is a **Linux-first, fleet-reproducible** tool that resets
the **waste-ink / ink-absorber counter** ("5B00 ink absorber full") on Canon
**MegaTank G-series** printers (lead unit: PIXMA **G6020**, USB `04a9:1865`,
"G6000 series"), over **native pyusb** — no Wine, no per-unit vendor keys, no
vendor cloud in production.

It is built on a **reverse-engineered, formally-modelled** understanding of the
maintenance protocol. The proprietary tools are **RE oracles only**:
- **Canon Service Tool** (v5103) — static RE via Ghidra (`ghidra/`).
- **WICReset / WIC Reset Connect** (PrinterPotty build) — RE oracle + capture
  source under Wine on the capture host.
- **Canon firmware** (pixma decrypt lineage) — dispatch-table cross-check (blocked
  on G6020 firmware sourcing).

This repo was extracted (history-preserving) from `printstack` on 2026-05-29.
printstack keeps only its CUPS `office` print queue for the G6020; reset lives here.

## Authoritative Entrypoints

- **DX/AX**: `Justfile` is the **single source of truth** for every operation
  (python, ansible, capture, Ghidra, CI). Always invoke via `just <recipe>`.
  Never call `pytest` / `ansible-playbook` / `ghidra` / `tshark` directly outside it.
- **Shell**: `nix develop` (auto-loaded by `direnv`) — never assume host toolchain.
  CI runs `nix develop --command just <recipe>`.
- **Check**: `just check` — lint + typecheck + yaml/ansible lint (static gates).
- **Test**: `just test` — pytest (fingerprint, pcap, protocol-model property tests).

## Runtime Stack

- Python ≥ 3.12 (one env: `pyproject.toml` + nix `flake.nix`; deps: pyusb,
  structlog, ruamel.yaml; dev: pytest, hypothesis, ruff, mypy strict).
- Ansible (host capture/RE environment + future fleet deploy) under `host/`.
- Ghidra 11.4.2 + Wine (Flathub) + Xvfb/xdotool + tshark — on the **capture host**
  (mbp-13), provisioned by the `canon_tool_dev` role. NOT in the dev devShell.

## Architecture (oracles → verified protocol → native tool)

```
RE oracles ─┬─ Canon Service Tool (Ghidra static)   ┐
            ├─ WICReset (Wine + usbmon/API/net trace)├─► verified protocol spec ─► native pyusb tool
            └─ firmware dispatch table (cross-check)  ┘     (docs/spec/, model.py)   (src/canon_megatank/)
```

The wire frame, transport, and the **reset payload + write cipher are recovered and
hardware-validated**: the native libusb 5B00 clear was proven on a real G6020
(23/23 byte-exact against a genuine captured frame; printer rebooted to normal
`04a9:1865` after a clean power-button shutdown — see
`docs/runbook/g6020-native-reset.md`). The tool writes to the printer EEPROM **only**
via the gated `reset-native --execute` path (test-unit UUID isolation, mandatory
pre-flight EEPROM dump, write budget, lockfile). It is **dry-run by default**, and
while the SSOT status (`printers/canon-g6020/maintenance.yaml`) is
`derived-unvalidated` it hard-stops unless `--accept-derived` is also passed for a
single run on the locked debug unit.

## Safety Model (enforced in code, not docs)

`src/canon_megatank/` + `printers/canon-g6020/maintenance.yaml` enforce:
1. **test_unit UUID isolation** — refuse any UUID ≠ locked `test_unit`.
2. **Write budget** — cap (50) per unit, persisted; refuse when exhausted.
3. **Mandatory EEPROM dump** — pre-flight dump + checksum before any write.
4. **Ping-suite baseline** — documented-safe ops; drift aborts.
5. **Lockfile guard** — `/run/canon-tool/in-progress` prevents mid-write restart.
6. **Differential determinism** — replay only verified-deterministic captures.

## RE / build phases (the tranche)

See the plan + `docs/adr/0007`. T0 bootstrap → T1 reproducible capture (no key)
→ T2 WIC static RE → T3 formal model → T4 ground-truth (spend key, after pads)
→ T5 native tool + fleet deploy → T6 contribution (pixma/Octo upstream).

## Current Fleet Reality

- **Capture host**: `mbp-13` (Rocky Linux 10, Budgie/Wayland, tailnet), G6020 on
  USB bus 001, fw **1.070**, stuck on **5B00**. Maintenance lane = interface 4,
  bulk OUT `0x03` / IN `0x86`.
- One purchased WICReset key (held by operator, **never** committed). Spent only
  in T4, after the physical waste-ink kit is installed.

## Interop

`leecher1337/pixma` (via `jesssullivan/pixma`) firmware-decrypt lineage — see
`INTEROP.md`. Future: upstream protocol findings + collaborate with OctoInkjet.
