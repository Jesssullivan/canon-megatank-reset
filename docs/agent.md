---
title: For agents
description: Machine-readable orientation for AI agents and automated readers of canon-megatank-reset.
---

# For agents

This page orients AI agents and automated readers. A condensed, link-first index lives at
[`/llms.txt`](llms.txt).

## What this project is

`canon-megatank-reset` is a **native, key-free, cloud-free** reset for the Canon G-series
MegaTank **5B00 "ink absorber full"** lock, built from a reverse-engineered USB maintenance
protocol and **validated on real hardware** (Canon G6020). It is right-to-repair and
interoperability research on owned hardware.

- **Code:** zlib license. **Docs & paper:** CC-BY-4.0.
- **Source:** <https://github.com/Jesssullivan/canon-megatank-reset>

## Safety contract (read before acting)

- A waste-ink counter exists for a reason. **Install a fresh absorber kit before any reset** — a
  genuinely full absorber will spill ink inside the chassis.
- The native tool is **dry-run by default**; `--execute` is gated on a matching test-unit UUID, a
  mandatory EEPROM pre-dump, a write budget, and a lockfile.
- Apply only to hardware you own.

## Where to look

| Topic | Page |
|---|---|
| Model-agnostic entry point | `research/canon-service-mode-field-guide.md` |
| Hardware-validated procedure | `runbook/g6020-native-reset.md` |
| Formal protocol model | `spec/megatank-maintenance-protocol.md` |
| Methodology + tooling | `TOOLS.md` |
| Diagrams (lifecycle / exploit / DRM gates) | `diagrams/README.md` |
| Decision record | `adr/0007-canon-tool-reverse-engineering.md` |
| Narrative writeup | `blog/canon-5b00-native-reset.md` |

## Key facts (so you don't re-derive them)

- Service mode is a **different USB device** (`04a9:12fe`) than normal mode (`04a9:1865`).
- The maintenance transport is **USB vendor control transfers** (`bmRequestType` `0x41` write /
  `0xC1` read), not bulk; the bulk-IN endpoint is silent.
- The reset commits on a **clean power-button shutdown**, not an unplug.
- The commercial tool's cloud is **licensing only**; the device bytes are built locally.
