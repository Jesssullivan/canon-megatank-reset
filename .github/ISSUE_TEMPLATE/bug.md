---
name: Bug
about: Report a bug in the tool, the protocol model, the RE evidence, or the docs
title: ''
labels: ['bug']
assignees: ''
---

## Description

<!-- What did you expect? What happened? If this is a protocol/cipher
     mismatch, say which byte / step diverged. -->

## Area

<!-- Tick the one that fits best. -->

- [ ] CLI / `reset-native` op (`src/canon_megatank/`)
- [ ] Protocol model / cipher (`src/canon_megatank/protocol/`, `docs/spec/`)
- [ ] Safety gate (UUID isolation, write budget, EEPROM dump, lockfile, status gate)
- [ ] SSOT (`printers/canon-g6020/maintenance.yaml`)
- [ ] RE evidence (`docs/research/`)
- [ ] Docs / runbook (`docs/`, `AGENTS.md`, `README.md`)
- [ ] Ansible host role / capture harness (`host/`, `scripts/`)
- [ ] CI / Justfile / flake

## Steps to Reproduce

<!-- Prefer a `just` recipe + the exact command. -->

```sh
just <recipe>
```

1.
2.
3.

## Expected vs actual output

<!-- Paste the relevant `just check` / `just test` / CLI log. For a wire-frame
     mismatch, include the dry-run (`canon-megatank reset-native`) frame bytes.
     DO NOT paste a purchased WICReset key or any credential. -->

## Environment

- `just --version` / host:
- Dev shell: `nix develop` via direnv? (yes / no)
- Python (`python --version`):
- Hardware (only if a live-run bug): printer model, USB id (`04a9:1865` normal /
  `04a9:12fe` service), firmware, normal vs service mode:

## Evidence / traceability

<!-- If this is a protocol claim, link the `docs/research/` file and the test
     that should cover it. See CONTRIBUTING.md → Traceability. -->

## Additional context

<!-- Console errors, pcap excerpts, screenshots. Never include secrets. -->
