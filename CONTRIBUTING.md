# Contributing — canon-megatank-reset

Thanks for helping with the open, native-Linux Canon MegaTank 5B00 reset. This is a
**right-to-repair** project: it reverse-engineers and reimplements the waste-ink /
ink-absorber counter reset for printers **you own**, and the tool **writes to a real
printer EEPROM**. That makes correctness, traceability, and the safety posture
non-negotiable. Read `AGENTS.md` (the operating contract) and `ETHICS/RIGHT-TO-REPAIR.md`
before you start, then this guide.

## Entrypoints — always `just`

The `Justfile` is the **single source of truth** for every operation. Never invoke
`pytest`, `ruff`, `mypy`, `ansible-playbook`, `tshark`, or `ghidra` directly — drive them
through a recipe so everyone (and CI) runs the same thing.

```sh
just --list      # every operation, unsorted
just check       # static gates: ruff lint + mypy + yaml-lint + ansible-lint
just test        # pytest (fingerprint, pcap, protocol-model property tests)
```

`just check` and `just test` are what CI runs and what a PR is judged on. If you extend
behaviour, extend the `Justfile` rather than adding ad-hoc commands.

## Dev shell

The toolchain comes from Nix, not your host:

- `nix develop` provides the shell; `direnv allow` auto-loads it. CI runs
  `nix develop --command just <recipe>`.
- The Python env is a project venv: `just setup` creates `.venv` and installs the package
  editable with dev extras (`uv venv .venv && uv pip install -e ".[dev]"`). Python ≥ 3.12;
  deps: `pyusb`, `structlog`, `ruamel.yaml`; dev: `pytest`, `hypothesis`, `ruff`, `mypy`
  (strict).
- Capture/RE-only tooling (Ghidra, Wine, Xvfb/xdotool, tshark) lives **on the capture
  host** (mbp-13) via the `canon_tool_dev` Ansible role — **not** in the dev shell.

Never assume host toolchain; if a tool is missing, add it to the flake / the role, don't
shim it locally.

## Branch + PR flow

1. Branch off `main` with a descriptive name (e.g. `feat/g6020-native-reset`,
   `fix/eeprom-checksum`). Do not commit to `main`.
2. Keep changes targeted — minimum-viable diff. Prefer a focused PR over a refactor
   avalanche.
3. Before opening a PR: `just check` and `just test` must be green, and the secret guard
   must pass (below).
4. Open the PR against `main`. CI (`ci-templates` composites) re-runs the gates. A PR that
   touches a protocol claim must carry its traceability (below).

## Secret guard (gitleaks + the global high-entropy hook)

A global high-entropy pre-commit hook plus `gitleaks` (`just secrets-scan` /
`secrets-scan-dir`, `--config .gitleaks.toml`) scan every commit.

The reverse-engineering evidence in this repo contains **cipher / keystream hex and
captured wire frames** — these are recovered protocol *findings*, not credentials. The
`.gitleaks.toml` allowlist scopes those paths so they don't trip the scanner:

```toml
paths = [
  '''docs/research/.*\.md$''',
  '''docs/paper/.*''',
]
```

So cipher-hex commits under `docs/research/` and `docs/paper/` pass **without**
`--no-verify`. Do **not** reach for `--no-verify` and do **not** widen the allowlist with a
blanket hex regex — that's exactly how a real secret would hide. If new RE hex needs to
land outside those two paths, move it under them or narrow the allowlist deliberately, and
say why in the PR.

## Traceability: RE evidence → code (required)

Every protocol claim must be traceable. The evidence chain is:

```
RE finding → docs/research/<file>.md → src/canon_megatank/<module> → tests/<test>
```

When you assert a protocol fact (a transport detail, a frame layout, a cipher step, a
dispatch value), it must cite **a `docs/research/` evidence file** and be **covered by a
test**. The formal protocol model (`docs/spec/`, `src/canon_megatank/protocol/`) is
property-tested (`just model`); contributions that change the model update the spec, the
research citation, and the tests together. See `docs/README.md` for the full
evidence→code on-ramp, and `docs/adr/0007` for the RE methodology and posture.

## Safety posture (this writes to a printer EEPROM)

The reset path mutates real printer hardware. The safety gates are enforced **in code**
(`src/canon_megatank/` + `printers/canon-g6020/maintenance.yaml`), not in prose, and you
must not weaken them:

1. **test_unit UUID isolation** — refuse any UUID ≠ the locked debug unit.
2. **Mandatory pre-flight EEPROM dump** + checksum before any write.
3. **Write budget** — a persisted per-unit cap; refuse when exhausted.
4. **Lockfile guard** — `/run/canon-tool/in-progress` blocks a mid-write restart.
5. **Status gate** — while the SSOT status is `derived-unvalidated`, `--execute`
   hard-stops unless `--accept-derived` is passed for a single run.

Operational rules: the tool is **dry-run by default**; run `--execute` only on the
**locked debug unit**, only with **waste pads / an external waste-ink tank installed**
(resetting the counter does not empty the absorber — printing on a saturated pad overflows
ink), and commit a clear with a **clean power-button shutdown**, never an unplug. See
`docs/runbook/g6020-native-reset.md`. PRs that touch a safety gate get extra scrutiny and
must explain the change.

## Right-to-repair & dual-use stance

This is interoperability and maintenance of your own property — recovering a protocol from
vendor tools used **as RE oracles** so a physically-serviced printer isn't bricked by a
software counter. We do not build DoS, malware, or bricking capability, and we hold a
clear authorized-repair scope. Read and respect `ETHICS/RIGHT-TO-REPAIR.md` and
`SECURITY.md`; contributions are expected to stay inside that posture.

## Good first issues

New here — human or agent? Start with these. Every one is **desk-doable**: no
live printer, no purchased key, a bounded blast radius, and a clear green check
(`just check` / `just test`). File any of them with the
`good first issue` issue template, or just pick one up. Read `AGENTS.md`,
`docs/README.md`, and the validated runbook (`docs/runbook/g6020-native-reset.md`)
first to orient.

1. **Resolve the `references.bib` TODOs (8 of them).** The paper's bibliography
   tags entries whose URL / venue / DOI / author list still needs confirming with
   a `TODO:` prefix in `note=`. Confirm the canonical source for each, fix the
   field, and drop the `TODO:`.
   - Files: `docs/paper/references.bib` (grep `TODO:`).
   - Done when: every `TODO:` is resolved or has a one-line reason it can't be,
     and `just paper` still builds clean (tectonic).
   - Note: docs/paper changes are CC-BY-4.0 and live inside the `.gitleaks.toml`
     allowlist, so cipher-hex examples there won't trip the scanner.

2. **Add a second-model reset template (e.g. G7020 / G3060).** The SSOT today
   covers only the lead G6020 (`G6000 series`). Extend
   `printers/canon-g6020/maintenance.yaml`'s structure (or add a sibling SSOT) for
   another MegaTank, sourced from the decrypted WICReset device DB — **status
   `derived-unvalidated`**, no live write.
   - Pointers: `docs/research/servicetool-version-model-tables.md` (the
     model/version map — note the regional triplet G6020/G6080/G6050),
     `docs/research/wicreset-g6020-reset-template.md` (how the G6020 template was
     derived), the existing `derived_template` block in the SSOT.
   - Done when: the new template parses, the fingerprint schema validates, and a
     unit test asserts its derived frames against the device-DB source. **Do not**
     relax the UUID isolation gate — a new model is a new locked unit.

3. **Decode the counter read-back (`get_command` / register reads).** The
   validated reset treats the empty `0x86` reply as expected and does not gate on
   it, but a *readable* pre/post absorber counter would make validation
   self-checking. Investigate the `VENDOR_GET` register-read shape and propose a
   decode, evidence-first.
   - Pointers: `docs/research/usbprint-vendor-urb-mapping.md` (the VENDOR_SET /
     VENDOR_GET URB mapping), `docs/runbook/g6020-native-reset.md` §2 and §4 (the
     transport + the empty-0x86 caveat — read this so you don't regress the
     no-gate rule).
   - Done when: a `docs/research/` note documents the read shape with cited
     evidence and a test covers any decode you add. Keep it read-only; this is not
     a new write path.

4. **Diagram polish.** The Mermaid + Graphviz sources under `docs/diagrams/`
   render via `just diagrams`. Tighten labels, fix any drift from the validated
   runbook, or add a missing view (e.g. the safety-gate ladder as its own
   diagram).
   - Pointers: `docs/diagrams/README.md` (the "Accuracy notes" — every claim must
     stay traceable to a finding), the per-file header comments (each cites its
     source doc).
   - Done when: `just diagrams` renders clean and every changed claim still
     matches `docs/runbook/g6020-native-reset.md`. SVG/PNG are gitignored build
     artifacts — commit only the `.mmd` / `.dot` sources.

If you want something larger, the open work is mapped in
`docs/PRODUCTIONIZATION.md` (the path from validated tool to fleet-deployable) and
`docs/adr/0007` (RE methodology + the tranche T0–T6).

## License of contributions

By contributing you agree your **code** is licensed under the zlib/libpng License
(`LICENSE`) and your **documentation / paper** contributions under CC-BY-4.0
(`LICENSE-docs`). See the README "License" section for the split.
