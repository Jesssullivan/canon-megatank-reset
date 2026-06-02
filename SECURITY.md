# Security & responsible-use policy

## Purpose & scope

`canon-megatank-reset` is a **right-to-repair** tool: it resets the waste-ink /
ink-absorber counter on Canon MegaTank printers **you own**, so a serviceable
printer is not bricked by a software counter. It is intended for owners and
repair technicians operating on their own hardware/fleet.

## Responsible use

- **Physically service the absorber first.** Resetting the counter lets the printer
  print again; if the physical absorber is genuinely full, doing so risks ink
  overflow. Fit new pads / an external waste-ink kit before resetting.
- **Test-unit isolation is enforced.** The tool refuses to write to any printer whose
  fingerprint ≠ the locked `test_unit` until the protocol is verified.
- EEPROM writes are gated (pre-flight dump, write budget, lockfile, ping baseline).

## No binary / firmware redistribution

We do **not** commit or redistribute Canon's Service Tool, WICReset, Canon firmware
blobs, or the Ghidra project database. Only our own scripts and curated findings are
tracked (`.gitignore` enforces this). RE is for interoperability/repair.

## Secrets

No secrets in the repo. The WICReset key and any host become-passwords live in the
operator's sops/secret store and are loaded via `direnv` — never committed.

## Supported versions

Security fixes land on `main` and ship in the next tagged release (see `VERSION`
/ `CHANGELOG.md`). Only the latest release is supported; please reproduce on
`main` before reporting.

## Reporting a vulnerability (coordinated disclosure)

Report privately — **do not** open a public issue for a security problem:

- Preferred: open a private GitHub Security Advisory on the canonical repo
  (Security → Advisories → "Report a vulnerability").
- Or email the maintainer: **jess@sulliwood.org**.

Please include the affected version/commit, a reproduction, and impact.

Coordinated-disclosure timeline:

- **48 h** — acknowledgement of your report.
- **90 days** — target window to ship a fix before public disclosure. We will
  agree an embargo with you and credit you in the advisory unless you prefer
  otherwise.

### In scope

The reset tooling, the protocol model, the host playbooks/roles, and CI/secret
handling in this repo. Since this is a **right-to-repair** project, "it lets a
device owner reset a counter they own" is the intended behavior, not a
vulnerability.

### Out of scope

- Reports that amount to "this enables repair/interoperability" — that is the
  point (see `ETHICS/RIGHT-TO-REPAIR.md`, `INTEROP.md`).
- Vulnerabilities in Canon firmware, Canon Service Tool, or WICReset
  themselves — report those to the respective vendors.
- Findings against forks or modified copies.
