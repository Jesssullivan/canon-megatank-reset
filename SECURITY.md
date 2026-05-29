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

## Reporting

Open a private security advisory on the canonical repo, or contact the maintainer
(jess@sulliwood.org).
