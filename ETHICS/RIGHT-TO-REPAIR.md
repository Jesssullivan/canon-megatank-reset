# Ethics & right-to-repair posture

This project reverse-engineers, documents, and reimplements the **waste-ink /
ink-absorber (5B00) counter reset** for Canon MegaTank G-series printers, natively
on Linux, with no purchased key and no vendor cloud. This document states *why that
is legitimate*, what we will and will not do, and the dual-use posture we hold
ourselves to. It complements (does not replace) `SECURITY.md`.

## What this is

A **right-to-repair** tool for printers **you own**. Canon's MegaTank G-series
refuses to print once an internal counter decides the waste-ink absorber is "full" —
even after the absorber has been physically serviced. The manufacturer's only
sanctioned remedy is a service-centre visit; the unsanctioned remedies are a
Windows-only Service Tool or a commercial resetter that charges a **single-use key
per printer**. None of these is acceptable for a Linux fleet doing its own refurb.

We recovered the maintenance protocol from those tools **as interoperability
oracles** and reimplemented the reset as open, native code. We proved (by decompile)
that the device-side reset takes **zero** cloud bytes — the cloud is **licensing
only**. Restoring a serviced printer to working order is **maintenance of your own
property**, not an attack.

## Authorized-repair framing (scope)

- **Owner / authorized-technician use only.** Use this on hardware you own or are
  authorized to service. It is for restoring a *physically serviced* printer to a
  working state.
- **Physical safety first — fit pads/tank before resetting.** Resetting the counter
  only changes the firmware's bookkeeping; it does **not** empty the absorber. If the
  physical absorber is genuinely saturated, resetting and then printing risks **ink
  overflow** onto the desk/floor and into the chassis. Install new waste pads or an
  external waste-ink kit (e.g. a Printer Potty tank) **before** you reset. This is the
  same guidance the vendor ecosystem gives, and the publication carries it too.
- **Commit safely.** The validated reset commits on a **clean power-button shutdown**
  (printhead park + EEPROM flush), not on an abrupt unplug — see
  `docs/runbook/g6020-native-reset.md` §4½.

## No DoS, no malware, no bricking

We do **not** build, ship, or document anything whose purpose is to damage,
deny-service, brick, surveil, or otherwise harm a printer or its owner:

- **No destructive or denial-of-service payloads.** The only write this project
  performs is the absorber-counter reset, behind a gate ladder (test-unit UUID
  isolation, mandatory pre-flight EEPROM dump, persisted write budget, lockfile,
  live-keyword guard). It refuses to write to any unit but the locked test unit until
  a per-unit validation, and it never sweeps, fuzzes, or mass-writes a fleet blind.
- **No malware.** We run **no** untrusted binaries. Free "V6.x Service Tool" mirrors
  that flagged as malware are explicitly **banned** (operator directive); the only
  proprietary tools touched are the operator's own legitimately-staged WICReset build
  and the Canon Service Tool, used read-only as RE oracles and **never
  redistributed**.
- **No firmware modification.** We do not patch, reflash, or alter printer firmware.
  The reset uses the printer's **own** maintenance command path — the same one the
  vendor tool uses — over standard USB control transfers.
- **No secrets exfiltration.** No keys, credentials, or `.env` files are committed;
  the WICReset key lives in the operator's secret store and is never required by the
  native tool (the reset is key-free).

## Dual-use posture

Protocol reverse-engineering is dual-use: the same knowledge that lets an owner
repair a printer could, in principle, be misused. We manage that honestly:

- **Defensive / repair intent is primary and explicit.** The work is framed,
  scoped, and gated for repair. The cloud-independence proof is published precisely
  to *de-mystify* the reset — to show it is an ordinary maintenance command the
  manufacturer has **administratively** (not cryptographically) withheld from owners,
  not a protection on copyrighted content.
- **We publish the mechanism, not a weapon.** What we release is a protocol spec, a
  reference codec, a paper, and gated tooling — with the physical-safety warnings
  attached. We do **not** release a one-click fleet-wide writer, a key generator, or
  anything that helps someone harm a device or evade a *content* protection.
- **Interoperability + repair, clean-room.** RE is performed for interoperability and
  repair under the clean-room posture in `SECURITY.md`. We redistribute no vendor
  binaries or firmware. We engage the vendor ecosystem (OctoInkjet / Printer Potty /
  the pixma lineage) collaboratively rather than silently — see `INTEROP.md` §5.
- **Attribution and traceability.** We credit the prior art we build on and keep an
  evidence-to-code trail (`INTEROP.md` §6) so the work can be audited, reproduced,
  and corrected — the opposite of a black-box exploit.

## Reporting

Safety, security, or misuse concerns: open a private security advisory on the
canonical repo, or contact the maintainer (jess@sulliwood.org). See `SECURITY.md`.
