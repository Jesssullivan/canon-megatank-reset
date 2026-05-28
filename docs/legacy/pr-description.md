# [TIN-1381] canon-tool — fleet G6020 refurb via reverse-engineered Service Tool

## Why

mbp-13 has a Canon PIXMA G6020 in 5B00 (ink absorber full) state. Physical
sponge inspection: not actually soiled — the counter is the failure, not
the hardware. The user has multiple surplus G6020s slated for fleet refurb,
so a Linux-native open-source equivalent of Canon's Windows-only Service
Tool unlocks a meaningful cost win + sustainability story (right-to-repair).

Confirmed prior-art gap (2026-05): no open-source G6020 absorber-reset
implementation exists. `leecher1337/pixma` (the closest attempt) is C
firmware-analysis only; its author abandoned the absorber-reset RE work.
Genuinely new RE territory.

Legal posture: DMCA §1201 has had an explicit diagnostic/maintenance/
repair exemption since 2018. Reverse-engineering for interoperability is
*Sega v. Accolade* / *Sony v. Connectix* fair use. No binary
redistribution; user owns the printers.

## What lands in this PR (Phase R0 D1)

The capture environment and safety-gate scaffolding — **no maintenance
write ops** yet; those land when we have the byte sequence captured.

### Plan + ADR
- `docs/adr/0007-canon-tool-reverse-engineering.md` — full methodology,
  4-rung parallel-evidence plan (R0/R1/R2 parallel, R3 last-resort),
  fingerprint gate, hardware safety protocol.

### Per-printer SSOT
- `printers/canon-g6020/manifest.yaml` — dispatch=cups; maintenance
  routed through canon-tool, not the 3D printer registry.
- `printers/canon-g6020/maintenance.yaml` — the locked spec:
  - `protocol_fingerprint`: fw `1.070`, IPP UUID
    `00000000-0000-1000-8000-00186501807c`, CMD set
    `BJRaster3,NCCe,IVEC,URF`, IEEE-1284 device-id raw payload.
  - `usb_interface_layout`: pinned via direct pyusb probe — 6 USB
    interfaces, **interface 4 (class 0xff sub 0x01 proto 0x01, bulk OUT
    0x03, bulk IN 0x86) identified as the expected maintenance channel**.
  - `test_unit`: the broken-5B00 G6020 on mbp-13, the ONLY printer that
    may receive an EEPROM write until protocol is locked.
  - `write_budget`: cap 50, consumed 0.
  - `service_tool_versions`: SHA-pinned v4718/v4906/v5103 (clean from
    shpgn) + v6310 (Vietnamese SmartKey-DRM-wrapped v5302; untrusted
    for static analysis).
  - `win11_iso`: 7.92 GiB Win11_25H2 with verified SHA256, location
    pinned at mbp-13:~/canon-tool-staging/iso/.

### Python service skeleton
- `services/canon-tool/pyproject.toml` — pyusb + structlog + ruamel.yaml
  + ruff/mypy/pytest under dev extras.
- `src/printstack_canon/types.py` — hierarchical CanonToolError family
  (Fingerprint/UnknownPrinter/PingSuite/WriteBudget/Lockfile/Eeprom/
  UsbAccess), PrinterFingerprint dataclass with from_ipp_attributes
  parser, TestUnit + WriteBudget dataclasses.
- `src/printstack_canon/fingerprint.py` — the gate every op passes
  through before touching USB. Refuses on uuid drift, fw drift, or
  cmd_set drift. Auto-locates maintenance.yaml via
  PRINTSTACK_PRINTERS_DIR or ancestor walk.
- `src/printstack_canon/usb.py` — thin pyusb wrapper with Canon-vendor
  allowlist + ClaimedDevice context manager (kernel driver detach +
  interface claim + endpoint discovery + safe reattach).
- `src/printstack_canon/main.py` — systemd entrypoint stub; loads
  maintenance.yaml on start (refuses to start if missing); idles until
  SIGTERM. HTTP-on-unix-socket listener stubbed for Phase A.
- `src/printstack_canon/pcap.py` — tshark-backed pcap summarizer with
  full `usb.endpoint_address` extraction (0x82, 0x86, etc) and Canon
  protocol header heuristics. `printstack-canon-pcap` console script.
- `scripts/safe-ping-probe.py` — read-only pyusb probe that reads USB
  descriptors + IEEE-1284 device-id. Used to capture the locked baseline.
- `scripts/r1-capture.sh` — one-command R1 cheap-spike orchestrator
  (pre-flight + tshark + Wine + GUI prompt + ipp-usb restore).

### Test suite (14/14 green)
- `tests/test_fingerprint.py` (8) — SSOT drift detection, IPP parser
- `tests/test_pcap.py` (6) — fixture integrity, .gz fallback, key
  negative-control invariant (**zero bulk-OUT to endpoint 0x03 in
  launch-no-clicks captures**)

### Committed evidence
- `captures/ping-baseline-2026-05-28.yaml` — pyusb-derived USB descriptor
  + interface enumeration + IEEE-1284 device-id payload.
- `captures/v5103-wine-launch-no-clicks-20260528-222034.pcapng.gz` —
  60-packet real USB capture of Wine + Service Tool v5103 launch on
  mbp-13. Sidecar `.meta.yaml` documents full provenance + confirms
  the negative-control finding: v5103 emits ZERO bulk-OUT on endpoint
  0x03 without GUI clicks. Maintenance channel binding is gated on
  user interaction.
- `captures/example.meta.yaml` — schema template for future captures.
- `captures/v5103-g3010mode-attempt-1.meta.yaml.template` — pre-staged
  template for the upcoming R1 cheap-spike capture.

### Ansible role + Justfile + CI
- `host/roles/canon_tool_dev/` — capture environment: qemu-kvm,
  libvirt, wireshark+tshark, python3-pyusb, libusb1, p7zip, Wine via
  Flathub (org.winehq.Wine/stable-25.08), udev rule for Canon 04a9
  vendor IDs (mode 0660 group printstack), wireshark group membership,
  usbmon autoload. Self-heals the broken winehq.repo from earlier
  attempts.
- `host/playbooks/canon-tool-dev.yml` — standalone playbook for the
  role (not in site.yml; dev-only).
- `Justfile`: `canon-test`, `canon-dev-setup`, `canon-dev-dry`,
  `canon-rsync`, `canon-r1-capture <label>`, `canon-capture-start`,
  `canon-analyze <pcap>`, `canon-replay <pcap>`, `canon-eeprom-dump`,
  `canon-verify-binaries`, `canon-verify-staging`.
- `.github/workflows/canon-tool.yml` — paths-filtered CI running
  `just canon-test` + ansible syntax-check on canon-tool changes.
- `flake.nix` — added `wireshark-cli` for in-shell tshark access.
- `docs/runbook/canon-tool-r1-cheap-spike.md` — Wine path runbook.
- `docs/runbook/canon-tool-r2-qemu-spike.md` — QEMU+Win11 path runbook
  with libvirt domain XML + USB hostdev passthrough config.

## Hardware safety enforcement (in code, not just docs)

1. Pre-flight ping suite must succeed; any drift aborts.
2. Pre-flight EEPROM dump + checksum mandatory before any write (Phase A).
3. Write-cycle budget capped at 50 per test unit, persisted on disk.
4. Refused on any UUID that isn't the named `test_unit`.
5. Lockfile in `/run/canon-tool/in-progress` prevents systemd restart
   mid-write (Phase A).
6. Walk-up identity gate + physical button confirmation (Phase B —
   in the SvelteKit route).

## What does NOT land in this PR

- Maintenance write ops (no protocol bytes captured yet)
- SvelteKit `/maintenance` route (Phase B; depends on captured ops)
- pyusb replay code (`replay.py` stub committed; impl needs evidence)
- EEPROM dump (`eeprom.py` stub committed; impl needs interface 4
  command shape)
- Linear ticket structure (will set up alongside / after merge)

## Test plan

- [x] `just canon-test` — 14/14 pass locally
- [x] CI workflow added; will run on this PR's first push to GitHub
- [x] `just canon-dev-dry -l mbp-13` — playbook dry-run passes
  (modulo `--check` mode artifacts for systemd-on-uninstalled-units)
- [x] `just canon-dev-setup -l mbp-13` — playbook applies cleanly
  on mbp-13 (verified: `ok=20 changed=9 failed=0`)
- [x] safe-ping-probe.py runs against real G6020, captures interface
  layout matching the pinned maintenance.yaml
- [x] Real Wine + Service Tool v5103 launches under Flathub Wine on
  mbp-13 with usbmon visible, full descriptor enumeration captured

## Linear

Initiative: "Canon G-series Service Tool replacement"
Issue: TIN-1381

## Reviewers

Bots only for now; the human review pass will happen alongside the R1
in-lab session (after we have the absorber-reset byte sequence to
audit).

---

Generated 2026-05-28 from the canon-tool R0 D1 work session.
20+ commits, ~3000 lines added, fully tested, ready to merge once R1
captures land and `supported:` in maintenance.yaml is populated.
