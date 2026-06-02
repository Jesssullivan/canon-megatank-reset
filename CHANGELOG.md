# services/canon-tool — changelog

Versioning follows printstack root. This changelog tracks the Phase
progression specifically (R0 → R1 → R2 → R3 → A → B → C). See
`docs/adr/0007-canon-tool-reverse-engineering.md` for phase definitions.

## 0.0.1 — Phase R0 D1+D2 (2026-05-28)

Pre-protocol-byte scaffolding. The capture environment is operational
and the safety gate code is real + tested, but no maintenance write op
exists yet.

### Evidence captured (committed under `captures/`)

| File | Bytes | What it tells us |
| --- | --- | --- |
| `ping-baseline-2026-05-28.yaml` | n/a | USB descriptor table for the G6020 test unit (6 interfaces, maintenance channel locked as interface 4: bulk OUT 0x03 / bulk IN 0x86). IEEE-1284 device-id payload pinned for cmd_set drift detection. |
| `v5103-wine-launch-no-clicks-20260528-222034.pcapng.gz` + `.meta.yaml` | 1872 | 60-packet Wine + Service Tool v5103 launch capture under Flathub Wine on mbp-13 via Xvfb. **Negative-control baseline:** zero bulk-OUT on endpoint 0x03 confirms Service Tool requires GUI clicks to bind interface 4. |
| `ipp-usb-baseline-20260529-001127.pcapng.gz` + `.meta.yaml` | 20022 | 420-packet capture of 4 ipptool queries against ipp-usb on localhost:60001. **Contrastive baseline:** decoded bulk-OUT shows ASCII `POST /ipp/print HTTP/1.1` — IPP-USB is HTTP-framed inside USB bulk transfers. Traffic lives on endpoints 0x0c / 0x0e / 0x8d / 0x8f. |

### Test suite — 20/20 green

| File | Tests | What they catch |
| --- | --- | --- |
| `tests/test_fingerprint.py` | 8 | SSOT drift in `printers/canon-g6020/maintenance.yaml` — uuid, firmware, cmd_set, write_budget. |
| `tests/test_pcap.py` | 12 | tshark integration, .pcapng.gz auto-fallback, the **key negative-control invariant** (zero bulk-OUT on endpoint 0x03 in launch-no-clicks), the **HTTP-over-USB confirmation** (POST prefix on IPP-USB bulk-OUT), IPP-USB noise filter behavior, bucketing consistency. |

### Python module status

- `types.py` — typed exception hierarchy + dataclasses ✓ done
- `fingerprint.py` — load + verify against locked maintenance.yaml ✓ done
- `usb.py` — pyusb ClaimedDevice context manager with vendor allowlist ✓ done
- `pcap.py` — tshark-backed pcap analysis + IPP-USB / maintenance traffic filters ✓ done
- `main.py` — systemd entrypoint (idle loop until Phase A) ✓ stub
- `ops.py` — maintenance op dispatch table — **deferred to Phase A (needs captured bytes)**
- `replay.py` — pcap → live replay — **deferred to Phase A**
- `eeprom.py` — pre-flight dump + checksum — **deferred to Phase A**
- `ping.py` — runtime ping suite — **deferred to Phase A** (baseline pinned via yaml in `captures/`)
- `lockfile.py` — `/run/canon-tool/in-progress` guard — **deferred to Phase A**

### Capture environment — operational on mbp-13

- ✓ wireshark + tshark
- ✓ qemu-kvm + libvirt-daemon-kvm + virt-install + virt-manager + edk2-ovmf
- ✓ python3-pyusb + libusb1
- ✓ p7zip (handles Service Tool AES-encrypted zips)
- ✓ Wine 11.0 via Flathub (`org.winehq.Wine/x86_64/stable-25.08`)
  with `--device=all` flatpak override granting USB device access
- ✓ udev rule (`/etc/udev/rules.d/50-canon-g6020.rules`) granting
  `mode 0660 group printstack` to all Canon 04a9 USB devices
- ✓ usbmon module autoloaded; jess in `printstack` + `wireshark` groups
- ✓ Win11_25H2_English_x64_v2.iso (7.92 GiB, SHA-pinned in
  `printers/canon-g6020/maintenance.yaml::win11_iso`)

### Service Tool binary landscape (acquired)

| Version | SHA256 (exe) | G6020? | Notes |
| --- | --- | --- | --- |
| v4718 (2017) | `cd487e10...` | no | Pre-G6020; bundles MFC4x runtime |
| v4906 (2017) | `ff3314ed...` | no | Suspicious — 0 model strings; uses external configs |
| v5103 (2022) | `98ca97b3...` | **G3010 family, possibly G6020-compatible via chipset-family** | Contains `CEEPROMDumpSave`, `CEEPROMHeadDumpSave`, `CEEPROMInfoDlg` MFC classes — best Ghidra static-analysis target |
| v6310 (2025, Vietnamese repack) | `73e49e1f...` | underlying = v5302 (per `DynSmartKey.txt`) | Wrapped in SmartKey commercial DRM; untrusted for static analysis; may still work for R2 runtime capture if DRM doesn't block Wine |

### Adjacent assets

- `jesssullivan/pixma` (forked from `leecher1337/pixma`) — vendored clone at `/Users/jess/git/pixma/` for firmware-decrypt reference. Author abandoned absorber-reset RE but the firmware decrypt path is useful for Ghidra cross-checks.
- Canon legacy firmware CDN URL pattern: `http://gdlp01.c-wss.com/rmds/ij/ijd/ijdupdate/<PID>.xml` — works for older Pixma (e.g. 1769) but 404s for G6020's 1865. Canon moved newer-printer firmware off the legacy index; alternate path not yet found.

### Phase R0 → Phase R1 transition

R0 is **complete**. The R1 cheap-spike runbook is ready to fire via `just canon-r1-capture v5103-g3010mode-attempt-1` whenever the user is physically at mbp-13 (or via X11 forwarding). The capture output will land at `~/canon-tool-staging/captures/v5103-g3010mode-attempt-1-<ts>.pcapng.gz` on mbp-13; rsync to neo and `just canon-analyze` for byte extraction.

### Decision log

1. **Flathub Wine over Winehq RPM** — Winehq dropped CentOS/RHEL RPM support; only Fedora 40/41 published as of 2026-05. Fedora ABI is too different from Rocky 10 to safely cross-install. Flathub `org.winehq.Wine` is the official cross-distro path; `flatpak override --device=all` grants USB device portal access (`--filesystem=/dev/bus/usb` is rejected as a reserved path).
2. **G3010-mode hypothesis** — v5103's model dropdown does NOT list G6020 but DOES list G3010 (same G-series MegaTank chipset family). The absorber-reset byte sequence is likely shared across the family at the protocol layer; Canon's model filtering may be just a config lookup at the GUI layer. The R1 cheap-spike tests this hypothesis at low cost.
3. **Interface 4 as maintenance channel** — confirmed via `safe-ping-probe.py` capturing the active configuration. Class 0xff sub 0x01 proto 0x01 with bulk OUT 0x03 / bulk IN 0x86. The other vendor-specific interfaces (0 and 5) are likely scan-event and a secondary maintenance lane respectively.
4. **Test_unit isolation** — the broken-5B00 G6020 on mbp-13 is the ONLY printer that may receive an EEPROM write until protocol is locked. Refused on any UUID that isn't the named `test_unit` per the fingerprint gate in code.
