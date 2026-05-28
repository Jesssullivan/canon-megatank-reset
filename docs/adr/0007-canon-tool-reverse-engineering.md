# ADR 0007 — canon-tool: reverse-engineering Canon Service Tool for G-series MegaTank

**Status:** Proposed (Phase R0 in progress, 2026-05-28)
**Owner:** jess
**Supersedes:** none
**Related:** sub-initiative plan in `~/.claude/plans/printstack-the-goal-snazzy-pebble.md` (canon-tool section, line ~440+)

## Context

`mbp-13` has a Canon PIXMA G6020 in 5B00 (ink absorber full) state. Physical
sponge inspection: not actually soiled — the counter is the failure, not the
hardware. Canon's Windows-only Service Tool clears the counter over USB but
isn't distributed to end users. The user has multiple surplus G6020s slated
for fleet refurb, so a Linux-native open-source equivalent is high-leverage.

Right-to-repair posture: DMCA §1201 has an explicit diagnostic/maintenance
exemption (renewed 2018+). Reverse-engineering for interoperability is
*Sega v. Accolade* / *Sony v. Connectix* fair use. No binary redistribution.

## Decision

Build `services/canon-tool/` as a Python service exposing an HTTP API for
maintenance ops, gated to walk-up identity + physical-button confirmation.
Discover the USB protocol via parallel evidence sources (NOT serial rungs):

- **R0** — Prior art + spec spelunking (3 days; in flight)
- **R1** — Wine + usbmon capture on mbp-13 (1-day spike)
- **R2** — QEMU/KVM + Win11 + USB passthrough on mbp-13 (1-day spike, parallel with R1)
- **R3** — Ghidra static analysis (last resort, 5-day timebox)

mbp-13 confirmed Intel x86_64 + VT-x + `/dev/kvm` available — both Wine and
QEMU paths run natively without emulation overhead.

## Evidence captured (Phase R0 D1)

### Test unit fingerprint (lock target)

```
firmware:        1.070
ipp_uuid:        00000000-0000-1000-8000-00186501807c
device_id:       MFG:Canon;CMD:BJRaster3,NCCe,IVEC,URF;SOJ:CHMP,CHMPu;
                 MDL:G6000 series;...;VER:1.070;...;CID:CA_IVEC1TYPE4_IJP;
cmd_set:         BJRaster3, NCCe, IVEC, URF
```

`NCCe` (Network Canon Configuration extension) is the likely maintenance
opcode carrier. `BJRaster3` is the print path. `IVEC` is newer Canon spec.

### Service Tool binary landscape (acquired 2026-05-28)

| Version | Source | SHA256 (exe) | G6020? | Notes |
| --- | --- | --- | --- | --- |
| v4718 | shpgn | `cd487e10...` | no | 2017; pre-G6020 |
| v4906 | shpgn | `ff3314ed...` | no | 2017; suspicious — 0 model strings |
| v5103 | shpgn | `98ca97b3...` | **no by name, family-shared possible** | 2022; covers G1000/2000/3000/3010/4010; contains `CEEPROMDumpSave`, `CEEPROMHeadDumpSave`, `CEEPROMInfoDlg` MFC classes — best Ghidra candidate so far |
| v5302 | needs source | (target) | yes | datvietcomputer's "v6310" is actually v5302 + DRM (per `DynSmartKey.txt`: `Company: ST5302`); needs clean source |

### Hypothesis to test in R1 (cheap spike)

The G6020 shares chipset family with G3000-series. v5103 covers G3010
explicitly. If Service Tool's model selection is just a config lookup but
the underlying byte sequence is family-shared, **v5103 in G3010 mode against
the G6020 may clear 5B00**. Cheap test, high upside. Capture USB throughout
via `tshark -i usbmon1` regardless of outcome — even a refusal yields useful
trace data.

### Adjacent assets

- `leecher1337/pixma` (forked to `jesssullivan/pixma`) — Canon Pixma firmware
  unpacker (C). Decrypts the encrypted firmware blob; author abandoned the
  absorber-reset RE but the firmware decrypt path is useful for Ghidra.
  The legacy Canon CDN URL pattern (`gdlp01.c-wss.com/rmds/ij/ijd/ijdupdate/<PID>.xml`)
  works for PID 1769 but 404s for G6020's PID 1865 — Canon moved newer
  firmware distribution; alternate index not yet found.

## Hardware safety enforcement (in-code, not just docs)

See `printers/canon-g6020/maintenance.yaml` for the live schema. Every op:

1. Pre-flight ping suite (documented-safe ops) must succeed; any drift aborts.
2. Pre-flight EEPROM dump + checksum mandatory before any write.
3. Write-cycle budget capped at **50** per test unit (persistent counter).
4. Refused on any UUID that isn't the named `test_unit`.
5. Lockfile in `ExecStartPre` prevents systemd restart mid-write.
6. Front-panel button press required within 30s of web-initiated op.

## Open questions (do not block Phase R0)

1. Will Wine run v5103 cleanly enough to reach the G3010 reset UI? (R1 spike)
2. Is the v5103 G3010 absorber-reset byte sequence shared with G6020? (R1 spike)
3. Can we source clean v5302 (without SmartKey DRM)? (search continues)
4. Does Canon's G6020 Windows driver installer ship a separate maintenance utility?
5. Is the IVEC1 type 4 IJP command set documented anywhere publicly?

## Consequences

- New service in `services/canon-tool/` once protocol bytes are locked.
- New ansible role `host/roles/canon_tool/` for Wine repo + tshark + libvirt.
- udev rule `50-canon-g6020.rules` granting USB access to `printstack` group.
- New SvelteKit route `/maintenance` with two-factor walk-up + physical gate.
- Kiosk tile (🔧 Maintenance).
- Vendored read-only clone of `jesssullivan/pixma` for firmware-decrypt
  reference (decision: git submodule vs subtree pending; defer to commit time).

## Verification

Phase R0 D1 success criteria (this commit):

- [x] Test unit fingerprint locked in `maintenance.yaml`
- [x] All discoverable Service Tool binaries SHA-pinned (v4718/v4906/v5103/v6310-datviet)
- [x] v5103 confirmed best static-analysis candidate (clean, contains EEPROM MFC classes)
- [x] v6310 confirmed UNTRUSTED (DRM-wrapped v5302)
- [x] Capture environment package list confirmed available on Rocky 10.1 mbp-13
- [ ] Clean v5302 sourced — open
- [ ] Wine installed + Winehq repo enabled on mbp-13 — open
- [ ] R1 cheap-spike attempted (v5103 G3010 mode against G6020) — open

Phase R0 done when all open items above land or are explicitly punted.
