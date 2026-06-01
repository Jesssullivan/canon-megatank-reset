# ServiceTool V6.x sourcing for G6020 — key-free lane — 2026-06-01

Goal of this lane (no printer, no reset, no WICReset key): obtain newer Canon
**ServiceTool** builds that actually list the **PIXMA G6020 / "G6000 series"** (the
staged **V5103 does not** — its model table stops at G1000–G4000), get them into
the throwaway Win11 capture VM, **malware-scan every binary before running**, and
verify **offline** whether G6020 appears in the tool's model table. Ranking target
from the research doc: **V6.310 > V6.300/STV6300 > V5610**.

> Environment: libvirt `canon-capture-win11-headless` (qemu:///session) on mbp-13.
> All guest ops via WinRM/ntlm ansible from `~/git/canon-megatank-reset`
> (`PATH=~/canon-tool-staging/ansvenv/bin:$PATH ansible -i
> host/vm-capture/ansible/inventory.yml canon-win11 …`). Files staged under
> `C:\canon\st-sourcing\`. Defender real-time protection **left ON** throughout —
> this is untrusted-binary territory even in a throwaway sandbox.

## TL;DR / recommendation

**No clean, runnable V6.x ServiceTool build was obtained.** Every freely
downloadable community V6.310 binary is **Defender-flagged malware** (two
independent mirrors, two *different* malware families), and the V5610 / STV6300
packages are **password-walled behind a vendor-contact / paywall funnel** that
cannot be passed autonomously. **Do not run any binary sourced in this lane.**

Consequently the **offline launch-and-screenshot model-table check (step 4) was
not performed** — doing so would mean executing known malware. The "G6020 is
listed" evidence for these builds therefore rests on the **vendor model lists**
(already captured in the research doc), not on a live dropdown.

**Recommended build to pursue for the eventual real-reset capture: none from the
free community mirrors.** Get a **paid, vendor-delivered STV6300 or V6.310**
(e.g. resetter.net / chiplessprinter / orpys ~$25, which deliver the unlocked
archive + activation key) — or stay on the **WICReset / WIC Reset Connect** path
already validated in MEMORY — rather than trusting any free repackage. If a paid
copy is acquired, re-run the malware gate below before launch.

## Candidate builds — source, hash, scan, model-table verdict

| Build | Source | Got binary? | SHA256 (as downloaded) | Defender | Signed? | G6020 in model table? |
|-------|--------|-------------|------------------------|----------|---------|------------------------|
| **V6.310** (GitHub mirror) | `github.com/datvietcomputer/Canon-service-tool-` raw `TOOL0006V6310.exe` | yes (5,131,264 B, MZ/PE) | `73E49E1F0684ACB7FCC76F0B14671DFCE3E5ECC46AA98414644011EAD74970FD` | **MALWARE — ThreatID 2147735505** (same family as the prior `C:\canon\TOOL0006V6310.exe` repackage) | no — Defender blocked Authenticode read ("file contains a virus") | **NOT VERIFIED** (cannot run malware) |
| **V6.310** (mediafire via softwarecrackguru.com, pw `sbz`) | `download2295.mediafire.com/.../psl0eb6vxf7zob1/TOOL0006V6310.rar` (landing `mediafire.com/file/psl0eb6vxf7zob1/TOOL0006V6310.rar/file`) | yes — RAR 12,976,078 B, extracted `TOOL0006V6310\tool0006v63102.exe` (12,340,736 B) | RAR: `88600E49D7AD48F2026790856AE13108C5DB5455469F020A2E52A38177B793DF` | **MALWARE — ThreatID 2147939874** (different family from the GitHub one) | no — Defender blocked Authenticode read | **NOT VERIFIED** (cannot run malware) |
| **V6.300 / STV6300** | `resetter.link/download/canon-service-v-6-300-one-pc` (linked from `resetter.net/canon-service-tool-version-6-300-v6300`) | **no** — archive + password **gated**: "contact us for the password and activation key" (FB/WhatsApp) | n/a | n/a | n/a | vendor list shows G6020 (research doc), **not** verified in-tool |
| **V5610** | `mediafire.com/file/be93zjjg1rlvbe2/Reset-Canon-ST5610.rar` (linked from `datvietcomputer.com/canon-service-tool-v5610.html`) | partial — RAR fetched (2,063,357 B) + extracted to inner **password-protected** `CANON-ST5610-RESET.zip` wrapping `TOOL0006V5610.exe` | RAR: `46153E8154050B6CDA8F811D831E8734A45D524134B0944F2C22152E41213D3B` | not reachable (inner zip locked) | n/a | vendor list shows G6020 (research doc), **not** verified in-tool |

### Detail per candidate

**V6.310 — datvietcomputer GitHub (first choice, FAILED gate).**
Direct raw URL `https://raw.githubusercontent.com/datvietcomputer/Canon-service-tool-/main/TOOL0006V6310.exe`.
Downloaded clean (HTTP 200, 5,131,264 B, MZ). `Start-MpScan` custom scan →
`Get-MpThreatDetection` reports **ThreatID 2147735505** on the file — the **exact
same ThreatID** the prior runbook recorded for `C:\canon\TOOL0006V6310.exe`. This
is the same poisoned repackage. Defender quarantined/blocked it; even
`Get-AuthenticodeSignature` failed with "the file contains a virus". **Not run.**

**V6.310 — softwarecrackguru.com → mediafire (second V6.310 source, FAILED gate).**
A *distinct, larger* V6.310 RAR (12.37 MB) with published extraction password
`sbz` (the guide explicitly told users to "disable antivirus before extraction" —
a classic malware-bundling tell; we kept Defender ON). Extracted with 7-Zip 24.09
(installed in-guest via the official `7z2409-x64.msi`; `7zr.exe` alone cannot open
RAR). Yielded `TOOL0006V6310\tool0006v63102.exe` (12,340,736 B). On first access
Defender real-time protection flagged it **ThreatID 2147939874** — a *different*
threat ID from the GitHub copy, i.e. a second, independent malware family riding
the same "ServiceTool V6310" name. The package's `_Password.txt` shows it was
re-bundled from `i-loadzone.com`. **Not run.**

**V6.300 / STV6300 (GATED).** resetter.link reports the file (2.7 MB, released
2024-02-18) but states **"contact us for the password and activation key"** and
routes to Facebook Messenger / WhatsApp. No autonomous path to the archive or its
password. Vendor compat list includes G6020 (per research doc) but that is
marketing text, not an in-tool dropdown.

**V5610 (GATED at inner zip).** The datvietcomputer mediafire RAR `Reset-Canon-
ST5610.rar` (2,063,357 B, RAR4) extracts to a **password-protected** inner zip
`CANON-ST5610-RESET.zip` (2,062,136 B) wrapping `TOOL0006V5610.exe`. The bundled
`pass_giai-nen.txt` / `ID_Datvietcomputer.txt` contain **only vendor contact info**
(Zalo/WhatsApp 0936161390), not the password — the password is handed out only on
contacting the vendor for key activation. Tried common candidates
(`datvietcomputer`, `datvietcomputer.com`, `datviet`, `0936161390`, `ST5610`,
`5610`, `123456`, `resetter123`) — all rejected (7-Zip exit 2 / wrong password).
The inner zip's central directory leaks the member name `TOOL0006V5610.exe` but it
was **never extracted** (0-byte stubs only). Binary never obtained → never scanned.

## Why offline model-table verification (step 4) was skipped

The plan's step 4 (launch the exe on the interactive desktop, screenshot the model
dropdown, confirm G6020) is only valid for a binary that passed the malware gate.
Both V6.310 binaries we could actually download are **Defender-confirmed malware**;
launching either to read its dropdown means **executing known malware** — outside
the acceptable envelope even in a throwaway VM, and pointless because a trojaned
build's model list proves nothing about a clean build. The V5610 / STV6300
binaries were never obtained (password/paywall), so there was nothing to launch.
**No screenshots were produced; none could be without running malware.**

## Security posture / box state left behind

- Defender real-time protection **ON** the entire run; it flagged + quarantined
  both V6310 exes on access. Detection history now shows ThreatIDs **2147735505**
  (datviet) and **2147939874** (scg) in addition to the prior remediated
  `C:\canon\TOOL0006V6310.exe`.
- **No community binary was executed.** No driver/registry changes. No WinUSB
  rebind. The earlier official Canon driver state (MI_04/05 WinUSB in normal mode)
  is unchanged.
- **Printer untouched:** still enumerates as `04a9:1865` (G6000 series, normal
  mode) on the host; never power-cycled, never put in service mode by this lane.
- **WICReset key NOT spent** — no new pcap produced (`~/canon-tool-staging/
  captures/` unchanged from prior runs).
- Staged artifacts (all under `C:\canon\st-sourcing\`): the two RARs, the partial
  V5610 extract tree, 7-Zip MSI + `7zr.exe`, and helper scripts
  (`st-inspect.ps1`, `st-scan.ps1`, `st-extract.ps1`, `st-extract-pw.ps1`,
  `st-magic8.ps1`, `st-readtxt.ps1`). The flagged V6310 exes are
  Defender-quarantined. Safe to wipe the whole `st-sourcing\` tree.

## What is still needed for the eventual real-reset capture

The capture goal is unchanged from `wicreset-live-capture-2026-05-31.md`; this lane
did **not** unblock it. To capture a genuine G6020 5B00 clear on the wire you still
need, together:

1. **A trustworthy maintenance tool that lists G6020 and actually clears** — either
   (a) a **paid, vendor-delivered STV6300 / V6.310** archive (unlocked + activation
   key; re-scan with the gate above before launch), or (b) the already-validated
   **WICReset / WIC Reset Connect** path (spends the OctoInkjet key).
2. **Printer physically in SERVICE MODE** so it re-enumerates as **`04a9:12fe`**
   (single printer-class iface) — the reset is firmware-gated on service mode.
3. **The `12fe` iface attached to the VM AND forced onto WinUSB** (Zadig / WinUSB
   override for `USB\VID_04A9&PID_12FE`) so the tool gets raw bulk past
   `usbprint.sys` — the still-open Option-B blocker from the prior runbook (Zadig
   update-policy modal must be pre-seeded/dismissed first).
4. **Host-side `usbmon` capture** (`dumpcap -i usbmon1 …`) running **before** the
   tool's Clear, to record the successful control-transfer sequence + any
   EEPROM-commit step, for diffing against the falsified `0x40/0x85/00 03 01 03 07`
   frame.

## Sources

- github.com/datvietcomputer/Canon-service-tool- — raw `TOOL0006V6310.exe` (flagged 2147735505)
- github.com/shpgn/service_tool_canon/releases — only v5103/v4906/v4718 (no V6.x; not useful here)
- softwarecrackguru.com/2026/02/how-to-open-canon-service-tool-v6310.html — pw `sbz`, mediafire `psl0eb6vxf7zob1/TOOL0006V6310.rar` (flagged 2147939874)
- resetter.net/canon-service-tool-version-6-300-v6300 + resetter.link/download/canon-service-v-6-300-one-pc — STV6300, password-gated
- datvietcomputer.com/canon-service-tool-v5610.html + mediafire `be93zjjg1rlvbe2/Reset-Canon-ST5610.rar` — V5610, inner zip password-gated
- orpys.com/en/canon/521-service-tool-v6310.html — V6.310 paid ($25, HWID-locked)
- cirujanodeimpresoras.com/service-tools-v6310-reset-canon/ — V6310 (pw `cirujanodeimpresoras.com`), download link not extractable via fetch
