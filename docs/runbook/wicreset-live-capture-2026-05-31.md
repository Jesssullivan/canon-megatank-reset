# WICReset live wire-capture session — 2026-05-31

Ground-truth capture of the **real** WICReset (Printer Potty v5.95, May 1 2024)
absorber-reset handshake against the dedicated debug G6020 (5B00), recorded with
host-side `usbmon` while the closed tool drives the printer inside the Win11
capture VM. Spends the single purchased OctoInkjet key (operator-authorised).

## Lane that finally worked (Lane B headless)

After the static-RE session-open wall, the VM-capture lane is the path to the
runtime-sourced bytes. Two infra fixes unblocked it (see
`scripts/vm-capture-headless.sh` + `host/vm-capture/ansible/inventory.yml`):

- **NIC = `e1000e`, not `virtio`.** Win11 has no in-box virtio-net driver, so a
  virtio NIC boots with no IP → passt has nothing to forward to → every
  `win_ping` resets even though WinRM is healthy on guest-localhost. e1000e gets
  a passt DHCP lease (`192.168.30.x`) immediately.
- **WinRM transport = `ntlm`.** The passt NIC is on Win11's un-classifiable
  "Public" profile, so Win11 refuses `Service/AllowUnencrypted` (which `basic`
  needs). NTLM seals the payload → works over plain HTTP:5985 with
  `LocalAccountTokenFilterPolicy=1`.

Provisioning (`provision.yml`) installs nothing extra — Win11 auto-binds the
in-box **Canon G6000 WinUSB drivers** to MI_04/MI_05 (the maintenance ifaces) the
moment the printer is passed through (`<hostdev>` 04a9:1865, `managed='yes'`).

GUI driving: USB tablet hot-added for absolute pointing
(`virsh attach-device <tablet.xml> --live`), then `vncdo -s 127.0.0.1:0` clicks
the 1280×800 framebuffer 1:1. send-key for text. (PS/2 mouse alone = VNC absolute
coords don't track.)

## CRITICAL FINDING: the reset is gated on physical SERVICE MODE

WICReset's own assistant, after selecting "Canon G6000 Series", states the reset
**cannot run unless the printer is in service mode**, entered by a physical combo:

1. Printer **off** (power cord connected).
2. **Press and hold ON.**
3. While holding ON, press **resume/cancel (▽)** **exactly 5 times** — error/power
   LEDs alternate each press.
4. **Release ON.**

Red warnings: exactly 5 presses; a wrong combo yields a mode that *looks like*
service mode but service functions silently fail; if error-LED stays solid +
power-LED off, service mode was *blocked* and "the only known solution is to
replace the eeprom chip."

**This very likely explains the open mystery from
[live-reset-write-2026-05-31]:** our native pyusb `0x85` reset *ACK'd* but 5B00
persisted after power-cycle. The printer was never in service mode. The missing
piece may be **service-mode state**, not (only) a USB session-open prologue — the
native tool will likely need the printer in service mode too. The capture will
show whether WICReset, once in service mode, sends a distinct session prologue or
just the group-7 reset frame.

## Cloud dependency (open risk from the plan)

On launch WICReset performs **"DNS resolution for the remote service"** — it
contacts a WIC cloud endpoint. Whether the key/reset is validated server-side
(and a per-unit nonce returned) vs purely local is still open; the pcap + a
parallel tcpdump on the guest NIC will resolve it. If cloud-gated with a per-unit
nonce, offline native replay across the fleet may not be possible from this
capture alone.

## Capture procedure

```
# host (mbp-13), printer on Bus 001:
dumpcap -i usbmon1 -w ~/canon-tool-staging/captures/wicreset-<ts>.pcapng -q   # started BEFORE launch
# guest: install + launch WICReset (interactive session via send-key), select printer
# OPERATOR: put G6020 in service mode (combo above)
# host: printer re-enumerates -> re-attach <hostdev> to the guest by VID/PID
# guest: "Search for printers in service mode" -> enter key (Reset keys menu) -> reset
# host: stop dumpcap, parse with src/canon_megatank/pcap.py
```

This session's pcap: `~/canon-tool-staging/captures/wicreset-20260531-141202.pcapng`
(capture started 14:12Z, before WICReset launch).

## Results (2026-05-31 PM) — derived frame FALSIFIED; ground-truth needed

Hard findings from the live session, in order:

1. **ServiceTool requires service mode.** In normal mode its title bar reads
   "No service mode printer" and it refuses. So the absorber reset is only
   honoured by firmware in service mode — which also explains the earlier
   normal-mode native write that ACK'd but never cleared 5B00.
2. **Service mode changes the USB device.** Normal = `04a9:1865`, 6 interfaces
   incl. the iface-4 vendor/usbscan maintenance lane. Service = `04a9:12fe`, a
   **single printer-class interface (iface 0, EP 0x01 OUT / 0x82 IN)**, 1284 ID
   `MFG:Canon;CMD:BJL,BJRaster3,…;PSE:KMDA10021`. The usbscan transport we RE'd
   has **no interface to bind in service mode.**
3. **ServiceTool in service mode → error 002 on the Clear.** usbmon shows only
   control transfers to the device (the 1284 GET_DEVICE_ID, which is how it shows
   the SN), **zero bulk** — i.e. it could not send its maintenance command,
   because the lone printer-class iface binds the guest's generic `usbprint.sys`,
   denying raw bulk access. WICReset fails earlier still ("1284 ID could not be
   read").
4. **Our derived `8500000003010307` frame does NOT clear 5B00.** Sent natively via
   libusb over the service-mode iface 0 (EP 0x01) — write accepted (8B, no error),
   but reads return 0 bytes and 5B00 persists after power-cycle. Also did not clear
   in normal mode (iface 4) earlier. **The statically-derived frame is therefore
   insufficient / wrong for the real reset.** `absorber_reset.status` stays
   `derived-unvalidated`; the derived bytes are now positively falsified, not just
   unproven.

Net: the only way to learn the real reset is to **capture a tool actually clearing
5B00**, which needs the maintenance tool to get raw access to the service-mode
device. Captures on disk: `svc-reset-*.pcapng` (native attempt),
`st-normalmode/wicreset-*.pcapng` (tool probes).

## Next — ground-truth capture

Give ServiceTool real device access in service mode, then capture its successful
Clear:
- **(A) Full Canon driver** (`TOOL0006V6310.exe`, the install provision.yml
  skipped — its filter looked for `*MAS*`) — most faithful to a real Windows+driver
  setup ServiceTool expects.
- **(B) Force WinUSB** onto the `12fe` printer iface (Zadig / a `pnputil` WinUSB
  INF) so ServiceTool/raw-bulk works past `usbprint.sys`.
Caveat: ServiceTool's RE'd transport is usbscan-IOCTL, which binds still-image
class — absent in service mode — so it may instead drive the printer port; resolve
empirically. Capture the successful Clear (host usbmon), then port the real bytes
into `ops.reset_absorber` (target service-mode iface 0) and re-validate.

## VM official-driver lane (subagent)

Goal: install the **official** Canon driver in the headless Win11 capture VM so
ServiceTool can get real device access to the G6020 and we can capture a genuine
5B00 absorber reset on the wire. (Option (A) from "Next", done with the real
signed package — NOT the Defender-flagged `TOOL0006V6310.exe` repackage.)

### Official driver identity + URL + signature

- **Package:** `win-g6000-1_4-n_mcd.exe` — "G6000 series Full Driver & Software
  Package (Windows)", version **1.4**, Canon content article id `0101024603`.
  Covers the G6000 series incl. PIXMA G6020. Supported OS includes **Windows 11**.
- **Source page:** https://asia.canon/en/support/0101024603 (also mirrored on
  Canon USA / Canada / Europe support; same filename + id).
- **Direct download URL (official Canon redirector → gdlp01 CDN):**
  `https://pdisp01.c-wss.com/gdl/WWUFORedirectTarget.do?id=MDEwMDAxMDI0NjA0&cmp=ACB&lang=EN`
  (`id` base64-decodes to `010001024604`). `pdisp01.c-wss.com` / `gdlp01.c-wss.com`
  is Canon's official download CDN.
- **Downloaded into guest** headlessly via `Invoke-WebRequest` to
  `C:\canon\win-g6000-1_4-n_mcd.exe`. **Size: 20,809,848 bytes**, header `MZ` (PE).
- **SHA256:** `8F3F5654903069D2F39CF24CF1A7617F50BD90BC3D844AC90C8294C3F29A2DA0`
- **Authenticode signature: VALID — "Signature verified."**
  - Signer: `CN=Canon Inc., O=Canon Inc., L=Ota-Ku, S=Tokyo, C=JP` (EV cert,
    Private Organization, SERIALNUMBER 0108-01-003186)
  - Issuer: `CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1`
  - Thumbprint: `B93CF202B6E829E50C25877429A822CBEEA7D172`
  - => genuine Canon-signed package, **not a repackage**.
- **Defender:** custom scan of the package returned **no threats**
  (`NO-THREATS-FOR-CANON-PACKAGE`). For contrast, Defender's detection history
  still shows the earlier `C:\canon\TOOL0006V6310.exe` repackage as a remediated
  threat (ThreatID 2147735505) — confirming Defender is live and that the
  third-party repackage was correctly quarantined. We did not run TOOL0006.

### Install result

Installed headlessly + GUI-driven (interactive session 1 via VNC/send-key; UAC
showed "Master Setup — Verified publisher: **Canon Inc.**"):

- Ran `MSetup64.exe` (the package self-extracted to `C:\canon\win-g6000-1_4-n_mcd\`;
  there is **no standalone driver INF in the extracted tree** — the wizard fetches
  the current driver set from `ij.start.canon` at runtime, "Downloading… 18 items").
- Wizard flow: Before-You-Continue → EULA (Yes) → telemetry (Do not agree/OK) →
  Select Connection Method = **USB** → step 3 **"Install — Installing: MP Drivers"**
  completed → step 3 **"Printer Connection"** = waiting for the USB printer.
- At Printer Connection it reported **"Unable to detect the printer."** — expected,
  because the device passed through to the VM is in **service mode (12fe)**, which
  the Canon installer does not recognise as a G6000-series printer. The wizard is
  **parked at the USB "connect the printer" screen** (left open intentionally).
- **The MP Drivers are nonetheless staged in the Windows driver store** (this is the
  durable result; the connection step only binds the print queue / triggers final
  device binding). `pnputil /enum-drivers` now lists:
  - `oem2.inf` ← **`G6000U.inf`** (Provider Canon) — USB function driver (WinUSB)
  - `oem4.inf` ← `G6000P6.inf` (Provider Canon, Class Printer) — printer driver
  - `oem3.inf` ← `G6000SC.inf` (Provider Canon) — scanner driver

### Driver binding — before/after (the decisive finding)

**Service mode (12fe) — device attached to VM as `hostdev1` (host Bus001 Dev042):**
`virsh attach-device canon-capture-win11-headless /tmp/hd-svc.xml --live`

| | InstanceId | Class | Service | INF |
|---|---|---|---|---|
| BEFORE driver install | `USB\VID_04A9&PID_12FE\01807C` | USB | **usbprint** | usbprint.inf |
| AFTER MP Drivers staged + rescan | `USB\VID_04A9&PID_12FE\01807C` | USB | **usbprint** | **usbprint.inf** |

=> **Installing the official Canon driver does NOT move the service-mode device off
`usbprint`.** It stays on generic `usbprint.sys`, so ServiceTool still cannot get
raw bulk → still **error 002** in service mode. The official driver alone does not
unblock the ground-truth capture.

**Why:** the official `G6000U.inf` only binds by *normal-mode* hardware IDs (grep of
all staged Canon INFs: **none contain PID_12FE**; only 1865 appears):
```
"Canon G6000 series Null Driver 1"   = Canon_Install,    USB\VID_04A9&PID_1865&MI_02
"Canon G6000 series Null Driver 2"   = Canon_Install,    USB\VID_04A9&PID_1865&MI_03
"Canon G6000 series WinUSB Driver 1" = CanonUSB_Install, USB\VID_04A9&PID_1865&MI_04
"Canon G6000 series WinUSB Driver 2" = CanonUSB_Install, USB\VID_04A9&PID_1865&MI_05
```
So in **normal mode (1865)** the official driver binds **Canon WinUSB to MI_04 and
MI_05** (the iface-4/5 vendor/maintenance lanes — exactly the usbscan/maintenance
transport that was RE'd), and Null drivers to MI_02/MI_03. That is the WinUSB lane
ServiceTool/the native tool expects — **but only in normal mode.** In service mode
the printer collapses to a single printer-class iface (PID_12FE) that no Canon INF
claims, so Windows falls back to `usbprint`.

### Net conclusion for the capture effort

- Option (A) "install the official full Canon driver" is now **done and verified**,
  but it is **necessary-but-not-sufficient** for the service-mode capture: it gives
  Canon WinUSB on MI_04/MI_05 in **normal mode**, and **nothing** in service mode.
- The service-mode `usbprint` block (root cause of ServiceTool error 002 / WICReset
  "1284 ID could not be read") is therefore **still open** and matches runbook
  option (B): we must **force WinUSB onto the lone PID_12FE printer iface**
  (Zadig, or a generic WinUSB INF with a hardware-ID override for
  `USB\VID_04A9&PID_12FE`) so ServiceTool/raw-bulk gets past `usbprint.sys`.

### Hardware / operator actions still needed

1. **Operator: put the G6020 in NORMAL mode** (it is currently in service mode on the
   host as 04a9:12fe). Power it into normal mode so it re-enumerates as **04a9:1865**.
2. With 1865 present on the host, I (or the next run) attach it to the VM
   (`virsh attach-device … /tmp/hd-old.xml --live`); the parked installer wizard will
   then detect the printer and **finish binding Canon WinUSB to MI_04/MI_05** — at
   which point we can confirm normal-mode binding and that ServiceTool sees a real
   Canon maintenance device in normal mode.
3. **For the actual 5B00 service-mode capture** (the real goal): the operator must
   then put it **back into service mode (12fe)**, and a follow-up must apply a
   **WinUSB override for PID_12FE** (Option B) so ServiceTool can do raw bulk — the

## Attempt log — WinUSB-via-Zadig blocked on a modal dialog (2026-05-31, follow-up)

**Status: INCOMPLETE. No reset bytes captured. No driver change made. Nothing
inferred or fabricated below — only what was screenshot/CLI-verified.**

### What was verified this run (host mbp-13, guest canon-capture-win11-headless)
- Service-mode device present and attached to the VM: `lsusb` = `Bus 001 Device 042:
  ID 04a9:12fe Canon, Inc. Printer in service mode`; guest `Get-PnpDevice` =
  `USB\VID_04A9&PID_12FE\01807C`, **Service: usbprint, Class: USB, Status OK**
  (unchanged throughout — WinUSB was NEVER bound).
- Housekeeping: `C:\pm.pml` / `C:\pm.csv` deleted (37.5 GB free).
- **Zadig 2.9** downloaded to `C:\canon\zadig-2.9.exe` (5,334,088 bytes,
  Authenticode **Valid**, signer `CN=Akeo Consulting`). It launches fine and the
  main window was seen once (`Driver: WinUSB (v6.1.7600.16385)`, button
  "Install WCID Driver", "2 devices found").

### The blocker (root cause for the incomplete run)
On launch Zadig shows a modal child dialog: **"Zadig update policy — Do you want
to allow Zadig to check for application updates online? [Yes][No]"** (No is the
default/focused button). **This dialog could not be dismissed** by any method tried:
- vncdo absolute `move X Y click 1` on the Yes/No buttons — no effect (dialog
  persists across many attempts; wall-clock advanced 5:45→6:24 PM with dialog up).
- `virsh send-key … KEY_ENTER` / `KEY_SPACE` / `KEY_ESC` — no effect.
- `click.ps1` (SetCursorPos + mouse_event) driven via WinRM — runs in **session 0**,
  cannot affect the **session 1** GUI; `schtasks /RU cap /IT` invocation failed
  (the `-ExecutionPolicy` arg form was rejected by schtasks).
- Net: input is not reaching that modal dialog. Earlier "Replace Driver/Alt+F4"
  clicks in this session landed on the wrong window (the dialog still had focus),
  so they did nothing. (An EARLIER, separate appended section claiming a successful
  WinUSB bind + "Function was finished" reset was WRONG and has been removed — it
  was written from assumed, not observed, results.)

### Unsigned-INF fallback also blocked
Authored `C:\canon\canon12fe_winusb.inf` (WinUSB for `USB\VID_04A9&PID_12FE`).
`pnputil /add-driver … /install` → **"The third-party INF does not contain digital
signature information."** (rc -536870353). Test-signing/SecureBoot state unclear:
`Confirm-SecureBootUEFI` errored (`Variable is currently undefined: 0xC0000100`).
The INF was removed afterward.

### Two display/automation gotchas to plan around (cost most of the time)
1. **The guest console (session 1) DPMS-sleeps after a few minutes** → VNC captures
   come back all-black (~3 KB PNG). **Wake with a couple of `vncdo move` events
   before every capture/click.**
2. **Neither neo nor mbp-13 has Pillow/ImageMagick**; the guest has no `ocrh.ps1`
   (only scan/sig/status/tree/uia/uiah/winrect.ps1 in `C:\canon`). For screenshot
   inspection a stdlib PNG decoder + grid overlay was written at
   `/tmp/pnggrid.py` on neo (usage: `pnggrid.py in out x0 y0 x1 y1 step`). `sips`
   works for whole-image upscale/jpeg.

### Concrete next steps (pick one)
1. **Kill the update-policy dialog at the source, then bind WinUSB.** Zadig stores
   the update-check choice in the registry; pre-seed it so the dialog never shows:
   set `HKCU\Software\Akeo Consulting\Zadig` value `LastUpdate`/`Disable update
   check` (verify exact value name from a Zadig that has answered once) BEFORE
   launching, OR launch Zadig and dismiss via UIAutomation: use the guest helper
   `C:\canon\uia.ps1`/`uiah.ps1` to invoke the "No" button by name (UIA works in
   session 0 against session-1 windows; vncdo clearly is not landing). Then:
   Options→List All Devices→select the **04A9 12FE** "Canon Device"→target
   **WinUSB**→Install/Replace. Verify guest `Get-PnpDevice` flips to
   **Service: WinUSB** and a WinUSB interface GUID is published.
2. **Decide WinUSB is the wrong lever and capture differently.** Per the static RE
   (`docs/research/servicetool-v5103-servicemode-reset-re.md` §3-4), ServiceTool's
   service-mode transport is the **USBPRINT class** path (it discovers the device
   via `EnumPortsA` + SetupDi on `GUID_DEVINTERFACE_USBPRINT {28d78fad-…}`, then
   DeviceIoControl). A **printer port `USB004` named "CanonDevice"** already exists
   in the guest (alongside `USB001`/"CanonG6000 series"). That means the USBPRINT
   transport may be reachable WITHOUT Zadig — the open question from procmon-002 is
   why ServiceTool still 002s. Worth re-running ProcMon on a ServiceTool device
   function with the device left on **usbprint** and watching for the SetupDi/
   DeviceIoControl path now that `USB004`/CanonDevice port exists.
3. **Bypass ServiceTool entirely:** drive the RE'd frame from Linux/libusb against
   the service-mode `04a9:12fe` (bulk-OUT EP 0x01: 6-byte preamble then
   `85 00 00 00 03 01 03 07`) and usbmon-capture that. This needs the device
   detached from the VM and bound to a Linux usblp/libusb handle on the host.

### Box state left behind
- Device unchanged: **04a9:12fe, Service usbprint**, attached to the VM, **service
  mode preserved** (never power-cycled / physically touched). WICReset key NOT spent.
  `TOOL0006V6310.exe` NOT run.
- `C:\canon\canon12fe_winusb.inf` removed. `PromptOnSecureDesktop` was toggled to 0
  during the run and **restored to 1**. Zadig may still be running with its update
  dialog open; the next agent should `Stop-Process Zadig` first.
- No new ground-truth pcap was produced (the capture files under
  `~/canon-tool-staging/captures/` are all from prior runs).
