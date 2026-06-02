# Instrumented WICReset capture — the definitive G6020 5B00 reset capture

**Goal.** Capture the EXACT USB sequence WICReset sends to clear the G6020 absorber
counter, on a real successful reset, and answer the make-or-break question for the
open native tool: **is the device-side reset a replayable LOCAL control transfer, or
is it cloud-validated per-reset (a nonce the firmware checks)?**

Why this is the path: static RE took us to the wall (the v5103-shaped `0x40/0x85`
control-OUT is ACK'd but firmware-GATED on this generation — 5B00 persists). The G6020
*does* clear via WICReset (the operator's trusted OctoInkjet tool — Octo's own G6020
reset is WICReset-driven, no proprietary algorithm). So we instrument WICReset doing
its real clear and learn the genuine bytes + whether they're locally replayable.

## The 3-layer rig (all on ONE successful reset, one VM session)

| Layer | What | Tool | File |
|---|---|---|---|
| 1. WIRE | USB ground truth over the passed-through `04a9:12fe` | host `usbmon` (`dumpcap -i usbmon1`) | `*-wire.pcapng` |
| 2. APP | the command frame + runtime-sourced bytes (pcap shows only opaque payload) | Frida in guest hooking `DeviceIoControl` + `WinUsb_*` + `CreateFile` | `*-frida.log` |
| 3. NET | does WICReset phone home at reset time? (local vs cloud) | guest `pktmon` (built into Win10/11) + Frida WinINet/WinHTTP/connect hooks | `*-net.pcapng` |
| + ANCHOR | correlate all three to the exact transfer before EEPROM commit | host `date +%s.%N` at reset-click + guest launch anchor | `anchors.log`, `*-anchor.txt` |

Components (IaC, in-repo):
- `host/vm-capture/win/frida-wicreset-hook.js` — the dual-path Frida hook.
- `host/vm-capture/win/run-frida-capture.ps1` — guest launcher (downloads standalone
  frida.exe, no Python; `-Setup` stages, `-Launch` spawns the tool under frida).
- `scripts/wicreset-instrumented-capture.sh` — host orchestrator
  (`preflight|stage|rehearse|anchor|capture|stop`).

## Substrate facts (verified 2026-06-01)

- mbp-13: QEMU 10.0.0, `dumpcap` has `cap_net_admin,cap_net_raw` (unprivileged
  capture), `usbmon` not loaded at rest (orchestrator `modprobe`s it).
- Passthrough is libvirt `<hostdev managed='yes'>`; we use **host usbmon** for the
  wire (proven working in prior runs) rather than QEMU `pcap=` (fiddly with managed
  hostdev). usbmon captures the URBs the same way.
- Guest has **no Python** → Frida via the **standalone CLI exe** (PyInstaller-frozen),
  not the pip package. If the in-guest download fails, scp `frida.exe` to mbp-13 and
  `win_copy` it to `C:\canon\frida.exe`.
- Guest GUI driven over VNC (`vncdo -s 127.0.0.1:0`, USB tablet attached) + send-key;
  the operator enters the single-use key and clicks reset (human controls the key).

## Procedure

### A. Stage (no key, no hardware)
```
scripts/wicreset-instrumented-capture.sh preflight   # substrate check
scripts/wicreset-instrumented-capture.sh stage       # push hook+launcher, frida -Setup
```
If `frida.exe` doesn't download in-guest: fetch the `frida-<ver>-windows-x86_64.exe.xz`
from github.com/frida/frida releases on mbp-13, decompress, `win_copy` to
`C:\canon\frida.exe`, re-run `preflight`.

### B. Rehearse (NO key, NO reset) — prove the rig fires
```
scripts/wicreset-instrumented-capture.sh rehearse
# drive a BENIGN action over VNC: let WICReset detect the printer / read device id.
# NO key entry, NO reset click.
```
Pass criteria: `*-frida.log` shows `HOOK_LOADED` + `DeviceIoControl`/`CreateFile`
(or `WinUsb_*`) lines on the benign detect; the wire pcap has URBs to `12fe`; the
pktmon etl exists. This proves all three layers capture before we spend a key.

### C. The real capture (spends one OctoInkjet key)
Pre: printer in **SERVICE mode** (`12fe`) and attached to the VM
(`virsh --connect qemu:///session attach-device <VM> /tmp/hd-svc.xml --live`);
operator has the key.
```
scripts/wicreset-instrumented-capture.sh capture
```
Operator, over VNC:
1. Select the service-mode Canon G6020 in WICReset.
2. Enter the OctoInkjet key, begin the reset.
3. **Just before the final reset click**, in another terminal:
   `scripts/wicreset-instrumented-capture.sh anchor reset-click`
4. **Wait for the SUCCESS window.** Per OctoInkjet: do NOT read the counter, print,
   or check ink before the power-cycle, or the reset fails and the key burns.
5. Back at the orchestrator, press ENTER to stop capture (captures are stopped at the
   success window, before the power-cycle).
6. **Power-BUTTON the printer off, wait 10s, power on** (NOT unplug). Check the panel:
   5B00 should be gone.

### D. Analyze
- **WIRE:** `tshark -r *-wire.pcapng -Y "usb.device_address==N && usb.capdata"` →
  the exact control transfers (bmRequestType/bRequest/wValue/wIndex/data) and any
  device responses around the anchor timestamp.
- **APP:** the `*-frida.log` `DeviceIoControl`/`WinUsb_*` lines around the anchor give
  the application command frame + the runtime bytes (preamble, session) the static RE
  could not supply.
- **NET (local-vs-cloud):** does `*-net.pcapng` / the Frida WinINet/connect lines show
  a cloud call *between* key-entry and the reset transfer? If the reset transfer is
  emitted with no preceding network round-trip carrying a per-reset token → likely
  locally replayable. If a server round-trip returns bytes that then appear in the USB
  payload → cloud-nonce-gated.
- **DECISIVE — offline replay test:** later, with the printer freshly in service mode
  and a *new* key NOT yet spent, replay ONLY the captured USB control transfers from
  Linux (`ctrl_transfer`) with the network DISCONNECTED, then power-cycle + EEPROM
  read-back. Clears offline → native key-free tool is possible. Fails offline but the
  online WICReset clears → cloud-gated, native replay impossible for G6020.

## Safety + constraints
- Spends exactly one key per real run; operator provisions keys from OctoInkjet.
- NEVER read counter / print before the post-success power-cycle (burns the key).
- Power-BUTTON cycle, never unplug, for the WICReset success step (vendor protocol).
- Frida is observational only — it never enters the key or clicks reset.
- Trusted binaries only: WICReset = the operator's genuine OctoInkjet build; Frida =
  the signed standalone CLI from frida.re GitHub releases. No crack mirrors.
