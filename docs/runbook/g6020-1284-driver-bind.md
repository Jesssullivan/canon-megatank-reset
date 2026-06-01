# G6020 1284-ID gate — Lane A fix (NOT a driver bind: a usbprint buffer-size clamp)

**Date:** 2026-06-01 · **Host:** mbp-13 (Rocky 10.1) · **Guest:**
`canon-capture-win11-headless` (`virsh --connect qemu:///session`, autologon
`cap`, WinRM/ntlm via `host/vm-capture/ansible/inventory.yml`).
**Device:** `04a9:12fe` (G6020 in **service mode**, Bus 001 Dev 046), single
printer-class interface (`070102`), passed through to the VM.
**Constraints honoured:** no WICReset key spent (`~/canon-tool-staging/.wic-key`
left 16 B mode 600, no key file ever copied into the guest), no reset write, no
power-cycle, **no driver binding changed** — device left `Service=usbprint`
exactly as found.

This is the Lane A deliverable. It **overturns the task's framing** (which
assumed 12fe was on the *wrong* driver and a Canon still-image/usbscan driver
had to be bound). Read the VERDICT first.

---

## VERDICT (evidence-final)

- **There is NO driver to bind, and a driver bind is the WRONG lever.** IOCTL
  `0x220034` is `IOCTL_USBPRINT_GET_1284_ID` — a **`usbprint.sys`** IOCTL
  (`CTL_CODE(FILE_DEVICE_USB=0x22, func 0x0d, METHOD_BUFFERED, FILE_ANY_ACCESS)`),
  not a still-image/usbscan IOCTL. (Confirmed by `g6020-ioctl-220034-re.md`:
  printerpotty has zero `Usbscan`/`StiUsb`/`WIA` references; the whole `0x22`
  family rides the `GUID_DEVINTERFACE_USBPRINT` handle.) The `12fe` device is
  **already on the correct driver** (`usbprint.sys`) and already answers
  `0x220034`.
- **The real blocker is a `usbprint.sys` output-buffer cap, not the device or the
  driver family.** On this Win11 build (`usbprint.sys 10.0.26100.8328`),
  `0x220034` returns the 120-byte 1284 ID for any output buffer **≤ 4096 bytes**
  and FAILS with `ERROR_CRC (23)` / `bytesReturned:0` for any buffer **> 4096**
  (one page). WICReset's extended read (`USBPipe::do_read_1284ID`) asks for
  **5000** bytes → fails → "Device 1284 ID could not be read" → bails before the
  key. Its discovery read (Site B) asks for **4096** → succeeds → which is why the
  printer still *enumerates*.
- **THE FIX = clamp the `0x220034` output-buffer size to 4096** at the
  app→kernel boundary. A 6-line Frida hook on `kernel32!DeviceIoControl`
  overwrites `nOutBufferSize` (arg 5) to `0x1000` for ioctl `0x220034`. No driver
  change, no key, printer-class enumeration untouched.
- **PROVEN LIVE in WICReset (printerpotty v5.95):** with the clamp active, the
  5000-byte call returns `ret:1 bytesReturned:120` (the full `MFG:Canon;…;PSE:
  KMDA10021` ID), WICReset **still detects** "Canon Printer (Unrecognized)" + shows
  "Reset waste counter(s)", and the "1284 ID could not be read / unsupported or
  not in service mode" gate is GONE. WICReset advances to the **next** stage (the
  encrypted maintenance session) — out of Lane A scope.

---

## 1. Established facts (enumeration)

Installed Canon INFs in the guest driver store (`pnputil /enum-drivers`), all
Canon-signed:

| oem | original | provider | class | matches |
|---|---|---|---|---|
| `oem2.inf` | `g6000u.inf` | Canon | USB | WinUSB on `PID_1865 MI_04/MI_05`; null on MI_02/MI_03 |
| `oem3.inf` | `g6000sc.inf` | Canon | **Image** (`{6bdd1fc6-…}`), `SubClass=StillImage`, `Needs=STI.USBSection.Services` | `PID_1865 MI_00` only |
| `oem4.inf` | `g6000p6.inf` | Canon | Printer | `PID_1865` printer node |

**None of the Canon INFs lists `PID_12FE`.** The still-image INF (`oem3`) matches
only the normal-mode scanner interface `USB\VID_04A9&PID_1865&MI_00` — an
**Image-class interface that does not exist** on the service-mode `12fe` device
(`12fe` is a *single printer-class interface*). So the still-image driver
**cannot bind** to `12fe`, and even if force-bound would not service `0x220034`
(a usbprint IOCTL). WinUSB binds but **removes** the printer-class device
interface WICReset enumerates → empty list (the prior `g6020-winusb-bind-capture-
rig.md` finding). Hence: leave it on `usbprint`.

`12fe` device facts (`Get-PnpDevice` / `Get-PnpDeviceProperty`):

```
InstanceId : USB\VID_04A9&PID_12FE\01807C
Class      : USB        Status : OK        Service : usbprint   (usbprint.inf)
HardwareIds: USB\VID_04A9&PID_12FE&REV_0107 | USB\VID_04A9&PID_12FE
CompatIds  : USB\…Class_07&SubClass_01&Prot_02 | … (USB printer class, bidirectional)
```

## 2. The exact cap (direct IOCTL sweep on the stock usbprint binding)

Opening `\\?\usb#vid_04a9&pid_12fe#01807c#{28d78fad-5a12-11d1-ae5b-0000f803a8c2}`
and calling `0x220034` with varying output-buffer sizes:

| outSize | ok | bytesReturned | err |
|---|---|---|---|
| 120 | False | 0 | 23 (buffer < the 120 B answer) |
| 121 … **4096** | **True** | **120** | 203 (benign) |
| **4097** | False | 0 | **23 (ERROR_CRC)** |
| 5000 | False | 0 | **23** |

The flip is **exactly at 4096** (one page) — a `usbprint.sys` GET_1284_ID
transfer-size limit on this build, independent of service mode.

## 3. The fix — `frida-1284clamp-hook.js`

Committed at `host/vm-capture/win/frida-1284clamp-hook.js`. Core:

```js
const CLAMP = 4096, IOCTL_GET_1284 = 0x220034;
Interceptor.attach(DeviceIoControl, { onEnter(args) {
  if (args[1].toUInt32() === IOCTL_GET_1284 && args[5].toUInt32() > CLAMP)
    args[5] = ptr(CLAMP);          // nOutBufferSize 5000 -> 4096
}});
```

It only ever *shrinks* the output buffer for `0x220034`; the kernel still writes
the 120-byte ID and reports `bytesReturned=120`, which WICReset parses
identically (it strips the 2-byte length prefix and reads `MFG`/`MDL`).

## 4. Live proof in WICReset (printerpotty v5.95)

Launched interactively under the proven v16.5.9 injector
(`C:\canon\frida-inject-x86-16.exe -f C:\PROGRA~2\PRINTE~1\PRINTE~1.EXE -s
C:\canon\frida-1284clamp-hook.js -R v8`, via `schtasks /ru cap /it`). Hook log:

```
{"api":"DeviceIoControl","dir":"in", "ioctl":"0x220034","outSize":4096,"clamped":false}   ← Site B discovery
{"api":"DeviceIoControl","dir":"out","ioctl":"0x220034","ret":1,"bytesReturned":120,…}    ← always worked
{"api":"CLAMP","ioctl":"0x220034","origOutSize":5000,"newOutSize":4096}                    ← Site A deep read
{"api":"DeviceIoControl","dir":"in", "ioctl":"0x220034","outSize":4096,"clamped":true}
{"api":"DeviceIoControl","dir":"out","ioctl":"0x220034","ret":1,"bytesReturned":120,
  "clamped":true,"outHex":"7878 MFG:Canon;CMD:BJL,…;MDL:Device;…;STA:10;PSE:KMDA10021;"}    ← NOW RETURNS DATA
```

VNC screenshot after: left panel **"Canon Printer (Unrecognized)"**, main pane
**"Waste counters" + "Reset waste counter(s)"**, assistant **"Select Canon
Printer (Unrecognized)."** → **detection intact, 1284 gate passed.** The red
banner now reads **"Could not read encrypted buffer with the printer series name
from the device"** — the *next* stage (`0x220038`/`0x22003c` encrypted
set_session/get_keyword maintenance session), i.e. the keyed path, NOT the
1284 gate. That is the keyed-capture work, downstream of Lane A.

Post-run: `12fe` still `Status=OK Class=USB Service=usbprint`; no key in guest;
processes + schtask cleaned up; device left as found.

## 5. Reproducible IaC steps

1. Stage assets in the guest (host `win_copy`, **forward slashes** in DEST):
   - `host/vm-capture/win/frida-1284clamp-hook.js` → `C:/canon/frida-1284clamp-hook.js`
   - `frida-inject-x86-16.exe` (v16.5.9; v17 broken on this guest) already staged.
2. Confirm `12fe` is on `usbprint` (default — do NOT rebind, do NOT Zadig→WinUSB):
   `Get-PnpDevice -InstanceId "USB\VID_04A9&PID_12FE\01807C"` → `Service usbprint`.
3. Launch WICReset under the clamp hook **interactively** (so the GUI lands on the
   console for VNC) via `schtasks /Create /TN cmrclamp /TR <wrapper.cmd> /SC ONCE
   /RU cap /IT /F; schtasks /Run /TN cmrclamp`, where the wrapper runs
   `frida-inject-x86-16.exe -f <printerpotty 8.3 path> -s
   C:\canon\frida-1284clamp-hook.js -R v8 > log 2> err`. Do NOT use `-e` (freezes
   the log); do NOT use `-o` (no output on this v16). Redirect stdout/err via the
   `.cmd` wrapper / `Start-Process`.
4. Verify in the hook log: a `{"api":"CLAMP",…origOutSize:5000…}` line followed by
   `{…"clamped":true,"bytesReturned":120…}`. Verify over VNC that the printer still
   shows "Canon Printer (Unrecognized)" + "Reset waste counter(s)".
5. **STOP. Do not enter the key.** Reaching the reset UI past the 1284 gate is the
   Lane A success criterion; the key is spent only in the downstream keyed-capture
   run.

### Optional: make the fix driverless / permanent

The clamp can also be applied without Frida, if a no-instrumentation path is
wanted: a tiny `kernel32!DeviceIoControl` IAT/inline shim DLL `AppInit`'d /
`SetDllDirectory`-shimmed into printerpotty, or a Detours/Microsoft-Detours
trampoline, doing the same `nOutBufferSize` clamp. The Frida hook is the
lowest-friction form and is already the rig WICReset is captured under, so it is
the recommended carrier for the keyed run too (clamp + capture in one hook).

## 6. Why a driver rebind was rejected (do not retry)

- Still-image/usbscan (`oem3`): no Image interface on `12fe` to bind; would not
  service `0x220034` anyway (usbprint IOCTL). **Impossible + useless.**
- Canon Printer-class (`oem4`) forced onto `12fe` via a `PID_12FE`-augmented INF:
  a printer-class driver still layers on `usbprint.sys`, so `0x220034` would hit
  the same 4096 cap. **Useless** (and an unsigned/edited INF needs test-signing).
- WinUSB (Zadig / WinUSB INF): removes the printer-class device interface →
  WICReset enumerates nothing. **Breaks detection** (prior finding, re-confirmed).
- Stock `usbprint.sys`: already bound, already answers `0x220034` ≤4096. The cap
  is in the driver's transfer logic, not reachable by swapping the *upper* driver.

The single load-bearing change is the **buffer-size clamp**, not a binding.

---

## 7. RETEST (no key) — full UI drive to the warning, 2026-06-01

**Goal:** with the clamp binding from §3 re-applied, relaunch WICReset under frida
v16.5.9 and drive the whole flow (Refresh → "Canon Printer (Unrecognized)" →
assistant → Open main interface → Reset waste counter(s) → **Yes**) to see whether
it now reaches the **key-entry prompt** instead of the old 1284 bail. **No key
spent.** Screenshots archived host-side at
`~/canon-tool-staging/captures/retest-20260601/vnc-step{1..7}-*.png`.

### Result: 1284 gate CLEARED (confirmed, fresh run). Key prompt NOT reached.

Relaunched via `C:\canon\launch-clamp-task.ps1` (recreates `cmrclamp` schtask,
`/RU cap /IT`, runs `clamp-wrap.cmd` = `frida-inject-x86-16.exe -f
C:\PROGRA~2\PRINTE~1\PRINTE~1.EXE -s C:\canon\frida-1284clamp-hook.js -R v8`). Hook
log this run (`C:\canon\clamp-wicreset.log`) — every deep read clamps and returns
data, including the one triggered by the **Reset → Yes** click at t=127030:

```
{"api":"CLAMP","ioctl":"0x220034","origOutSize":5000,"newOutSize":4096,"t":8929}
{"api":"DeviceIoControl","dir":"out","ioctl":"0x220034","ret":1,"bytesReturned":120,"clamped":true,
  "outHex":"7878…MFG:Canon;CMD:BJL,…;MDL:Device;…;STA:10;PSE:KMDA10021;"}
… (repeats for each detect cycle, and once more after the warning-Yes click) …
{"api":"CLAMP","ioctl":"0x220034","origOutSize":5000,"newOutSize":4096,"t":127030}  ← Reset→Yes deep read
{"api":"DeviceIoControl","dir":"out","ioctl":"0x220034","ret":1,"bytesReturned":120,"clamped":true,…}
```

UI states walked (each screenshotted):

| step | screenshot | state |
|---|---|---|
| 1 | `vnc-step1-detect.png` | left "Canon Printer (Unrecognized)" + "Reset waste counter(s)"; assistant "Greetings … Select Canon Printer (Unrecognized)." **No 1284 error.** |
| 2 | `vnc-step2-select.png` | after Select: assistant **"This CANON printer is already in service mode. You must select the correct operation from the main interface."** ← brand-new state, never reached before |
| 3 | `vnc-step3-main.png` | Open main interface → printer **selected** (blue), "Waste counters" pane active |
| 4 | `vnc-step4-resetbtn.png` | Reset waste counter(s) → warning **"Please read this first! …(5B00,1700)… reset key may be lost. Continue?"** Yes/No |
| 5 | `vnc-step5-afteryes.png` | **Yes** → NO key prompt. New red line appended + bottom shows **"This printer is either unsupported or not in service mode."** |
| 6 | `vnc-step6-resetkeysmenu.png` | "Reset keys" menu = only **"Buy reset key(s) online"** / **"Check Reset Key"** (no standalone "enter key" item; key entry is gated inside the reset flow). Not clicked (would risk a key prompt). |
| 7 | `vnc-step7-closed.png` | parked at residual |

### Verdict

- **Gate CLEARED:** the old hard bail ("Device 1284 ID could not be read" /
  "unsupported or not in service mode" *before detection*) is GONE. The tool now
  detects, selects, and **explicitly asserts the printer is in service mode**,
  opens the main interface, and accepts the reset warning. That is materially
  further than any prior run.
- **Key prompt NOT reached → NO-GO for the keyed run (yet).** After **Yes**,
  WICReset does **not** prompt for the reset key. It fails at the **next** stage —
  the encrypted maintenance session (`0x220038` set_session / `0x22003c`
  get_keyword) — logging "Could not read encrypted buffer with the printer series
  name from the device", which then re-raises the generic "unsupported or not in
  service mode" **at this later point** (not the 1284 gate). The clamp hook only
  instruments `0x220034`, so the encrypted IOCTLs aren't in its log; the failure
  is downstream of and independent from the 1284 clamp.

### Precise residual gate + next no-key move

- **Residual:** the **encrypted printer-series-name read** (`0x220038`/`0x22003c`
  VENDOR_SET/GET on the same `usbprint` handle). WICReset must decrypt a
  series-name/keyword buffer to bind the printer to a model profile **before** it
  will show the key field. Empty/garbled here → "Could not read encrypted buffer …"
  → bail. This is the keyed-capture path (Lane B/keyed scope), **not** a 1284 or
  driver problem.
- **It is NOT a driver/usbscan/test-signed-INF problem.** Re-confirmed this run:
  `12fe` stayed `Status=OK Class=USB Service=usbprint ProblemCode=0`; the 1284 ID
  read returns the full blob every cycle. Binding a usbscan/still-image node or
  test-signing a `PID_12FE` printer INF would not help — the `0x22003c` data is
  the firmware's encrypted vendor response, gated by the maintenance-session
  protocol, not by the upper driver. (The vendor IOCTLs already reach the device
  fine; the buffer is *unreadable/encrypted*, not *unroutable*.)
- **Next no-key step:** extend the Frida hook from a narrow `0x220034` clamp to
  also **trace `0x220038`/`0x22003c`** (inSize/outSize, in/out hex) so we capture
  the exact set_session → get_keyword exchange and see *why* the series-name buffer
  comes back empty (wrong session seed? a length WICReset rejects? a buffer-size
  cap like the 1284 one?). Decode the encrypted-series-name handshake from the
  `appbin`/printerpotty RE already underway (`C:\canon\appbin-*`,
  `frida-events.log`). Only once that handshake yields a non-empty series name
  (and WICReset advances to the key field) is it GO to spend the key.

### Non-destructive guarantees (verified post-run)

- `12fe` unchanged: `Status=OK Class=USB Service=usbprint ProblemCode=0`.
- No `.wic-key` ever copied into the guest (recursive search of `C:\` = none).
- Host key untouched: `~/canon-tool-staging/.wic-key`, 16 B, mode 600, mtime 09:28
  (pre-run).
- No reset write / no clear / no `0x85`: last 1284 ID still `STA:10` (service mode
  intact, absorber not reset). No power-cycle. No driver rebind.
- WICReset left parked at the residual encrypted-session failure for the
  keyed-capture follow-up.
