# G6020 1284-ID baseline — the WICReset failure on the CURRENT usbprint binding (Lane C control)

**Date:** 2026-06-01 (run ~11:40 UTC) · **Host:** mbp-13 (Rocky 10.1) ·
**Device:** `04a9:12fe` (G6020 in **service mode**, Bus 001 Dev 046),
passed through to `canon-capture-win11-headless` via libvirt `<hostdev managed='yes'>`.
**Guest binding under test:** `USB\VID_04A9&PID_12FE\01807C` → **Status OK,
Service `usbprint`, CM_PROB_NONE** (the generic Windows printer-class driver —
the current, unmodified state).

**Purpose.** This is the **Lane C control**: a faithful re-capture of the exact
call that WICReset (PrinterPotty v5.95) fails on *today*, on the stock
`usbprint` binding, so the Lane A driver-rebind fix can be measured against a
known-bad baseline. **Non-destructive: no key entered, no reset clicked, no
power-cycle, binding left exactly as found.** The frida hook is observational
only.

---

## TL;DR — the baseline failure

WICReset issues the IEEE-1284 device-ID read via **one and the same IOCTL,
`0x220034`** (the still-image / usbscan `GET_1284_ID` family), **twice per detect
cycle**, distinguished only by the caller's output-buffer size:

| call | ioctl | inSize | outSize | ret | bytesReturned | result |
|---|---|---|---|---|---|---|
| **BASIC 1284 read** | `0x220034` | 0 | **4096** | **1** | **120** | **SUCCESS** — returns the 120-byte device ID |
| **EXTENDED 1284 read** | `0x220034` | 0 | **5000** | **0** | **0** | **FAILURE** — empty → "Device 1284 ID could not be read" |

The extended (`outSize=5000`) read returning **ret:0 bytesReturned:0 (empty)** is
what makes WICReset print **"Device 1284 ID could not be read"** and leave the
device as **"Canon Printer (Unrecognized)"** — it bails here, **before** any
reset-key prompt. The basic (`outSize=4096`) read **succeeds in the same
session** and returns the full 120-byte ID, so the failure is specific to the
extended read on the `usbprint` binding, **not** a dead device or a dead pipe.

> Note this **refines** the prior framing: `0x220034` is *not* inherently empty
> on usbprint — at `outSize=4096` it returns the 120 B ID fine. Only the
> `outSize=5000` extended variant comes back empty. Whatever Lane A binds must
> make the `outSize=5000` call return data while keeping the `outSize=4096`
> path (and discovery) working.

---

## 1. The exact failing call (frida-captured, fresh session)

App-layer capture: **frida v16.5.9** (`C:/canon/frida-inject-x86-16.exe`) with
`C:/canon/frida-wicreset-hook.js` hooking `DeviceIoControl`, spawning PrinterPotty
under the hook (`-f … -s hook -R v8`, **no `-e`** so the injector holds the
stdout pipe and `console.log` events flush to `C:/canon/frida-events.log`).
Launched **interactively in console session 1** via `schtasks /RU cap /IT
/RL HIGHEST` (NOT a WinRM session-0 Start-Process — that never reaches the GUI).

The full chronological `DeviceIoControl` sequence WICReset emits per detect cycle
(usbprint port queries `0x47xxxx`, then the two 1284 reads), captured twice at
startup:

```
in   0x470807  outSz=32788          t=3278     # usbprint port info
out  0x470807          br=166 ret=1 t=3278
in   0x470813  outSz=420            t=3278     # usbprint config queries x3
out  0x470813          br=78  ret=1 t=3278
in   0x470813  outSz=532            t=3278
out  0x470813          br=20  ret=1 t=3278
in   0x470813  outSz=36             t=3280
out  0x470813          br=36  ret=1 t=3280
in   0x220034  outSz=4096           t=3280     # BASIC 1284 read  -> SUCCESS
out  0x220034          br=120 ret=1 t=3282     #   120 bytes returned
in   0x470853  outSz=16             t=3284     # usbprint
out  0x470853          br=16  ret=1 t=3284
in   0x220034  outSz=5000           t=3286     # EXTENDED 1284 read -> FAIL
out  0x220034          br=0   ret=0 t=3288     #   EMPTY (ret:0 bytesReturned:0)
… (the whole block repeats once more, t=3316–3320) …
```

**The exact failing call, verbatim from `frida-events.log`:**

```json
{"api":"DeviceIoControl","dir":"in","ioctl":"0x220034","inSize":0,"outSize":5000,"inHex":"","t":3286}
{"api":"DeviceIoControl","dir":"out","ioctl":"0x220034","ret":0,"bytesReturned":0,"outHex":"","t":3288}
```

- **ioctl** = `0x220034` (still-image `GET_1284_ID` family)
- **inSize** = 0, **outSize** = 5000
- **ret** = 0 (DeviceIoControl returned FALSE)
- **bytesReturned** = 0 (empty out-buffer)

Failing extended-read count this session: **2** (one per detect cycle, matching
the two "Device 1284 ID could not be read." lines on screen after startup; a
third appeared after clicking "Search for available printers again", confirming
the click re-issues the same failing `0x220034/5000`).

The on-screen evidence (VNC): WICReset v5.95, left pane **"Canon Printer
(Unrecognized)"**, assistant dialog open at the printer-select step, and red
**"Device 1284 ID could not be read."** lines at the bottom. Parked here —
**before the key prompt**.

---

## 2. The basic 1284 read works in the SAME session — and IS the reference

The basic read (`0x220034 outSize=4096`) returns **ret:1 bytesReturned:120** with
this `outHex` (identical across both detect cycles AND identical to the prior
session — byte-for-byte stable):

```
78784d46473a43616e6f6e3b434d443a424a4c2c424a526173746572332c42534343652c4956
45432c49564543504c493b4d444c3a4465766963653b434c533a5052494e5445523b4445533a
43616e6f6e204465766963653b5645523a312e3037303b5354413a31303b5053453a4b4d4441
31303032313b
```

Decoded (120 B; leading `78 78` = the literal `xx` Windows places where the
IEEE-1284 2-byte length prefix would sit on this GET_1284_ID path):

```
MFG:Canon;CMD:BJL,BJRaster3,BSCCe,IVEC,IVECPLI;MDL:Device;CLS:PRINTER;DES:Canon Device;VER:1.070;STA:10;PSE:KMDA10021;
```

This is **the reference the extended read should also return** — it carries
`STA:10` (service mode) and `PSE:KMDA10021`, exactly the identity Lane B reads
natively on the host via the class control-IN `0xA1/0x00` GET_DEVICE_ID
(`docs/runbook/wicreset-device-keyword-read.md`, §1). i.e. the Windows
`0x220034/4096` minidriver path and the host-side `0xA1/0x00` class control-IN
return the *same* 120 bytes — so the basic 1284 read is confirmed working in
this session at the application layer, without detaching the live device (a
host pyusb `0xA1/0x00` probe would have required unbinding the device from the
running WICReset session, which would have perturbed the very binding being
baselined; the frida-captured 120 B is the same bytes and is non-perturbing).

---

## 3. Why the split (basic OK, extended empty) on usbprint

`0x220034` is the still-image / usbscan `GET_1284_ID` IOCTL. On the generic
**usbprint** binding the device-ID is serviced for the small (`4096`) request but
the **extended (`5000`) request comes back empty** — the usbprint minidriver does
not satisfy the larger still-image GET_1284_ID the way the Canon STILL-IMAGE
(WIA/usbscan) class driver would. This is consistent with the established
diagnosis: the device needs the Canon still-image driver bound for `0x220034`
extended to return data, but the Canon INFs match normal-mode `PID_1865 MI_04/
MI_05`, not service-mode `PID_12FE`, so `12FE` stays on usbprint.

Surrounding `0x470807/0x470813/0x470853` calls all return `ret:1` (the usbprint
port/config queries succeed), so **discovery works on usbprint** — WICReset does
enumerate and talk to the printer; it only chokes on the extended 1284 read.
(Plain WinUSB, by contrast, made WICReset see *nothing* — printer-class
enumeration is required even to list the device. So Lane A must preserve
usbprint-style discovery while making `0x220034/5000` return the ID.)

---

## 4. Non-destructive confirmation (state before == after)

| signal | value |
|---|---|
| host device | `04a9:12fe` "Printer in service mode", Bus 001 Dev 046 (unchanged) |
| VM passthrough | `<hostdev>` `0x04a9:0x12fe` bus 1 dev 46 (still attached) |
| guest binding | `USB\VID_04A9&PID_12FE\01807C` → Status **OK**, Service **usbprint**, **CM_PROB_NONE** (unchanged) |
| WICReset state | "Canon Printer (Unrecognized)", "Device 1284 ID could not be read." — parked before the key prompt |
| key | `~/canon-tool-staging/.wic-key` **NOT** touched |
| reset | **none** — no reset click, no `0x85`/clear/write, no power-cycle |

`STA:10` in the device ID = device still in service mode after the run.

---

## 5. Reproduce

All steps from neo: author script → `scp …:/tmp` → one `ssh mbp-13 'bash -lc
"bash /tmp/x.sh"'`. WinRM from `~/git/canon-megatank-reset` on mbp-13 with
`PATH=~/canon-tool-staging/ansvenv/bin:$PATH ansible -i
host/vm-capture/ansible/inventory.yml canon-win11 -m ansible.windows.win_shell
-a "<ps>"` (ntlm). `win_copy` DEST uses **forward slashes** (`C:/canon/x`).

1. **Confirm binding:** `Get-PnpDevice -InstanceId "USB\VID_04A9&PID_12FE\01807C"`
   → Status OK / Service usbprint / CM_PROB_NONE.
2. **Launch under hook (no `-e`):** write a launcher that
   `Start-Process C:/canon/frida-inject-x86-16.exe -ArgumentList
   @('-f','C:\PROGRA~2\PRINTE~1\PRINTE~1.EXE','-s','C:\canon\frida-wicreset-hook.js','-R','v8')
   -RedirectStandardOutput C:/canon/frida-events.log -WindowStyle Hidden`, then
   run it via `schtasks /Create … /RU cap /RL HIGHEST /IT /F` + `/Run`
   (interactive session 1). **Do NOT add `-e`** — eternalize detaches the
   injector and the console.log pipe goes dead (log freezes at `HOOK_LOADED`).
   Verify `frida-inject-x86-16` AND `PRINTE~1` both alive in SessionId 1, and
   `frida-events.log` grows past the `HOOK_LOADED` line.
3. **Drive the failing read (no key):** over VNC (`vncdo -s 127.0.0.1:0`, wake
   with `move 640 400` first) the startup detect already fires it; optionally
   click "Search for available printers again" (~387,426) to re-issue it. The
   bottom of the window gains another red "Device 1284 ID could not be read."
4. **Capture:** filter `frida-events.log` for `0x220034`:
   - `outSize=4096 → ret=1 bytesReturned=120` (basic OK; `outHex` decodes to the
     `MFG:Canon;…PSE:KMDA10021;` ID).
   - `outSize=5000 → ret=0 bytesReturned=0` (extended FAIL — the baseline).
5. **STOP.** No key entry, no reset. Leave PP parked at "Unrecognized".

Frida hook: `host/vm-capture/win/frida-wicreset-hook.js` (logs
`DeviceIoControl` ioctl/inSize/outSize on enter, ret/bytesReturned/outHex on
leave). Guest launcher written this run: `C:/canon/lanec-frida-launch.ps1`;
fresh log: `C:/canon/frida-events.log` (prior frozen attempt archived as
`C:/canon/frida-events.empty-*.log`).

---

## 6. Hand-off to Lane A

The Lane A success criterion, measured against this control, is exactly:

> On the rebound (Canon still-image / usbscan) driver, the **`0x220034`
> `outSize=5000`** call must return **ret:1** with **bytesReturned≈120** and an
> `outHex` decoding to `MFG:Canon;…;STA:10;…;PSE:KMDA10021;` — while the
> `0x220034 outSize=4096` basic read and WICReset's printer enumeration
> (`0x47xxxx`) keep working so the tool still lists and selects the printer and
> advances **past** "Device 1284 ID could not be read" to the reset-key prompt.
