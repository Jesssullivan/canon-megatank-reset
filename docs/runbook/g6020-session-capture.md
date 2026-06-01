# G6020 encrypted series-name session capture (Lane A, NO KEY)

Date: 2026-06-01. Box: mbp-13, VM `canon-capture-win11-headless`
(qemu:///session). Printer `04a9:12fe` (service mode, Bus001 Dev046), on
`usbprint.sys` (CORRECT — not rebound, not WinUSB). Tool: Printer Potty
WICReset v5.95. Frida-inject v16.5.9 (`C:\canon\frida-inject-x86-16.exe`).

## Goal

Merge the 1284 clamp hook + the full DeviceIoControl trace hook into ONE hook,
drive WICReset to the encrypted printer-series-name read (the gate AFTER the
1284 clamp, BEFORE the key field), and capture the real enciphered
`0x220038`/`0x22003c`/`0x16000c` traffic on the wire. **No key spent, no reset
write, no rebind, no power-cycle.**

## What ran

- Combined hook: `host/vm-capture/win/frida-session-capture-hook.js` — keeps the
  `0x220034` `nOutBufferSize` 5000->4096 clamp AND logs every DeviceIoControl
  (full in-hex onEnter, full out-hex/bytesReturned/ret onLeave), with a raised
  1024 B cap for the vendor IOCTLs (`0x220030/34/38/3c`, `0x16000c`) so the
  small maintenance frames are never truncated. Plus CreateFile / WinUSB /
  connect tracing.
- Launched via `C:\canon\launch-session-capture.ps1`: kills stale procs, writes
  an anchor, builds `session-capture-wrap.cmd`
  (`frida-inject-x86-16.exe -f <8.3 tool path> -s <hook> -R v8 > log 2> err`),
  runs it under `schtasks /TN cmrsession /RU cap /IT` (interactive desktop so the
  GUI is on the VNC console). v16: do NOT use `-e` (freezes log) or `-o` (no
  output) — redirect stdout via the `.cmd`.
- Host capture: `dumpcap -i usbmon1 -w session-capture-20260601-122631-wire.pcapng`
  (Bus001 -> usbmon1; my user is in the `usbmon`+`wireshark` groups and dumpcap
  has `cap_net_raw`, so no sudo for dumpcap; `modprobe usbmon` needed sops sudo).
- VNC drive (the documented flow): launch -> the assistant already showed
  "Select Canon Printer (Unrecognized)" -> "This CANON printer is already in
  service mode" -> "Open the main interface" -> "Reset waste counter(s)" ->
  "Please read this first!" warning -> **Yes**. STOPPED at the failure — never
  reached / never entered the Reset-keys field.

## Result: the series-name read FAILS at the driver, NEVER reaches the wire

WICReset got PAST the 1284 gate (clamp works: `0x220034` 5000->4096 ->
`ret:1 bytesReturned:120`, the `MFG:Canon;...PSE:KMDA10021` ID, every cycle).
It then issued the encrypted series-name read and bailed with the documented
red errors, ending in **"This printer is either unsupported or not in service
mode."** — before any key field.

### The series-name read is a single `0x22003c`, NOT a set_session/get_keyword pair

The capture FALSIFIES the prior model that the series-name read is a
`0x220038` set_session followed by a `0x22003c` get_keyword. Across the entire
session:

- `0x220038` (VENDOR_SET_COMMAND / set_session) count = **0** — never issued.
- `0x16000c` count = **0** — never issued.
- WinUSB count = **0** — WICReset uses usbprint, as expected.
- `0x22003c` (VENDOR_GET_COMMAND) count = **16** (8 in/out pairs).

Every series-name read is the SAME single primed `0x22003c`:

```
in : ioctl 0x22003c VENDOR_GET_COMMAND inSize=3 outSize=5000 inHex= 8a 00 00
out: ioctl 0x22003c VENDOR_GET_COMMAND ret=0 bytesReturned=0 outHex=(empty)
```

i.e. prime/in-buffer = `8a 00 00` (cmd `0x8a`, arg `0x0000`), requested
`outSize = 5000`, and the call returns `ret=FALSE, bytesReturned=0`, empty out
buffer. No `0x220038` precedes it — there is no enciphered set_session frame on
the wire because **WICReset never sends one** in this state; the series-name
read is the first vendor command it attempts and it is rejected outright.

### Ordered IOCTL trace around the Reset->Yes click (hook ms)

```
t=193746 CLAMP            0x220034 5000->4096
t=193746 0x220034 in      outSize=4096 clamped
t=193748 0x220034 out     ret=1 bytesReturned=120  (1284 ID MFG:Canon...PSE:KMDA10021)
t=193750 0x22003c in      inSize=3 outSize=5000 inHex=8a0000        <- series-name read (prime)
t=193753 0x22003c out     ret=0 bytesReturned=0 outHex=             <- REJECTED, 0 bytes
t=193753 0x22003c in      inSize=3 outSize=5000 inHex=8a0000        <- retry
t=193753 0x22003c out     ret=0 bytesReturned=0 outHex=             <- REJECTED, 0 bytes
```

The startup auto-detect at t=3274/3338 is byte-identical (same `8a0000` ->
empty). The `0x470807/0x470813/0x470853` IOCTLs interleaved are SetupAPI
device-interface enumeration (DeviceType 0x47), not the maintenance lane.

### The wire confirms: the rejected `0x22003c` produced ZERO USB traffic

usbmon `usbmon1` pcap (16 frames, ALL control transfers on EP 0x80):

```
frame 1-6   t=0       device/config/string descriptors (enumeration)
frame 7-14  t=26.4s   five 120-byte control-IN completions = the 1284 GET_DEVICE_ID reads (startup)
frame 15-16 t=216.9s  one  120-byte control-IN completion  = the 1284 read on Reset->Yes
```

There is **no bulk-OUT carrying `8a0000` and no vendor control transfer** for
the series-name read anywhere on the wire. The `ret=0, bytesReturned=0`
`0x22003c` calls are rejected by `usbprint.sys` in the driver BEFORE any URB is
submitted — the device never sees the request.

## Why the series-name reply is empty

**A rejected-at-the-driver call, almost certainly the SAME page-size cap as the
1284 gate — but it manifests differently and is the next thing to test.**

- The `0x22003c` series-name read requests `outSize = 5000`, the exact same
  over-one-page (>4096) size that broke `0x220034` (which usbprint.sys on
  10.0.26100 caps at 4096). That is the strongest signal: WICReset's deep reads
  default to 5000.
- BUT the failure SHAPE differs from the 1284 case. `0x220034` at 5000 returned
  ERROR_CRC(23)/empty and, when clamped to 4096, returned `ret:1 / 120 B`.
  `0x22003c` at 5000 returns `ret:0, bytesReturned:0` AND emits no USB transfer
  at all — so for the GET_1284 IOCTL usbprint truncates-then-CRCs, while for the
  VENDOR_GET IOCTL it rejects the whole request up front.
- This is therefore best characterised as a **driver-rejected length / 0-byte
  completion**, with the leading hypothesis that it is ANOTHER buffer-size cap
  (the 5000 over-page request) that, like the 1284 one, may be fixable by
  clamping `0x22003c` `nOutBufferSize` to 4096. It is NOT (on this evidence) a
  device STALL — the device is never reached.

It is NOT a wrong-cipher / wrong-seed problem: there is no enciphered
set_session on the wire to be wrong, and the prime is the trivial `8a 00 00`.
The gate is upstream of the cipher.

### Next no-key step

Extend the clamp to `0x22003c` (5000->4096, same as `0x220034`) and re-drive
Reset->Yes. Two outcomes, both diagnostic and both no-key:

1. If the series-name read then returns data (`ret:1`, non-empty out buffer),
   the empty-reply was purely the page-size cap and WICReset will proceed to the
   key field — at which point the encrypted set_session/get_keyword session (if
   any) becomes capturable. (Add `0x22003c` to the clamp list in the combined
   hook; it already traces it.)
2. If `0x22003c` still returns `ret:0`/empty at 4096, the rejection is not the
   length and we characterise the IOCTL's failure further (e.g. the `8a0000`
   prime itself is rejected by this service-mode device / usbprint variant).

## Artifacts (mbp-13)

- pcap: `~/canon-tool-staging/captures/session-capture-20260601-122631-wire.pcapng`
- frida log: `~/canon-tool-staging/captures/session-capture-20260601-122631-frida.log`
  (full 502-line stream; guest copy `C:\canon\session-capture.log`)
- screenshots: `~/canon-tool-staging/captures/session-shots/`
  (`step0-launch`, `drive1-cmd-min`, `drive2-selected`, `drive3-main`,
  `drive4-resetbtn`, `drive5-afteryes` = the failure)
- combined hook: `host/vm-capture/win/frida-session-capture-hook.js`
  (guest `C:\canon\frida-session-capture-hook.js`)
- launcher: `C:\canon\launch-session-capture.ps1`

## Discipline confirmed

Key `~/canon-tool-staging/.wic-key` UNTOUCHED (16 B, mtime 09:28, unchanged).
No `0x220038` reset/set frame issued, no power-cycle, printer left on usbprint
(not rebound), STA:10 not reset.
