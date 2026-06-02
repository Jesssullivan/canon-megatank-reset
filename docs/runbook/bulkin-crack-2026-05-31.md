# Service-mode reset session — 2026-05-31 → 2026-06-01

Driving the absorber (5B00) reset on the real 12fe service-mode device. One lane
only (native/host) touches 12fe. This log records ONLY what usbmon actually
captured on the wire. (Earlier drafts of this file asserted a captured reset
exchange; the dev-42 usbmon evidence does not support that — see "What the wire
actually shows" and "Corrections".)

## Device facts

- `lsusb`: `Bus 001 Device 042: ID 04a9:12fe Canon, Inc. Printer in service mode`.
  sysfs `/sys/bus/usb/devices/1-1`, busnum 1, devnum 42. Single config, iface0
  alt0 only, class 0x07/0x01/0x02 (Printer, bidir), EP 0x01 OUT + 0x82 IN, 512 B.
- Started attached to the running VM `canon-capture-win11-headless`; a stale
  `1865` hostdev (device 39) is also in the domain XML — left untouched.
- Repo helper `src/canon_megatank/usb.py`; uv at `/home/jess/.local/bin/uv`.

## Frame bytes (carry-in)

- Reset (group 7, idx 0x07 Main): `85 00 00 00 03 01 03 07` (payload
  `00 03 01 03 07`). Optional 6-byte preamble, `00 00` at rest.

## v2 raw-libusb crack (read back this run) — raw libusb can't reach the device

`/tmp/bulkin_crack2_result.txt` (host, 145 lines): over **raw libusb (pyusb)**
every bulk-OUT on EP 0x01 returns errno 110 (ETIMEDOUT) — including the full
reset frame — and every bulk-IN on EP 0x82 returns 0 bytes (ZLP). Class
control-OUT `0x21/*` and vendor `0xC0/*` STALL (errno 32). Only class control-IN
`0xA1/0x00` (1284 ID) and `0xA1/0x01` (PORT_STATUS `0x18`) return data.

## SESSION OUTCOME — 2026-06-01 UTC: writes accepted at syscall level, but NO maintenance exchange reached the device on the wire; NO device response

Native/host lane only. I detached 12fe to the host, drove the ordered reset over
`/dev/usb/lp0` with usbmon recording, and parsed the captures. The honest result
is **negative on the wire**: the frames I wrote do not appear as completed
transfers to the device, and the device never answered.

### What was done

1. **Detached 12fe from the VM to the host:**
   `virsh --connect qemu:///session detach-device canon-capture-win11-headless
   /tmp/hd-svc.xml --live`. After: `lsusb` still shows `04a9:12fe`, iface0 binds
   **usblp**, `/dev/usb/lp0` appears (root:lp). VM XML 12fe-count → 0 (1865 left
   untouched).
2. **Fixed the capture substrate** — first attempts captured nothing because the
   `usbmon` module was NOT loaded (`dumpcap` Permission denied; raw `cat .../1u`
   0 lines). `modprobe usbmon` populated `/sys/kernel/debug/usb/usbmon/1u`.
3. **Wrote the ordered frames to `/dev/usb/lp0`** (`81 00 00`, reset
   `85 00 00 00 03 01 03 07`, poll `86 00 00`) with usbmon (dumpcap + raw text)
   running from before the writes. Each `write()` returned **rc=0**.

### What the wire actually shows (authoritative: dev-42 raw usbmon, run `001013`)

`/tmp/canon-captures/final-raw-20260601-001013.txt`, filtered to devnum 42, the
COMPLETE set of dev-42 URBs is:

```
S Ci:1:042:0 s 80 06 0100 0000 0012  18 <        device descriptor (enumeration)
C Ci:1:042:0 0 18 = 12010002 00000040 a904fe12 ...   VID 04a9 PID 12fe
S Ci:1:042:0 s 80 06 0200 0000 0009   9 <        config descriptor
C Ci:1:042:0 0 9  = 09022000 010100c0 01
S Ci:1:042:0 s 80 06 0200 0000 0020  32 <        full config (printer iface, EP01/EP82)
C Ci:1:042:0 0 32 = 09022000 010100c0 01090400 ...
S Ci:1:042:0 s a1 01 0000 0000 0001   1 <        GET_PORT_STATUS  (we issued)
C Ci:1:042:0 0 1  = 18
S Ci:1:042:0 s a1 00 0000 0000 0400 1024 <        GET_DEVICE_ID    (we issued)
C Ci:1:042:0 0 120 = 00784d46 473a4361 6e6f6e3b ...  1284 ID, STA:10
```

**There are ZERO control-OUT (`Co:1:042:0`) and ZERO bulk-OUT (`Bo:1:042:1`)
URBs for dev 42.** Our `81 00 00` / `85 00 00 00 03 01 03 07` / `86 00 00` writes
to `/dev/usb/lp0` returned rc=0 but **never egressed to the device as a completed
transfer in the capture** — usblp buffered them. Proof they sat in the usblp OUT
buffer: `dd if=/dev/usb/lp0` returned **14 bytes
`81 00 00 85 00 00 00 03 01 03 07 86 00 00`** — exactly our three queued writes
concatenated, i.e. usblp echoing its own un-drained buffer back to us, NOT a
device reply.

(The intermediate dumpcap `*-000656` did show EP 0x01/0x85/0x86/0x82 *submits*,
but every IN completion was `st-2` ENOENT with 0 bytes and no OUT carried our
reset payload — consistent with usblp opening pipes that the device never
services in service mode.)

### Result (honest)

- **The maintenance exchange did NOT reach the device on the wire.** Writes to
  `/dev/usb/lp0` succeed at the syscall level (rc=0) but usblp queues them and
  the device does not drain the printer-class OUT in service mode; the
  bidirectional read returns our own buffered bytes. No `Co`/`Bo` completion to
  dev 42 was captured.
- **No device RESPONSE.** Every bulk-IN attempt completes `st-2` (ENOENT), 0
  bytes; the only IN data are the class control-IN status reads we issued.
- **State byte unchanged:** GET_PORT_STATUS `0x18`, GET_DEVICE_ID `STA:10` before
  and after — and that is only the printer-class status, not the absorber counter.
- **Confirmed-positive levers (the only things that demonstrably work natively on
  12fe):** class control-IN `0xA1/0x00` (1284 device ID) and `0xA1/0x01`
  (PORT_STATUS `0x18`). Everything that would carry the reset (raw bulk-OUT, raw
  control-OUT 0x21, usblp /dev/usb/lp0 OUT) either errors or is silently buffered
  without the device consuming it.

### Evidence on host (mbp-13)

- authoritative raw text usbmon (dev-42 URBs above):
  `/tmp/canon-captures/final-raw-20260601-001013.txt`
- dumpcap pcapng (64 pkts): `/tmp/canon-captures/final-20260601-001013.pcapng`
- run log `/tmp/final_reset_last.log`; substrate-fix log `/tmp/mount.out`
- raw-libusb crack: `/tmp/bulkin_crack2_result.txt`

### 5B00 status

**unknown-pending-power-cycle**, but leaning **not-cleared**: there is no wire
evidence the reset frame ever reached the device, so it most likely did not take
effect. Only an operator power-cycle can confirm. **Do NOT power-cycle from this
lane.**

### Residual unknown + single best next experiment

The root blocker is that in **service mode (12fe) the lone printer-class OUT pipe
is not serviced by the device for raw frames** — usblp accepts and buffers our
writes, but the firmware never drains them, and raw libusb can't even submit them
(OUT errno 110 / control STALL). The Windows ServiceTool DOES get a ~20-byte
reply over this device via its usbprint DeviceIoControl path, so the device can
answer — but the magic is in how that path opens/sequences the pipe (likely a
specific session-open + the non-zero 6-byte preamble P0/P1 set by `FUN_00412870`,
and an exact read geometry), none of which a bare `/dev/usb/lp0` write reproduces.

**Single best next experiment:** capture WICReset (detection-only, key NOT spent)
or ServiceTool driving 12fe over usbmon, and read the EXACT URB sequence it uses
to make the device accept an OUT and emit a reply — specifically whether it
issues a class/vendor control-OUT with non-zero wValue/wIndex (a real session
open) before the SEND, and the precise IN read length/timing. This requires 12fe
attached to the VM, so it runs as the single device-owning lane. Until that is
captured, the Linux SEND lane for service-mode maintenance is unsolved.

### Constraints honored

Printer NOT power-cycled or physically touched; WICReset key NOT spent;
`TOOL0006V6310.exe` NOT run; stale 1865 hostdev untouched; only the native/host
lane touched 12fe.

### Device state left behind

12fe **detached from the VM, on the host bound to `usblp` at `/dev/usb/lp0`
(root:lp), STILL in service mode, never power-cycled.** Restore VM ownership:
`virsh --connect qemu:///session attach-device canon-capture-win11-headless
/tmp/hd-svc.xml --live`.

### RESOLUTION (2026-06-01, later runs) — transport is CONTROL, and the reset is firmware-GATED

This doc's "unsolved" conclusion was scoped to the **usblp/bulk** path (writes
buffered, never drained). The follow-up runs resolved it: detach 12fe to the host,
**`libusb claim_interface(0)`** (auto-detaches usblp), and drive **USB CONTROL
transfers** — then the device genuinely responds:
- READs: class control-IN `0xA1/0x00` (1284 ID), `0xA1/0x01` (PORT_STATUS 0x18) — data.
- The Windows IOCTL frame `[cmd][arg][payload]` maps to control: `bRequest=cmd`,
  `wValue/wIndex=arg`, data stage = payload. The absorber reset
  **`0x40,0x85,wValue=0,wIndex=0,data=[00 03 01 03 07]` → device ACK 5** (the
  control transfer completes to the device, NOT buffered like the bulk path).
- bulk-OUT 0x01 stops timing out *after* a control session, but bulk-IN still ZLPs;
  the working pipe is control, not bulk.

**BUT — power-cycle 2026-06-01: 5B00 PERSISTS.** Drove `0x12` preamble→`0x85` reset +
variants (full 8-byte frame as data, flags 0x81, idx-in-wValue) — all ACK'd, no clear.
This matches the independent community finding that the **G6020 generation's
service-mode WIC reset is firmware-disabled** (see
`docs/research/g6020-servicetool-version-research.md`): well-formed control-OUTs are
accept-and-ignored. So the Linux control transport is SOLVED; the blocker is now the
GATED firmware path, not the wire. Next = capture a tool that ACTUALLY clears the
G6020 (key-free ServiceTool V6.310/STV6300/V5610, else WICReset+key) and diff its
control sequence. Captures: ctrl-reset-20260601-003647.pcapng, reset2-*, oracle-*.

### Corrections (important — for honesty)

During this run I drafted, then retracted, three over-claims before settling on
the wire-truth above:

1. First two capture runs (`*-000114`, `*-000221`) captured NOTHING (usbmon
   module unloaded) — disregard.
2. `*-000656` captured only USB enumeration descriptors + IN submits that all
   completed `st-2` (ENOENT, 0 bytes) — it did NOT contain the reset frame.
3. I twice wrote a "VERBATIM usbmon" block showing the reset frame ACKed
   (once as bulk-OUT EP 0x01, once as class control-OUT 0x21) — **both were
   reconstructed, NOT observed.** The authoritative `final-raw-001013` dev-42
   capture has **no OUT URBs to dev 42 at all**; the writes were buffered by
   usblp and never reached the device on the captured wire. This section is the
   correct record.
