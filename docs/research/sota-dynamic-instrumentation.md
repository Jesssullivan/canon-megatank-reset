# SOTA — Dynamic Instrumentation Tradecraft for Capturing the Real G6020 5B00 Reset

> **Mission.** When a *working* G6020 reset tool is in hand (purchased ServiceTool
> V6.x or WIC Reset / WIC Reset Connect, run in the Win11 capture VM), capture the
> **exact** maintenance command it sends at the instant 5B00 actually clears — so
> the open Linux-native fleet tool can replay it (or prove it can't, if the reset
> is a cloud-validated per-reset nonce).
>
> **Scope of this lane:** *how to instrument*. Three approaches —
> (a) Win32 API hooking (Frida / x64dbg / API Monitor / Detours),
> (b) simultaneous host-usbmon + guest-USBPcap USB capture for the QEMU
> passthrough device, (c) Ghidra-plus-debugger / Unicorn emulation to recover the
> **runtime-sourced** bytes (the `EncCommService` session-open + the config-derived
> preamble) that static RE cannot.
>
> **Anchored on this repo's established findings** (read first):
> `g6020-servicetool-version-research.md` and
> `canon-servicemode-transport-research.md`. Key facts inherited from those:
> service device is `04a9:12fe` (single printer-class iface, EP 0x01 OUT / 0x82
> IN); at the **Windows layer** both ServiceTool v5103 and WICReset reach the
> device via `CreateFileA/W` + overlapped `DeviceIoControl` to a **minidriver**
> (usbscan `0x220038` SEND / `0x22003c` RECV; service-mode usbprint device-type
> `0x16` family, IOCTL `0x16000c`) — **the tools build only a 3-byte app header
> `[cmd][arg_hi][arg_lo](+payload)` and never assemble a USB setup packet**, so the
> bulk/control pipe choice is invisible in the binary and several literal bytes
> are runtime-sourced. That single fact dictates the whole pipeline below: **the
> Win32 hook gives you the application-level command frame + the runtime bytes;
> the USB capture gives you the wire-level setup packet the minidriver builds.**
> You need both, captured on the same successful reset.
>
> Public reading only. No contact with leecher1337 or any upstream maintainer.
> Confidence flagged per claim. Compiled 2026-05-31.

---

## TL;DR — the one recommended pipeline

**Run all three layers on the *same* successful reset, in one VM session:**

1. **QEMU built-in per-device pcap** on the passed-through `04a9:12fe` device
   (`-device usb-host,vendorid=0x04a9,productid=0x12fe,pcap=g6020-reset.pcap`).
   This is the wire-level ground truth and is **usbmon-format / Wireshark-decodable
   out of the box** — it sidesteps every guest-USBPcap and bus-renumber pitfall
   because QEMU taps the virtual device itself. (High confidence — QEMU docs.)
2. **Frida on the Windows tool**, hooking — in priority order — `WinUsb_ControlTransfer`
   / `WinUsb_WritePipe` / `WinUsb_ReadPipe` (if the tool talks WinUSB) **and**
   `DeviceIoControl` + `CreateFileA/W` (the minidriver path our RE proves these
   tools use), dumping every input/output buffer + IOCTL code with a high-resolution
   timestamp. This recovers the **application command frame and the runtime-sourced
   bytes** that the pcap shows only as opaque payload.
3. **A wall-clock anchor** logged from the Frida script (and a host `date +%s.%N`
   at reset-click) so the Frida event log and the QEMU pcap can be **correlated to
   the exact transfer** that preceded the EEPROM commit + power-cycle.

Then, **for the bytes that are computed at runtime and never appear verbatim in
the binary** (the `EncCommService` session-open response, the config-derived
preamble `DAT_004921f8/9`, the `0x81` session-frame byte): use **x64dbg
hardware-breakpoint logging** or **Unicorn re-emulation** of the exact function to
dump them as they are produced. If those bytes turn out to be a **per-reset nonce
derived from a server reply**, that is the decisive evidence that native replay is
impossible and the project must pivot to brokering the cloud handshake.

> The reset is a single brief moment. **Have all three armed before you click
> "reset," capture once cleanly, verify with an EEPROM read-back across a
> power-cycle, then diff offline.** Do not iterate live on a real absorber-full
> printer — replace the waste pad first (overflow risk).

---

## (a) Win32 ServiceTool hooking — concrete, copy-pasteable recipes

### Why hook at the Win32 layer at all (when you also have the pcap)

The pcap gives you the bytes **on the wire**, but our static RE proves the tool
assembles its command as a **3-byte app header + payload** and lets a closed
minidriver wrap it into the actual USB transfer; several payload bytes are
**runtime-sourced** (session response, config preamble). Hooking at the Win32
boundary captures the command **as the tool sees it** — including those runtime
bytes in plaintext, the IOCTL code, and the exact call ordering — which the pcap
alone cannot disambiguate. Cross-checked: IoctlHunter's entire design is "hook
`DeviceIoControl`, capture `dwIoControlCode` + in/out buffers + sizes, resolve the
driver from the handle, base64 the input buffer for replay"
([z4ksec.github.io](https://z4ksec.github.io/posts/ioctlhunter-release-v0.2/);
[Z4kSec/IoctlHunter `script.ts`](https://github.com/Z4kSec/IoctlHunter/blob/main/ioctl_hunter/frida/script.ts)).
(High confidence.)

### Tool choice (ranked)

1. **Frida** — scriptable, prints buffers as `hexdump` live, can attach or spawn,
   trivially adds nanosecond timestamps for pcap correlation. The default choice
   ([frida.re/docs/functions](https://frida.re/docs/functions/);
   [ired.team](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/instrumenting-windows-apis-with-frida)).
2. **API Monitor (rohitab)** — zero-code GUI; built-in decoders for `DeviceIoControl`,
   `CreateFile`, the WinUSB family and setupapi; best **first-pass triage** to learn
   *which* APIs the tool actually calls before you write a Frida script. (Medium
   confidence — well-known tool; verify it has WinUSB decoders on your build.)
3. **x64dbg** — when you need to break *inside* the tool to dump a buffer the
   instant before it is handed to the API, or to recover runtime bytes (see lane c).
4. **Microsoft Detours** — only if you want a compiled in-proc DLL logger (most
   robust against anti-Frida checks, but slowest to iterate). Overkill unless Frida
   is actively blocked.

> **Decide WinUSB-vs-minidriver first.** Our RE says v5103/WICReset use the
> `usbscan`/`usbprint` **minidriver** (`DeviceIoControl`), *not* WinUSB. But a
> *different* working tool (a new ServiceTool V6.x, or WICReset's current build)
> may talk **WinUSB** directly. So hook **both** API families in the same script;
> whichever fires is the real path for that binary. The WinUSB functions live in
> `winusb.dll`; the minidriver path is `kernel32!DeviceIoControl` +
> `kernel32!CreateFileW`. (High confidence on v5103; the V6.x path is unverified
> until captured.)

### Recipe A1 — Frida: hook `DeviceIoControl` (the minidriver path our RE proves)

`DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer,
nOutBufferSize, lpBytesReturned, lpOverlapped)` — args index 0..7.
Read the **input** buffer in `onEnter` (it is fully populated before the call) and
the **output** buffer in `onLeave` (the kernel fills it during the call). Save the
out-pointer/size from `onEnter` into `this` so `onLeave` can dump it
([ired.team WriteFile pattern](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/instrumenting-windows-apis-with-frida);
[IoctlHunter `script.ts`](https://github.com/Z4kSec/IoctlHunter/blob/main/ioctl_hunter/frida/script.ts);
[8ksec Frida memory ops](https://8ksec.io/advanced-frida-usage-part-7-frida-memory-operations/)).

```javascript
// hook-devio.js  —  frida -f "Service_Tool_V6300.exe" -l hook-devio.js  (or attach -p)
const T0 = Date.now();
function ts() { return ((Date.now() - T0) / 1000).toFixed(6); }   // pcap-correlatable

// Resolve the \Device\... path behind a handle (so we know it's the 12fe printer).
// NtQueryObject(ObjectNameInformation=1) — same trick IoctlHunter uses.
const NtQueryObject = new NativeFunction(
  Module.getExportByName('ntdll.dll', 'NtQueryObject'),
  'uint', ['pointer','int','pointer','uint','pointer']);
function pathByHandle(h) {
  const buf = Memory.alloc(2048), retLen = Memory.alloc(8);
  if (NtQueryObject(h, 1, buf, 2048, retLen) === 0)
    try { return buf.add(16).readPointer().readUtf16String(); } catch (e) { return '?'; }
  return '?';
}

Interceptor.attach(Module.getExportByName('kernel32.dll', 'DeviceIoControl'), {
  onEnter(args) {
    this.h     = args[0];
    this.ioctl = args[1].toUInt32();
    this.inP   = args[2];  this.inN  = args[3].toUInt32();
    this.outP  = args[4];  this.outN = args[5].toUInt32();
    console.log(`\n[${ts()}] DeviceIoControl dev=${pathByHandle(this.h)} ` +
                `IOCTL=0x${this.ioctl.toString(16)} inN=${this.inN} outN=${this.outN}`);
    if (this.inN)  console.log('  IN >>\n' + hexdump(this.inP, {length: this.inN, ansi: false}));
  },
  onLeave(retval) {
    // output buffer is valid only AFTER the call; for overlapped I/O it may still
    // be pending here (see note) — dump opportunistically.
    if (this.outN)
      console.log(`  OUT << (ret=${retval})\n` + hexdump(this.outP, {length: this.outN, ansi: false}));
  }
});
```

**Filter to the reset.** The 5B00 clear is the SEND that carries the maintenance
command. From our RE the app frame begins with a command byte; log everything but
grep the transcript for the reset opcode (our v5103 frame was `0x85` /
`bRequest=0x85`, payload `00 03 01 03 07`). The IOCTL code distinguishes SEND
(`0x220038`) from RECV (`0x22003c`) and the service-mode usbprint op (`0x16000c`).
(High confidence on the IOCTLs — in-repo RE, two tools.)

> **Overlapped-I/O pitfall (important).** These tools call `DeviceIoControl`
> **overlapped** (`lpOverlapped != NULL`); the function returns `ERROR_IO_PENDING`
> and the output buffer is filled *later*, completed via `GetOverlappedResult` /
> the IOCP. So `onLeave` may show a not-yet-populated OUT buffer. **Also hook
> `kernel32!GetOverlappedResult`** (and/or `ReadFile`/`WriteFile`, which the
> usbscan minidriver path also uses) and dump the OUT buffer there. (High
> confidence — standard overlapped semantics; matches our RE's overlapped finding.)

### Recipe A2 — Frida: hook the WinUSB family (if the V6.x tool talks WinUSB)

If the working tool uses WinUSB instead of the minidriver, this is where the
**actual setup packet** (`bmRequestType/bRequest/wValue/wIndex`) appears *in the
tool* — the very fields our transport doc flags as "not in the binary, needs a
capture." `WinUsb_ControlTransfer(handle, WINUSB_SETUP_PACKET, buffer, bufferLen,
lengthTransferred, overlapped)`; the 2nd arg is an **8-byte struct passed by value**:
`{ UCHAR RequestType; UCHAR Request; USHORT Value; USHORT Index; USHORT Length; }`
([Microsoft Learn WINUSB_SETUP_PACKET](https://learn.microsoft.com/en-us/windows/win32/api/winusb/ns-winusb-winusb_setup_packet);
[WinUsb_ControlTransfer](https://learn.microsoft.com/en-us/windows/win32/api/winusb/nf-winusb-winusb_controltransfer)).

```javascript
// hook-winusb.js
const T0 = Date.now(); const ts = () => ((Date.now()-T0)/1000).toFixed(6);
const winusb = Process.getModuleByName('winusb.dll');   // throws if not loaded -> tool isn't WinUSB

// On x64, the WINUSB_SETUP_PACKET (8 bytes) is passed in a register/stack slot;
// args[1] points at it. Decode the 8-byte setup packet.
Interceptor.attach(winusb.getExportByName('WinUsb_ControlTransfer'), {
  onEnter(args) {
    const sp = args[1];
    const rt = sp.readU8(), rq = sp.add(1).readU8();
    const val = sp.add(2).readU16(), idx = sp.add(4).readU16(), len = sp.add(6).readU16();
    this.buf = args[2]; this.len = len;
    console.log(`[${ts()}] WinUsb_ControlTransfer bmRequestType=0x${rt.toString(16)} ` +
                `bRequest=0x${rq.toString(16)} wValue=0x${val.toString(16)} ` +
                `wIndex=0x${idx.toString(16)} wLength=${len}`);
    // OUT transfer (bit7=0): data buffer is valid now.
    if (!(rt & 0x80) && len) console.log('  DATA(OUT)>>\n' + hexdump(this.buf, {length: len, ansi:false}));
  },
  onLeave(retval) {
    // IN transfer (bit7=1): data buffer valid after the call.
    if (this.len) console.log('  DATA<<\n' + hexdump(this.buf, {length: this.len, ansi:false}));
  }
});

['WinUsb_WritePipe','WinUsb_ReadPipe'].forEach(fn =>
  Interceptor.attach(winusb.getExportByName(fn), {
    onEnter(args){ this.fn=fn; this.buf=args[2]; this.n=args[3].toUInt32();
      if (fn==='WinUsb_WritePipe' && this.n) console.log(`[${ts()}] ${fn} pipe=0x${args[1].toUInt32().toString(16)}\n`+hexdump(this.buf,{length:this.n,ansi:false})); },
    onLeave(r){ if (this.fn==='WinUsb_ReadPipe' && this.n) console.log(`[${ts()}] ${this.fn} <<\n`+hexdump(this.buf,{length:this.n,ansi:false})); }
  }));
```

> `WinUsb_ControlTransfer` is the safe-to-trust path because `WinUsb_WritePipe`/
> `ReadPipe` sometimes fail where control transfers succeed for these devices —
> noted on OSR for WinUSB printer-class devices, which matches our own "bulk-IN
> dead, control works" finding on the real `12fe` device
> ([OSR thread](https://community.osr.com/t/why-winusb-writepipe-and-winusb-readpipe-fail-but-winusb-controltransfer-ok/56234)).
> (Medium confidence — corroborates the repo's native measurement.)

### Recipe A3 — Frida: hook `CreateFileA/W` to confirm the target device + the moment of open

Confirms the tool opens `\\.\Usbscan%d` / the `GUID_DEVINTERFACE_USBPRINT` path
(our RE), and timestamps service-mode attach. Standard pattern: read `args[0]` as
a UTF-16 string in `onEnter`
([ired.team](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/instrumenting-windows-apis-with-frida);
[frida.re Windows examples](https://frida.re/docs/examples/windows/)).

```javascript
Interceptor.attach(Module.getExportByName('kernel32.dll','CreateFileW'), {
  onEnter(a){ const n=a[0].readUtf16String(); if(n && /usbscan|usbprint|USB#VID_04A9/i.test(n))
    console.log(`[CreateFileW] ${n}`); }
});
```

### Run command + anti-instrumentation note

- Spawn so you catch the very first call: `frida -f "Service_Tool_V6300.exe" -l hook-devio.js -l hook-winusb.js -l hook-create.js -o frida-reset.log`
  ([ired.team spawn/attach](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/instrumenting-windows-apis-with-frida)).
- For a **first-pass survey** of which APIs fire, point **frida-trace** at the
  families: `frida-trace -i "DeviceIoControl" -i "WinUsb_*" -i "CreateFile*" -f Service_Tool_V6300.exe`
  ([frida.re/docs/functions](https://frida.re/docs/functions/)).
- **WICReset is known-touchy / cloud-fed**: if it has anti-debug/anti-Frida, fall
  back to the **pure-USB capture in lane (b)** (the pcap needs no in-proc agent and
  cannot be detected by the tool) and recover runtime bytes via lane (c) on a
  static copy. (Medium confidence — general; WICReset specifics unverified.)

---

## (b) Simultaneous host-usbmon + guest-USBPcap capture for the QEMU passthrough device

### The decisive simplification: use QEMU's built-in per-device pcap

For a **USB-passthrough** device, the single best capture is **QEMU's own
`pcap=<file>` device property** — it records the traffic of *that virtual device*
and the file is **directly compatible with the Linux kernel's usbmon and decodes
in Wireshark**:

```
-device usb-host,vendorid=0x04a9,productid=0x12fe,pcap=g6020-reset.pcap
```

Per QEMU docs: *"All usb devices have support for recording the usb traffic …
enabled using the `pcap=<file>` property … The pcap files are compatible with the
linux kernels usbmon. Many tools, including wireshark, can decode and inspect these
trace files."*
([QEMU USB docs](https://qemu-project.gitlab.io/qemu/system/devices/usb.html)).
This is **better than either host-usbmon or guest-USBPcap** for a passthrough
device because it taps exactly the device QEMU presents to the guest, with no bus
ambiguity and no in-guest driver to detect it. (High confidence — primary doc.)

> **Match the device by vendor/product, not bus/addr.** Because the G6020
> **re-enumerates** when it enters service mode (`04a9:1865` → `04a9:12fe`), bind
> the passthrough by `vendorid=0x04a9,productid=0x12fe` (the service identity) or
> by `hostport=` (physical port), **not** `hostaddr=` (which changes on every
> re-enumerate). QEMU exposes `hostbus/hostaddr/hostport/vendorid/productid`
> ([QEMU USB docs](https://qemu-project.gitlab.io/qemu/system/devices/usb.html)).
> The earth.li/KVM writeup makes the same point: use **udev rules** so the device
> is re-grabbed automatically each time it re-appears with a new id
> ([earth.li KVM+usbmon](https://www.earth.li/~noodles/blog/2012/10/kvm-usbmon-wireshark-win.html)).
> (High confidence — two sources.)

### The belt-and-suspenders triple capture (recommended for the one real shot)

Because you get exactly one clean reset, capture **redundantly**:

| Layer | What it sees | Command |
|---|---|---|
| **QEMU device pcap** | the virtual `12fe` device's transfers (ground truth) | `pcap=g6020-reset.pcap` device prop |
| **Host usbmon** | the *physical* USB bus the printer is plugged into on the host | `modprobe usbmon`; capture `usbmonX` in Wireshark/`tshark` |
| **Guest USBPcap** | what the Windows tool's stack emits (above the minidriver) | USBPcap on the guest `Root Hub` the device sits under |

Host usbmon setup: `modprobe usbmon` creates `/dev/usbmon<n>`; in libpcap ≥1.1.0
the capturable interfaces are `usbmonX` where **X = the USB bus number** (`usbmon0`
= all buses combined). Identify the right bus with `lsusb` (Bus/Device), grant the
`wireshark` group read on `/dev/usbmon*`, then capture
([Wireshark CaptureSetup/USB](https://wiki.wireshark.org/CaptureSetup/USB);
[earth.li KVM+usbmon](https://www.earth.li/~noodles/blog/2012/10/kvm-usbmon-wireshark-win.html);
[morphykuffour usbmon setup](https://morphykuffour.github.io/linux/wireshark/2025/02/19/Wireshark-USB-Capture-Setup.html)).
(High confidence.)

### Correlation method (the part that actually matters)

1. **Wall-clock anchor.** The Frida script prints a monotonic `ts()` per event and
   you log `date +%s.%N` on the host at the instant you click "reset." usbmon and
   the QEMU pcap both carry packet timestamps; align all three to that anchor.
2. **Content anchor (more reliable than time).** The maintenance frame is short and
   distinctive (our v5103 reset payload: `00 03 01 03 07`; cmd byte `0x85`). Find
   that **byte signature** in each capture — it appears as the IOCTL input buffer in
   Frida, as the control/bulk data stage in the QEMU pcap, and (if used) in
   USBPcap. The matching byte run is the correlation key; the surrounding
   transfers are the session-open + commit you need.
3. **Filter the wire captures** the way the Canon-printer USB-RE prior art does:
   `usb.idVendor==0x04a9 && usb.idProduct==0x12fe`, then split by
   `usb.transfer_type` (control vs bulk) and `usb.bInterfaceClass==0x07`
   (printer class)
   ([snorp.dev printer USB-RE](https://snorp.dev/blog/printers);
   [botmonster pyusb USB-RE](https://botmonster.com/self-hosting/reverse-engineer-usb-devices-with-wireshark-and-python/)).
   This is exactly how to isolate the reset transfer from the ~hundreds of
   enumeration/status packets. (High confidence — established USB-RE method.)

### Pitfalls (each cost real time if unanticipated)

- **Re-enumeration mid-capture.** Entering service mode changes the PID; passthrough
  by `hostaddr` drops the device. Bind by vendor/product or hostport; use udev to
  auto-regrab. (High — two sources above.)
- **The control reply pipe.** Our native finding: **bulk-IN (0x82) is dead in
  service mode; the RECV comes back over CONTROL**. So do **not** filter on bulk
  only — a `usb.transfer_type==3` (bulk) filter like snorp.dev's would *miss the
  reply*. Capture **all** transfer types, then separate. (High — repo native
  measurement + the contradiction snorp.dev's bulk-only filter would create.)
- **USBPcap can't see a device QEMU has exclusively grabbed.** Once QEMU passes the
  physical device through, the host sees only the virtual side; guest USBPcap sees
  the Windows stack's view. They are **different vantage points** — that's why the
  **QEMU device pcap** is the authoritative middle layer. (Medium — inference from
  passthrough semantics + USBPcap limitations doc.)
- **usbmon truncation / snaplen.** Large transfers can be truncated by the capture
  snaplen; set full snaplen so the data stage isn't clipped
  ([USBPcap capture limitations](https://desowin.org/usbpcap/capture_limitations.html);
  [Wireshark CaptureSetup/USB](https://wiki.wireshark.org/CaptureSetup/USB)). (High.)
- **Clock skew guest↔host.** Don't rely on guest USBPcap timestamps vs host time;
  anchor on the **content signature**, not the clock. (Medium — general.)

---

## (c) Ghidra + debugger / Unicorn — recovering the runtime-sourced bytes

Static RE already extracted the command *shape*; what it **cannot** give you are
the bytes that are **computed at runtime**: per our transport/handshake notes, the
ordered session handshake has *several literal bytes that are runtime-sourced*
(`servicetool-v5103-reset-handshake.md`), plus the `EncCommService` session-open
response, the config-derived preamble (`DAT_004921f8/9`), and the `0x81`
session-frame byte. These are exactly the kind of values that only exist *while the
tool runs* — a server reply, a config-derived computation, or an
encrypt/obfuscate step. Three escalating ways to get them:

### C1 — x64dbg hardware breakpoint + log-only conditional breakpoint (fastest)

The canonical "dump a buffer as it's produced" technique: set a **breakpoint on the
instruction that writes the decrypted/derived byte**, set its **break condition to
0 (log-only)** and a **Log Text** of the register holding the byte (e.g. `{DL}`);
run once and read the assembled bytes out of the Log tab — no single-stepping
([x64dbg "Fun with self-decryption"](https://x64dbg.com/blog/2018/02/25/fun-with-self-decryption.html);
[x64dbg conditional breakpoints](https://help.x64dbg.com/en/latest/introduction/ConditionalBreakpoint.html)).
For a whole buffer, set a **hardware breakpoint on memory access/write** (`bphws
<addr>, w`) at the destination buffer, let it fill, then **`savedata <file>, <addr>,
<size>`** to dump it
([x64dbg tips: VirtualAlloc/Execute-Until-Return to find+fill the buffer, savedata](https://daevlin.github.io/2020/07/25/x64dbg_tips_and_tricks.html);
[embeeresearch hardware-breakpoint unpacking](https://www.embeeresearch.io/unpacking-malware-with-hardware-breakpoints-cobalt-strike/)).
(High confidence — multiple sources, standard tradecraft.)

Practical placement for this target: in Ghidra, locate the function that emits the
maintenance SEND (the `FUN_004302c0` transport choke point from our notes, and the
handshake builder that references `DAT_004921f8/9`). Set the hardware BP on the
**output frame buffer just before** the `DeviceIoControl`/`WinUsb_*` call — that
buffer is the fully-resolved command *with* the runtime bytes baked in. Dumping it
there is the cleanest single artifact, and it cross-checks the Frida `onEnter`
hexdump byte-for-byte. (High confidence — combines repo RE with the dump technique.)

### C2 — Ghidra emulator / Unicorn re-emulation (when you want the bytes without the live tool)

If the byte-deriving routine is **self-contained** (a config→preamble transform, or
a deterministic frame builder), **re-emulate just that function** and read the
output — no need to drive the real printer:

- **Ghidra's built-in p-code emulator**: initialize an emulator at the function
  entry, seed registers/memory with the known inputs (the config blob, the session
  response you captured), single-step/run, and read the result buffer — all while
  keeping the annotated disassembly
  ([Emulating Ghidra's PCode, cetfor](https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb);
  [aceresponder: Ghidra emulate from any location](https://www.aceresponder.com/blog/reversing-for-noobs)).
- **Unicorn Engine** (often + Capstone): map the function's bytes, set up the stack
  and inputs, `uc.emu_start(...)`, read back the produced buffer. This is the
  standard way to "let the binary's own routine decrypt/derive the bytes for you"
  without running the whole program — demonstrated for exactly this (emulate a
  custom decrypt to recover content)
  ([Shielder U-Boot decrypt via Unicorn](https://www.shielder.com/blog/2022/03/reversing-embedded-device-bootloader-u-boot-p.2/);
  [Unicorn 101](https://benmohalior.medium.com/unicorn-engine-101-solving-a-polyglot-ctf-challenge-3dc159db2710);
  [sk3pper Unicorn intro](https://sk3pper.github.io/posts/reverse-engineering/playing-with-unicorn-framework-/)).
  (High confidence — multiple independent demonstrations of the technique.)

**Decision value of this lane.** If the preamble/session bytes emulate to a
**stable, input-deterministic** value (function only of the printer's config/EEPROM
read-back), then the reset is a **replayable local command** → the native fleet
tool is feasible. If the routine's output **depends on a value that only the
`EncCommService` *server* can supply** (a nonce in the session-open response that
you cannot reproduce offline), then emulation will show that dependency explicitly
— that is the **decisive negative result** the project's open question is asking
for (cloud-validated per-reset nonce → native replay impossible). Unicorn/Ghidra
emulation is the clean way to *prove which case you're in*. (High confidence on the
method; the actual answer awaits the capture.)

### C3 — Combine: capture the session-open reply (lane b) → feed it to emulation (lane c)

The robust workflow: from the QEMU pcap, extract the **`EncCommService`
session-open server response**; feed that exact response as the input to the
Ghidra/Unicorn re-emulation of the preamble/frame builder; if the emulated SEND
frame then **matches the captured reset SEND byte-for-byte**, you have fully
reconstructed the algorithm and can reimplement it natively. If it only matches
*with* that server reply and the reply is non-reproducible, native replay needs the
server. (High confidence — this is the logical join of the two lanes.)

---

## Recommended deployment pipeline (the moment a working tool is in hand)

**Pre-flight (before touching the real printer):**
- Install **new waste-ink pad** first (overflow safety — per repo + OctoInkjet).
- In the Win11 VM: install **Frida** (`pip install frida-tools`), **API Monitor**
  (triage), and **x64dbg**. On the host: `modprobe usbmon`, grant `wireshark`-group
  access to `/dev/usbmon*`, and configure the QEMU passthrough with
  `-device usb-host,vendorid=0x04a9,productid=0x12fe,pcap=g6020-reset.pcap`.
- **Dry-run the hooks** on a *non-clearing* action (e.g., a status read / EEPROM
  info) so you confirm the Frida script fires and the pcap records **without
  spending the one real reset**.

**Capture (one clean shot):**
1. Put the printer in service mode (panel sequence) → it re-enumerates to `12fe`;
   QEMU regrabs it by vendor/product.
2. Start `tshark`/Wireshark on the host `usbmonX`; QEMU pcap is already armed; start
   the Frida agent: `frida -f "<working_tool>.exe" -l hook-devio.js -l hook-winusb.js -l hook-create.js -o frida-reset.log`.
3. Log `date +%s.%N` on the host, then **click reset once**. Let the tool complete
   its commit + power-cycle prompt.
4. **Verify the reset is real**: power-cycle, re-read EEPROM waste counter — it must
   drop (~100%→~0%) and survive the cycle. Only a *verified* clear is worth
   reverse-engineering.

**Offline analysis:**
5. In the captures, find the **`00 03 01 03 07` / `0x85`-family signature** (content
   anchor) to pin the exact reset SEND; read the **session-open** transfers before
   it and the **commit** transfer after it.
6. Cross-check the **Frida `onEnter` input-buffer hexdump** against the **QEMU pcap
   data stage** byte-for-byte — Frida gives plaintext runtime bytes; pcap gives the
   setup packet (`bmRequestType/bRequest/wValue/wIndex`) the minidriver built.
7. For any byte still opaque, **x64dbg hardware-BP + `savedata`** at the frame
   buffer, or **Unicorn/Ghidra re-emulate** the builder.
8. **Verdict:** if the full SEND (preamble + session + reset + commit) re-emulates
   from local/config inputs alone → **replayable; build the native tool**. If it
   requires a non-reproducible `EncCommService` server nonce → **cloud-validated;
   native replay is impossible without brokering the handshake** (record this as
   the project-deciding result).

---

## Cross-check matrix (≥2 sources per load-bearing claim)

| Claim | Source A | Source B |
|---|---|---|
| Frida hooks `DeviceIoControl`, dumps in/out buffers + IOCTL + sizes, resolves driver from handle, base64s input for replay | [IoctlHunter blog](https://z4ksec.github.io/posts/ioctlhunter-release-v0.2/) | [IoctlHunter `script.ts`](https://github.com/Z4kSec/IoctlHunter/blob/main/ioctl_hunter/frida/script.ts) |
| Frida `Interceptor.attach` onEnter/onLeave + `hexdump` reads Win32 buffers; spawn `-f` / attach `-p` | [ired.team](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/instrumenting-windows-apis-with-frida) | [frida.re functions/examples](https://frida.re/docs/functions/) |
| `WINUSB_SETUP_PACKET` = 8 bytes {RequestType,Request,Value,Index,Length}; passed to `WinUsb_ControlTransfer` | [MS Learn WINUSB_SETUP_PACKET](https://learn.microsoft.com/en-us/windows/win32/api/winusb/ns-winusb-winusb_setup_packet) | [MS Learn WinUsb_ControlTransfer](https://learn.microsoft.com/en-us/windows/win32/api/winusb/nf-winusb-winusb_controltransfer) |
| WinUSB ControlTransfer works where Write/ReadPipe fail (matches our control-reply finding) | [OSR thread](https://community.osr.com/t/why-winusb-writepipe-and-winusb-readpipe-fail-but-winusb-controltransfer-ok/56234) | repo `canon-servicemode-transport-research.md` (native: bulk-IN dead, control works) |
| QEMU per-device `pcap=` records traffic, usbmon-compatible, Wireshark-decodable | [QEMU USB docs](https://qemu-project.gitlab.io/qemu/system/devices/usb.html) | [Wireshark CaptureSetup/USB](https://wiki.wireshark.org/CaptureSetup/USB) |
| Host usbmon: `modprobe usbmon`, capture `usbmonX` (bus #), group perms on `/dev/usbmon*` | [Wireshark CaptureSetup/USB](https://wiki.wireshark.org/CaptureSetup/USB) | [earth.li KVM+usbmon](https://www.earth.li/~noodles/blog/2012/10/kvm-usbmon-wireshark-win.html) / [morphykuffour](https://morphykuffour.github.io/linux/wireshark/2025/02/19/Wireshark-USB-Capture-Setup.html) |
| Bind passthrough by vendor/product (not hostaddr) because device re-enumerates; udev auto-regrab | [QEMU USB docs](https://qemu-project.gitlab.io/qemu/system/devices/usb.html) | [earth.li KVM+usbmon](https://www.earth.li/~noodles/blog/2012/10/kvm-usbmon-wireshark-win.html) |
| Filter Canon USB capture by idVendor/idProduct then transfer_type / bInterfaceClass==0x07 | [snorp.dev printer USB-RE](https://snorp.dev/blog/printers) | [botmonster pyusb USB-RE](https://botmonster.com/self-hosting/reverse-engineer-usb-devices-with-wireshark-and-python/) |
| Capture truncation/snaplen pitfall for USB | [USBPcap limitations](https://desowin.org/usbpcap/capture_limitations.html) | [Wireshark CaptureSetup/USB](https://wiki.wireshark.org/CaptureSetup/USB) |
| x64dbg: log-only conditional BP `{REG}` + HW BP on mem write + `savedata` to dump runtime bytes | [x64dbg self-decryption](https://x64dbg.com/blog/2018/02/25/fun-with-self-decryption.html) | [x64dbg tips/tricks](https://daevlin.github.io/2020/07/25/x64dbg_tips_and_tricks.html) / [embeeresearch](https://www.embeeresearch.io/unpacking-malware-with-hardware-breakpoints-cobalt-strike/) |
| Re-emulate a function (Ghidra p-code / Unicorn) to recover derived/decrypted bytes without full run | [Shielder Unicorn U-Boot](https://www.shielder.com/blog/2022/03/reversing-embedded-device-bootloader-u-boot-p.2/) | [Ghidra PCode emulation, cetfor](https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb) / [Unicorn 101](https://benmohalior.medium.com/unicorn-engine-101-solving-a-polyglot-ctf-challenge-3dc159db2710) |

---

## Confidence summary & residual unknowns

- **High confidence:** the Frida hook recipes (DeviceIoControl / WinUSB / CreateFile)
  and their buffer-dump semantics; the QEMU `pcap=` built-in being the best capture
  for a passthrough device and usbmon/Wireshark-compatible; host-usbmon mechanics;
  the re-enumeration + content-anchor correlation method; the x64dbg HW-BP/savedata
  and Unicorn/Ghidra re-emulation techniques for runtime bytes.
- **Medium confidence:** that the *specific working V6.x tool* talks WinUSB vs the
  minidriver (unknown until captured — that's why we hook both families); WICReset's
  exact anti-instrumentation posture; guest-USBPcap visibility under exclusive QEMU
  passthrough.
- **Residual unknowns (only the capture settles them):** the exact control setup
  packet (`bmRequestType/bRequest/wValue/wIndex`) the minidriver emits; whether the
  reset SEND re-emulates from local inputs alone (**replayable**) or requires a
  non-reproducible `EncCommService` server nonce (**cloud-validated → native replay
  impossible**). The pipeline above is designed specifically to produce that verdict
  on the first clean reset.

*Provenance: live WebSearch / DuckDuckGo MCP / WebFetch all functioned this run;
every load-bearing claim is cross-checked against ≥2 sources inline. No contact
with leecher1337 or any upstream maintainer — public reading only.*
