# Canon Service-Mode Maintenance Command Transport over USB

**Research lane deliverable** — how Canon service-mode (MegaTank G-series, plus
MG / MX / MP / iP inkjet) maintenance commands are physically carried over USB:
is the service command/response channel a USB **control** transfer or a USB
**bulk** transfer, and what handshake / "wake" (if any) puts the device into a
state where it answers maintenance reads.

> Method note: live web search worked this run (DuckDuckGo MCP, SearXNG,
> WebSearch returned results); autonomous full-page fetch was partly blocked by
> robots.txt. **The load-bearing evidence is this repository's own static +
> native reverse-engineering of two real tools (Canon ServiceTool v5103 and
> WICReset) and a real MegaTank service-mode device** — that is stronger than
> any web source and is what this document is anchored on. Web sources are used
> only as corroboration. **No upstream/leecher1337 contact; public reading
> only.**
>
> This file has been corrected twice. The honest, evidence-final answer is in
> the TL;DR and §1; earlier drafts that said "bulk only" or "control via
> IOCTL_USBPRINT_VENDOR_*" were both imprecise and are superseded.

---

## TL;DR (evidence-final)

The question "control or bulk?" has a **layered** answer, and the precise answer
depends on the layer you ask about:

1. **At the Windows application layer, neither.** Both Canon ServiceTool v5103
   and WICReset reach the printer through **`CreateFileA/W` + overlapped
   `DeviceIoControl`** to a kernel **minidriver** (Canon's `usbscan.sys` in
   normal mode; the `usbprint.sys` printer-class transport in service mode).
   The binaries build only a **3-byte application header `[cmd][arg_hi][arg_lo]`
   (+ payload)** — they **never assemble a USB setup packet**. So the
   bulk-vs-control pipe selection is made *inside the closed Windows
   minidriver*, not in the tool, and is invisible in the binaries. (High
   confidence — in-repo static RE of both binaries.)

2. **On the real MegaTank service-mode device, the working maintenance RECV is a
   CONTROL transfer; the SEND is a BULK-OUT.** Empirically (native lane against
   `04a9:12fe` in service mode): a bare **bulk-IN on EP 0x82 returns nothing**,
   while a **control IN works**. The command/query SEND is a **bulk-OUT on EP
   0x01**. So a Linux/libusb reimplementation must: write the command frame as
   **bulk-OUT (EP 0x01)** and read the reply over the **control pipe (EP 0,
   class/vendor IN)** — not over bulk-IN. (High confidence on the empirical
   result; the exact control `bmRequestType/bRequest/wValue/wIndex` is not in
   the binaries and needs a usbmon capture to pin.)

3. **The handshake is a SEND-primed read, not a free-running pipe.** The tool
   does **not** do an unsolicited bulk-IN. A read is: **SEND `[0x86][00][00]`
   (or a `[0x85]…` query) to prime, then read the ~20-byte status reply.** A
   cold bare RECV times out (errno 110) because nothing armed it. The 3-byte
   `[cmd][arg_hi][arg_lo]` header *is* the in-band command; the firmware then
   returns the reply on whichever pipe it favors (control on `12fe`).

4. **"Service mode" is a device-side firmware state entered by a front-panel
   button sequence, not a USB request.** Hold Power + tap Stop/Resume ~5–6× (by
   model). The printer then **re-enumerates with a different USB identity** — in
   normal mode it shows PID `04a9:1865` with 6 interfaces incl. a still-image
   (usbscan) interface; in service mode it shows PID `04a9:12fe` with a single
   **printer-class** interface (EP 0x01 OUT / 0x82 IN). The tool "detects"
   service mode purely by enumerating a Canon device and reading its **1284
   GET_DEVICE_ID** (control, EP0); no dedicated "enter service mode" USB opcode
   exists. (High confidence — in-repo RE + community entry procedure.)

**One-line answer for the schema:** the maintenance command frame goes **OUT as
bulk** (EP 0x01) and the reply comes back **IN over the control pipe** on the
real service-mode MegaTank; at the Windows layer this is wrapped in
`usbscan`/`usbprint` `DeviceIoControl` IOCTLs (`0x220038` SEND / `0x22003c` RECV;
service-mode `usbprint` device-type `0x16` family, IOCTL `0x16000c`), with the
bulk/control pipe choice made by the minidriver.

---

## 0. In-repo evidence map (the load-bearing sources)

| In-repo doc | What it establishes |
|---|---|
| `docs/research/canon-tool-ghidra-notes.md` | Single transport choke point `FUN_004302c0(cmd,arg,mode,…)`: `mode==0`→SEND IOCTL `0x220038`, `mode!=0`→RECV `0x22003c`, on a `\\.\Usbscan%d` handle; **no USB setup packet built in the binary — pipe choice is the minidriver's.** |
| `servicetool-v5103-servicemode-reset-re.md` | Two coexisting transports auto-selected by exposed interface: **usbscan** (normal) vs **usbprint** (service). Service-mode device discovered via `EnumPortsA`+SetupDi on `GUID_DEVINTERFACE_USBPRINT`; PID `04a9:12fe`, single printer-class iface, EP 0x01/0x82. Reset payload identical across modes. |
| `servicemode-ioctl-0x16000c.md` | Decodes the three IOCTLs: `0x220038`/`0x22003c` (DeviceType `0x22` usbscan, SEND/RECV) and `0x16000c` (DeviceType **`0x16`** usbprint family, the alt/status op). **At Win32 none is a raw control transfer** — all are `DeviceIoControl(METHOD_BUFFERED)`. Native result: bare bulk-IN 0x82 dead, control works → replicate RECV as control IN. |
| `servicetool-v5103-read-re.md` | READ = SEND `[0x86][00][00]` then poll a **20-byte** RECV; a cold bare RECV times out (errno 110) — reads are **SEND-primed**, not free bulk-IN. |
| `servicetool-v5103-reset-handshake.md` | Ordered session handshake before the reset payload SEND; several literal bytes are runtime-sourced (need a capture). |
| `wicreset-static-re.md` | **Independent second tool**: WICReset uses `SetupDi`+`CreateFileW`+`DeviceIoControl` with the **same** usbscan IOCTL family `0x220038`(SEND)/`0x22003c`(RECV) (+`0x220030/34` read variants). Confirms the transport across two separately-reversed tools. |

Two independently reverse-engineered tools converging on the same IOCTL family,
plus a live device measurement, is the strongest available evidence.

---

## 1. Control vs bulk — the precise answer

- **Bulk** carries: ordinary print data (USB Printer Class spec: "The host
  prints something on a printer by delivering data on the Bulk OUT endpoint"),
  and the **maintenance command/query SEND** (the `[cmd][arg_hi][arg_lo][payload]`
  frame goes **bulk-OUT on EP 0x01** of the `12fe` service device).
- **Control (EP0)** carries: the **GET_DEVICE_ID** identity handshake (USB
  Printer Class bRequest 0x00), and — empirically on the real service-mode
  device — the **maintenance RECV / status reply**, because the device's
  bulk-IN (EP 0x82) returns nothing in service mode while a control IN works.
- **The Windows tools never choose the pipe directly.** They emit
  `DeviceIoControl` IOCTLs (`0x220038`/`0x22003c` via usbscan; `0x16000c` via the
  usbprint `0x16` device-type family in service mode) to a minidriver that
  performs the actual USB transfer. The binaries build no `bmRequestType`/
  `bRequest`/`wValue`/`wIndex`, so which pipe the minidriver uses is not
  determinable from the `.exe` — only the native device measurement settles it,
  and it says **control for the reply**.

So the earlier "bulk only" draft was wrong (the reply path is control on the
real device), and the "control via `IOCTL_USBPRINT_VENDOR_GET/SET_COMMAND`"
draft named the wrong IOCTLs (the actual ones are the usbscan/usbprint framed-
buffer IOCTLs `0x220038`/`0x22003c`/`0x16000c`, not the WDK VENDOR_COMMAND pair).
This version reflects the in-repo binary + native truth.

---

## 2. The "wake" / service-mode entry

- **Genuine wake = front-panel button sequence on the printer** (model-specific;
  G-series: power off, hold Stop/Resume, press+hold Power, release Stop, tap
  Stop ~5–6× while holding Power, release). No USB request does this.
- **Effect on USB = re-enumeration with a new identity.** Normal mode PID
  `04a9:1865` (6 interfaces incl. usbscan still-image iface-4); service mode PID
  `04a9:12fe` (single printer-class interface, EP 0x01 OUT / 0x82 IN). The tool
  must enumerate fresh after entry — endpoint/interface numbers differ from
  normal mode.
- **Host-side "wake" of the command channel** is just: claim the printer-class
  interface, read **GET_DEVICE_ID** (control, EP0) to confirm `MFG:Canon;MDL:…`,
  then begin the SEND-primed command exchange. There is **no separate vendor
  enable-service control request**; community sources confirm the tool is inert
  ("stays grey" / "resets only if in service mode") until the panel sequence is
  done.

Community corroboration of the entry method and inert-until-service-mode
behavior: samehfix, resetter.net, easyfixs (cited below).

---

## 3. Web-source corroboration (secondary)

- USB Printer Class spec v1.1 — print data on Bulk OUT; class requests
  GET_DEVICE_ID(0x00)/GET_PORT_STATUS(0x01)/SOFT_RESET(0x02) on EP0:
  https://www.usb.org/sites/default/files/usbprint11a021811.pdf
- Microsoft Learn — usbprint.sys / USB printing:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-printing
- Microsoft Learn — How to Send a USB Control Transfer (bmRequestType
  semantics, for interpreting a future capture):
  https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-control-transfer
- Community RE describing the tool's USB as **control transfers** (matches the
  reply-pipe finding, snippet strength — pages partly blocked from auto-fetch):
  BCH Technologies ("sniffing USB control transfers"):
  https://bchtechnologies.com/blogs/blog/developing-an-opensource-alternative-to-canon-service-tool
  ; PrinterKnowledge ("the software uses … 'control transfers' … open on the USB
  bus … open calls via control transfers"):
  https://www.printerknowledge.com/threads/make-a-canon-service-tool.16250/
- SANE pixma (the **scanner** command path uses **bulk** — a different channel
  from the service path; shows Canon's command framing lineage):
  https://gitlab.com/sane-project/backends/-/tree/master/backend ;
  http://www.sane-project.org/man/sane-pixma.5.html
- Service-mode required / tool inert otherwise:
  https://samehfix.com/product/canon-service-mode-tool-version-6-310/ ;
  https://resetter.net/canon-service-tool-5610 ;
  https://easyfixs.blogspot.com/2019/09/service-tool-v4718.html

Note the apparent contradiction in community sources (some say "control," and a
scanner writeup like snorp.dev filters on `usb.transfer_type==3`/bulk): both are
right for different channels — **bulk for the OUT command/print/scan stream,
control for the service-mode status reply**. That is exactly the layered picture
the in-repo native measurement produced.

---

## 4. Verification capture (to pin the exact control setup packet)

The control-vs-bulk split is settled; a usbmon/USBPcap capture of ServiceTool or
WICReset against a real `12fe` device in service mode is needed only to recover:
1. the **GET_DEVICE_ID** control IN (bmRequestType `0xA1`, bRequest `0x00`) at
   enumeration;
2. the **exact control IN setup packet** the minidriver uses for the RECV
   (vendor `0xC0,<bReq>,<wValue>,wIndex=iface` vs class `0xA1,0x01,…`) — NOT in
   the binaries;
3. confirmation the SEND is **bulk-OUT EP 0x01** of `[cmd][arg_hi][arg_lo][payload]`;
4. the runtime-sourced preamble bytes (`DAT_004921f8/9`) and the `0x81` session
   frame payload byte.
Discriminator in the capture: `bmRequestType` (`0x21/0xA1` class vs
`0x40/0xC0/0x41/0xC1` vendor); bulk shows as `URB_BULK` with no setup packet.
Refs: https://wiki.wireshark.org/CaptureSetup/USB ;
https://desowin.org/usbpcap/capture_limitations.html

---

## 5. Cross-check matrix (≥2 independent sources per core claim)

| Claim | Source A (load-bearing, in-repo) | Source B |
|---|---|---|
| Tools use CreateFile+DeviceIoControl to a minidriver; no USB setup packet in the .exe | canon-tool-ghidra-notes.md / servicemode-ioctl-0x16000c.md | wicreset-static-re.md (independent 2nd tool) |
| Maintenance IOCTL family = usbscan `0x220038`/`0x22003c` (+ usbprint `0x16000c` in service) | servicetool-v5103-servicemode-reset-re.md | wicreset-static-re.md (`0x220038`/`0x22003c`/`0x220030`/`0x220034`) |
| Real service device: bulk-IN dead, RECV works over CONTROL; SEND = bulk-OUT EP 0x01 | servicemode-ioctl-0x16000c.md (native lane) | servicetool-v5103-read-re.md (cold RECV errno 110 → SEND-primed) |
| Reads are SEND-primed (`[0x86]` or `[0x85]` query → 20-byte reply), not free bulk-IN | servicetool-v5103-read-re.md | servicetool-v5103-reset-handshake.md |
| Service mode = panel sequence + USB re-enumeration (1865→12fe); detect via GET_DEVICE_ID | servicetool-v5103-servicemode-reset-re.md | community: samehfix / resetter.net / easyfixs |
| Bulk also carries print (spec) and the separate pixma scanner path | USB Printer Class spec v1.1 | SANE pixma / sane-pixma(5) |
| Community RE independently calls the tool's USB "control transfers" | BCH Technologies | PrinterKnowledge thread |

---

## 6. Confidence + residual unknowns

- **High:** Windows tools use `DeviceIoControl` to usbscan/usbprint minidrivers
  with a 3-byte app header and no USB setup packet (two-tool RE); IOCTL family
  `0x220038`/`0x22003c`/`0x16000c`; service mode is panel-entered + re-enumerated
  (`1865`→`12fe`); reads are SEND-primed; on the real device the RECV works over
  control while bare bulk-IN is dead and the SEND is bulk-OUT on EP 0x01.
- **Medium:** that the working reply pipe is *specifically* a control IN (native
  empirical result reconciled with the SEND-primed model; the binary cannot
  prove the pipe).
- **Residual unknown — needs a service-mode usbmon capture:** the exact control
  setup packet (`bmRequestType/bRequest/wValue/wIndex`) for the RECV; which
  low-level IOCTL the runtime usbprint object issues (`0x220038` vs `0x16000c`,
  invisible on the wire); the runtime-sourced preamble bytes.
- **Corrections recorded:** draft 1 ("bulk for maintenance, control only for the
  handshake") and draft 2 ("control via `IOCTL_USBPRINT_VENDOR_GET/SET_COMMAND`")
  are both superseded by this in-repo-evidence-anchored version.
