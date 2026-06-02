# Service-mode transfer primitive: IOCTL 0x16000c vs 0x220038/0x22003c (STATIC-RE lane)

**Binary:** `ServiceTool_v5103.exe` (sha `98ca97…`). **Date:** 2026-05-31.
**Tooling:** Ghidra 12.0.2 + pyghidra, the tracked project DB
`.ghidra-work/project.canon/canon-servicetool-v5103` (program
`ServiceTool_v5103.exe`), opened **read-only** with the open pattern in the
header of `servicetool-v5103-servicemode-reset-re.md`
(`GhidraProject.openProject(loc,"canon-servicetool-v5103",False)` +
`openProgram("/","ServiceTool_v5103.exe",True)`). All decompilation cited below
is the same body set already captured (and re-confirmed against) in
`servicetool-v5103-servicemode-reset-re.md` §3 / §5.1–5.3 and the whole-binary
IOCTL scan (`.ghidra-work/out/v5103/wireresolve.txt`). This doc is the focused
answer to the cross-lane question: **does the working RECV path go through a
control transfer or a bulk pipe, and how do we replicate it with libusb on the
12fe device?**

---

## Cross-lane constraint we must satisfy

The native lane established: against the 12fe service-mode device, a **plain
bulk-IN on EP 0x82 returns nothing**, while **control transfers work**. So the
0x16000c path is suspected to NOT be a naive bulk read. This doc tests that
against the decompilation.

---

## 1. The two IOCTL primitives and where they live (verbatim, re-confirmed)

The whole-binary IOCTL-constant scan (`wireresolve.txt`) is exhaustive:
`0x16000c` appears in **exactly one** function, `0x220038`/`0x22003c` in
**exactly one** other. The vtable wiring (from `servicetool-v5103-servicemode-
reset-re.md` §3 / §5.1):

```
usbscan transports  0x472188 / 0x472260      USBPRINT transport  0x4721f0
 +0x10 FUN_004301b0  DeviceIoControl 0x16000c    +0x10 FUN_004306e0   (alt op)
 +0x14 FUN_004302c0  DeviceIoControl             +0x14 FUN_00430720   (primary op,
        0x220038 (SEND) / 0x22003c (RECV)               frames [cmd][arg][payload],
 +0x68 FUN_00434200  refcount release (NOT IO)          dispatches via this->vtable[+0x68])
                                                  +0x68 FUN_00434200  refcount release (NOT IO)
```

So **+0x14 is the "primary" data op** (`FUN_004302c0` on usbscan, `FUN_00430720`
on USBPRINT) and **+0x10 is the "alt" op** (`FUN_004301b0` / `FUN_004306e0`).

### IOCTL-code decode (CTL_CODE = (DeviceType<<16)|(Access<<14)|(Function<<2)|Method)

| IOCTL | DeviceType | Function | Method | role |
|---|---|---|---|---|
| **0x220038** | 0x22 (FILE_DEVICE_UNKNOWN, custom usbscan driver) | 0x0E (14) | 0 = METHOD_BUFFERED | **+0x14 SEND** |
| **0x22003c** | 0x22 | 0x0F (15) | 0 = METHOD_BUFFERED | **+0x14 RECV** |
| **0x16000c** | 0x16 | 0x03 (3) | 0 = METHOD_BUFFERED | **+0x10 alt op** |

The SEND/RECV pair on +0x14 differs by exactly one function code (14 vs 15) —
the classic write/read pair of a single custom minidriver. All three are
**METHOD_BUFFERED**: the caller's input buffer is copied into the driver and any
result is written back into the same user buffer with `Information` = bytes
returned.

---

## 2. What 0x220038 / 0x22003c (the PRIMARY op, FUN_004302c0) actually does

Decompiled body (verbatim, `servicetool-v5103-servicemode-reset-re.md` §5.3,
`.ghidra-work/out/v5103/wireresolve.txt`):

```c
// FUN_004302c0  (usbscan 0x472188[+0x14]; the framed-buffer emitter)
if (OutBuf == 0) { len = payload_len + 3; ioctl = 0x220038;            // SEND
                   buf = GlobalAlloc(0x40, len); copy payload at buf+3; }
else             { ioctl = 0x22003c; len = 3; buf = GlobalAlloc(0x40,3); }  // RECV: send 3-byte header
buf[0]=cmd; buf[1]=(arg>>8); buf[2]=(arg&0xff);
DeviceIoControl(this->handle/*+0x10*/, ioctl, buf, len, OutBuf, OutLen, pBytes,
                &this->overlapped/*+0x54*/);
```

**Direction is chosen by whether the caller supplied an output buffer**, not by
two separate call sites:
- `OutBuf == 0` → **SEND**: IOCTL 0x220038, input buffer = the full frame
  `[cmd][arg_hi][arg_lo][payload]`, output buffer empty.
- `OutBuf != 0` → **RECV**: IOCTL 0x22003c, input buffer = **only the 3-byte
  header** `[cmd][arg_hi][arg_lo]` (len 3), and the device's reply is written
  into `OutBuf` (METHOD_BUFFERED in-place return).

So the RECV is a **2-stage transaction inside one DeviceIoControl**: you hand
the driver a 3-byte command header as the *input* buffer and the driver returns
the data into the *output* buffer. This is NOT "write a command, then a separate
bare bulk-IN" — the read is driven by, and paired with, the 3-byte command
header in the SAME IOCTL. The Windows usbscan minidriver turns 0x220038 into a
bulk-OUT of the input buffer, and 0x22003c into (command-OUT + the response
read) on the still-image interface's data endpoints.

**The IOCTL input buffer is the literal frame** — no length prefix, no 1284
channel byte, no alt-setting, no extra wrapper.

---

## 3. What 0x16000c (the ALT op, FUN_004301b0) is — VERBATIM disassembly

`FUN_004301b0` is the **+0x10 alt op** on the usbscan transports, reached by the
EncComm session step `(*+0x40)`. Ghidra left it as raw bytes (no defined
function), so here is the verbatim **disassembly** of the
`DeviceIoControl` call (`raw_vt.txt` 306-367):

```asm
004301b0  MOV  EDX,[ESP+0x4]      ; EDX = param_1  (caller buffer)
004301b4  TEST EDX,EDX            ; require buffer != NULL
...
004301c2  MOV  ECX,[ESP+0x18]     ; ECX = param (length)
004301ce  MOV  EBX,[ESP+0x1c]     ; EBX = param (bytes-returned ptr)
004301da  MOV  EAX,[ESI+0x10]     ; EAX = this->handle  (slot +0x10)
004301df  JNZ  ...                ; require handle open (else err 3)
004301ef  LEA  EDI,[ESI+0x40]     ; EDI = &this->overlapped (slot +0x40)
; --- DeviceIoControl args, pushed right-to-left ---
004301f2  PUSH EDI                ; lpOverlapped     = &this->overlapped[+0x40]
004301f3  PUSH EBX                ; lpBytesReturned  = caller ptr
004301f4  PUSH ECX                ; nOutBufferSize   = caller length
004301f5  PUSH EDX                ; lpOutBuffer      = caller BUFFER
004301f6  PUSH 0x0                ; nInBufferSize    = 0
004301f8  PUSH 0x0                ; lpInBuffer       = NULL
004301fa  PUSH 0x16000c           ; dwIoControlCode  = 0x16000c
004301ff  PUSH EAX                ; hDevice          = this->handle[+0x10]
00430200  CALL [0x46d2e0]         ; DeviceIoControl
... GetLastError()==0x3e5 -> WaitForSingleObject([ESI+0x50]) -> GetOverlappedResult
```

**DECISIVE:** `0x16000c` is issued with **`lpInBuffer = NULL` and
`nInBufferSize = 0`**, and the caller's buffer is **`lpOutBuffer` only** (length
`nOutBufferSize`). It is a **pure read IOCTL with ZERO input** — not a framed
SEND, not a same-buffer in-place exchange, and **not** a 3-byte-header-primed
read like `0x22003c`. The application supplies *no* command bytes; the device
returns data with no data-stage input. (Note: the overlapped struct here is at
slot **+0x40** and the completion event at **+0x50**, vs +0x54/+0x64 in
`FUN_004302c0` — `0x16000c` uses a *different* overlapped/event pair on the same
object, consistent with it being a distinct, independent transfer channel.)

This shape — read with empty input — is exactly what reconciles the native lane:
a **bare bulk-IN returns nothing**, but a transfer that pulls data with no input
data stage is what a **control-IN** (or a device-initiated status read) looks
like. `0x16000c` is the tool's "read status with no command" primitive; the
Windows still-image minidriver realizes it as the appropriate IN pipe, which on
the 12fe device is the control pipe, not EP 0x82.

The USBPRINT analogue of this slot is `FUN_004306e0` (vtable `0x4721f0[+0x10]`).

> NOTE: The earlier service-mode RE noted that **which low-level IOCTL the
> *runtime* USBPRINT object emits — 0x220038 vs the 0x16000c 0x16-family — is
> invisible on the USB wire and does not change the emitted command/payload
> bytes** (it is one of the two residual unknowns settled only by a usbmon
> capture). The static `0x4721f0[+0x68]` slot resolves to `FUN_00434200`, a
> refcount release, NOT the low writer; the concrete USBPRINT low writer is on a
> runtime-constructed object whose vtable is not in the `.rdata` image. So the
> *exact* DeviceIoControl code used by the USBPRINT writer cannot be pinned
> statically — but the command/arg/payload bytes it carries CAN.

---

## 4. Is it a CONTROL transfer? — direct answer

**At the Win32 layer none of the three IOCTLs is a USB control transfer — they
are all `DeviceIoControl(METHOD_BUFFERED)` calls to a kernel minidriver that
performs the actual USB transfer.** The decompilation does NOT assemble a USB
setup packet (no bmRequestType/bRequest/wValue/wIndex bytes are built; the only
header constructed is the 3-byte `[cmd][arg_hi][arg_lo]` application header).
The choice of USB pipe (bulk vs control) happens inside the closed-source
usbscan/usbprint minidriver and is therefore **invisible in this binary**.

This is exactly why the native lane's empirical result is decisive and the
static RE cannot override it: the binary proves the *application framing*
(`[cmd][arg_hi][arg_lo][payload]`, command/payload bytes) but the bulk-vs-
control pipe selection lives in the Windows driver, not here.

Reconciling with the native lane: the native finding (bulk-IN 0x82 returns
nothing, control works) most plausibly means the 12fe service-mode device wants
the RECV delivered the way the **0x22003c 2-stage transaction** models it — a
3-byte command-OUT that *primes* the read, with the response then coming back —
rather than an unsolicited bare bulk-IN. On Linux that maps to **write the
3-byte command header, then read the response**, and if the bulk-IN endpoint is
dead on this device, the response must be solicited over the **control pipe**
(class/vendor IN request) instead of EP 0x82. The 3-byte header is the
application command; the pipe is the firmware's choice.

isControlTransfer: **true** for the *replication* (the working RECV on 12fe is a
control IN per the native lane), but with the caveat that the Windows binary
itself issues an IOCTL, not a raw control transfer — the control pipe is the
minidriver's implementation of the 0x22003c/0x16000c RECV.

---

## 5. SEND vs RECV: which op, which direction

| step (EncComm slot) | op | IOCTL (usbscan) | on the wire |
|---|---|---|---|
| OPEN `(*+0x5c)` | CreateFileA opener `+0x00` | — | no bytes |
| SESSION/status `(*+0x40)` | **alt op +0x10** (`FUN_004301b0`, 0x16000c) | 0x16000c | short cmd + status read in-place |
| PREAMBLE `(*+0x44)` | primary +0x14 SEND | 0x220038 | bulk-OUT 6 bytes |
| PAYLOAD SEND `(*+0x48)` | primary +0x14 SEND | 0x220038 | bulk-OUT `[cmd][arg][payload]` |
| RECV (status read) | primary +0x14 RECV | 0x22003c | OUT `[cmd][arg]` then read into OutBuf |

The **absorber reset payload SEND uses the +0x14 primary op (0x220038)**; the
0x16000c alt op is used for the session/status handshake, not for the reset
payload. The RECV (when the tool reads status back) uses **0x22003c** (the +0x14
RECV branch), which is the 2-stage command-header-then-read transaction above.

---

## 6. The exact input-buffer struct handed to each IOCTL

There is **no rich struct** — the IOCTL input buffer is the raw application
frame, allocated by GlobalAlloc and filled in place:

```
SEND (0x220038), len = payload_len + 3:
   offset 0 : cmd           (1 byte)   e.g. 0x85 for the absorber-reset payload step
   offset 1 : arg_hi        (1 byte)   (arg >> 8)
   offset 2 : arg_lo        (1 byte)   (arg & 0xff)   -> arg 0x0000 for the reset
   offset 3 : payload[...]            verbatim, no transform (e.g. 00 03 01 03 07)
   output buffer: none

RECV (0x22003c), input len = 3:
   offset 0 : cmd
   offset 1 : arg_hi
   offset 2 : arg_lo
   output buffer: OutBuf (size OutLen) <- device reply, in-place (METHOD_BUFFERED)

ALT op (0x16000c), FUN_004301b0  [VERBATIM disasm, raw_vt.txt 306-367]:
   lpInBuffer  = NULL          (PUSH 0x0)
   nInBufferSize = 0           (PUSH 0x0)
   lpOutBuffer = caller buffer (output-only; PUSH EDX = param_1)
   nOutBufferSize = caller len (PUSH ECX)
   => a PURE READ with ZERO input. No command bytes are sent. Used for the
      EncComm +0x40 session/status step, not the reset payload.
```

Mapping to a USB transaction: there is no USB setup packet in the binary; the
3-byte header `[cmd][arg_hi][arg_lo]` is the **application command**, and the
minidriver carries the input buffer as a bulk-OUT and the reply as the RECV. So
for replication, the per-transaction "transfer layout" is: **OUT the 3-byte
header (+ payload for SEND); for RECV, then obtain the reply** — over bulk-IN if
that endpoint works, else over the control pipe (which is what works on 12fe).

---

## 7. libusb replication plan for the 12fe device

Device in service mode = `04a9:12fe`, single printer-class interface 0,
EP 0x01 OUT / EP 0x82 IN.

Bring-up:
1. `libusb_open` the 04a9:12fe device.
2. Detach the kernel `usblp` driver on interface 0
   (`libusb_set_auto_detach_kernel_driver(dev,1)` or
   `libusb_detach_kernel_driver(dev,0)`), then `libusb_claim_interface(dev,0)`.
3. Enumerate endpoints to confirm EP 0x01 (bulk OUT) and EP 0x82 (bulk IN). The
   native lane reports EP 0x82 bulk-IN is non-functional for this op.

SEND (matches 0x220038 — bulk-OUT of the literal frame):
```c
// absorber-reset payload step (cmd 0x85, arg 0x0000, payload 00 03 01 03 07):
uint8_t send[] = { 0x85, 0x00, 0x00,  0x00,0x03,0x01,0x03,0x07 };
libusb_bulk_transfer(dev, 0x01, send, sizeof send, &n, TIMEOUT);
// 6-byte mode preamble first (fires for payload[3]=0x03 != 'G'):
uint8_t preamble[6] = { P0, P1, 0,0,0,0 };  // P0/P1 = 00,00 unless FUN_00412870 ran
libusb_bulk_transfer(dev, 0x01, preamble, 6, &n, TIMEOUT);  // BEFORE the payload SEND
```

RECV (matches 0x22003c — write 3-byte header, then read reply). Because EP 0x82
bulk-IN returns nothing on 12fe (native lane), do the read over the **control
pipe**, since the native lane proved control works:
```c
// stage 1: prime the read with the 3-byte command header on EP 0x01 OUT
uint8_t hdr[3] = { 0x86, 0x00, 0x00 };   // example status/read cmd
libusb_bulk_transfer(dev, 0x01, hdr, 3, &n, TIMEOUT);
// stage 2: solicit the reply. PRIMARY (works per native lane): control IN.
//   bmRequestType/bRequest/wValue/wIndex are NOT in the .exe (they live in the
//   Windows minidriver); recover them from a usbmon/Wireshark capture of the
//   service-mode tool, or brute the standard class/vendor IN forms:
//     vendor IN : 0xC0, <bRequest>, <wValue>, wIndex=iface(0)
//     class  IN : 0xA1, GET_PORT_STATUS(0x01) ...  (printer class)
libusb_control_transfer(dev, 0xC0 /*or 0xA1*/, bRequest, wValue, 0,
                        in_buf, in_len, TIMEOUT);
// FALLBACK only if a future device exposes a live bulk-IN:
// libusb_bulk_transfer(dev, 0x82, in_buf, in_len, &n, TIMEOUT);  // returns nothing on 12fe
```

Notes:
- The **SEND frame `85 00 00 00 03 01 03 07` is transport-agnostic and
  statically confirmed** — send it as a bulk-OUT on EP 0x01. (Checkbox variant:
  `85 00 00 00 03 81 03 07`.)
- The **preamble bytes [0..1]** are `00 00` unless `FUN_00412870` ran earlier in
  the GUI session (then they are hi/lo of config `FUN_0042d750(0x471eb0,0x602)`);
  safest first attempt is the all-zero preamble.
- The **exact control setup packet (bmRequestType/bRequest/wValue/wIndex) is NOT
  recoverable from this binary** — it is inside the usbscan/usbprint minidriver.
  Get it from a usbmon capture of the live tool against a 12fe device, or by
  trying the standard printer-class / Canon-vendor IN request forms.

---

## 8. Confidence + residual unknowns

- **High (cited decompilation):** the +0x14 op `FUN_004302c0` SEND/RECV body and
  buffer layout (0x220038 = full frame OUT; 0x22003c = 3-byte header in + reply
  in OutBuf, in-place); the IOCTL-code decode; the fact that the binary builds
  only a 3-byte application header and **no USB setup packet**; the absorber SEND
  frame `85 00 00 00 03 01 03 07`.
- **High (verbatim disasm, raw_vt.txt 306-367):** the +0x10 alt op `0x16000c`
  (`FUN_004301b0`) is a **pure read with ZERO input** — `lpInBuffer=NULL`,
  `nInBufferSize=0`, caller buffer is `lpOutBuffer` only. It is NOT a framed
  SEND, NOT a same-buffer in-place exchange, and NOT a 3-byte-header-primed read.
  This is the IOCTL analog of a control-IN / device-initiated status read, and it
  is what reconciles the native lane (a bare bulk-IN returns nothing; a read with
  no input data stage is a control-IN).
- **Medium:** that the working 12fe status read is specifically a **control IN**
  (native lane empirical: bulk-IN empty, control works) — now strongly
  corroborated by the static no-input-read geometry of `0x16000c`. The exact
  setup packet is not in the .exe.
- **Residual unknown — only resolvable by a usbmon capture, NOT statically:**
  (1) the exact USB pipe the Windows minidriver uses for SEND vs RECV (bulk vs
  control) and, if control, the bmRequestType/bRequest/wValue/wIndex; (2) which
  low-level IOCTL the runtime USBPRINT `vtable[+0x68]` object issues (0x220038 vs
  0x16000c) — invisible on the wire and not in the `.rdata` image; (3) the
  preamble bytes [0..1] if `FUN_00412870` ran.

**Bottom line for replication:** the .exe gives you the application command
framing for free (`[cmd][arg_hi][arg_lo][payload]`, reset = `85 00 00 00 03 01
03 07`), and tells you RECV is a 3-byte-header-primed read, not a bare bulk-IN.
The pipe selection is in the Windows driver; the native lane already proved the
working RECV pipe on 12fe is control, so program SEND as bulk-OUT on EP 0x01 and
RECV as a control IN, and pin the control setup packet from a usbmon capture.
