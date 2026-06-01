# usbprint.sys → URB mapping for VENDOR_SET / VENDOR_GET / GET_1284_ID

**Lane 2 (pure-native, NO hardware) deliverable.** Derive, by static decompile of
Windows' `usbprint.sys`, the EXACT USB control transfer behind the
`IOCTL_USBPRINT_VENDOR_SET_COMMAND` (0x220038) IOCTL — the missing piece for the
native Linux/libusb G6020 5B00 reset — and cross-check it against the two mappings
the live device already confirmed (`GET_1284_ID` 0xA1/0x00 and `VENDOR_GET`
0xC1/0x8a).

No USB device was touched. The `04a9:12fe` printer stayed passed through to the
capture VM throughout. This is static RE + native code prep only.

## Binary provenance

| field | value |
|---|---|
| file | `C:\Windows\System32\drivers\usbprint.sys` (Win11 24H2 capture guest) |
| version | `10.0.26100.8328 (WinBuild.160101.0800)` |
| size | 110592 bytes |
| SHA256 | `3eb6b8172849290bac6ff548b53fbf78c37c6f68a22bdc604b12418d1b22a968` |
| image base | `0x140000000` (PE32+ native x86-64) |
| imports of note | `USBD.SYS!USBD_CreateConfigurationRequestEx`, `ntoskrnl!IoBuildDeviceIoControlRequest`, `IofCallDriver`, `ExAllocatePool2` |

Fetched from the guest via Ansible WinRM (`win_shell` base64), decoded on mbp-13,
hash-verified byte-exact. Decompiled with capstone 5.0.7 + pefile (objdump
cross-check available). Evidence files preserved at
`mbp-13:~/canon-tool-staging/usbprint-evidence/` (`usbprint.sys`,
`text_disasm.txt` full linear listing, `interesting.txt`).

## 1. IRP_MJ_DEVICE_CONTROL dispatch → handler addresses

The device-control entry reads `IoControlCode` from the IO_STACK_LOCATION
(`+0x18`) and `OutputBufferLength` (`+0x08`), then dispatches via a normalized
jump table (it does **not** decode `(code>>2)&0xFFF`; it subtracts a base and
indexes a table):

```
0x140004c8d: mov  eax, [rdx+0x18]      ; eax = IoControlCode
0x140004c90: mov  r13d,[rdx+0x08]      ; r13d = OutputBufferLength
0x140004c94: cmp  eax, 0x220024 / ja 0x140004f03   ; > 0x220024 -> upper tree
...
0x140004f03: add  eax, 0xffddffd0      ; eax -= 0x2200030  (normalize)
0x140004f08: cmp  eax, 0x34 / ja default
0x140004f11: lea  r8, [rip-0x4f18]      ; r8 = image base 0x140000000
0x140004f18: movzx eax, byte [r8+rax+0x1140c]      ; byte index table
0x140004f21: mov   ecx, dword [r8+rax*4+0x113d0]   ; dword jump-offset table
0x140004f2c: jmp   rcx                              ; -> r8 + offset
```

Decoding the jump table (`norm = IoControlCode - 0x2200030`):

| IOCTL | norm | handler |
|---|---|---|
| `0x220030` GET_LPT_STATUS | 0x00 | `0x1400050bb` |
| `0x220034` GET_1284_ID | 0x04 | `0x140005056` → shared `0x140001ca0` |
| **`0x220038` VENDOR_SET** | **0x08** | **`0x1400051d4`** |
| `0x22003c` VENDOR_GET | 0x0c | `0x1400026e0` |

All four allocate a 0x88-byte `_URB_CONTROL_VENDOR_OR_CLASS_REQUEST` (pool tag
`'USBP'`) and submit it to the USB bus driver via an
`IOCTL_INTERNAL_USB_SUBMIT_URB` (0x220003) IRP + `IofCallDriver` (seen at
`0x140002835: mov [rax-0x30], 0x220003`).

## 2. URB struct field offsets (64-bit `_URB_CONTROL_VENDOR_OR_CLASS_REQUEST`)

| offset | field | type |
|---|---|---|
| +0x00 | `Hdr.Length` / `Hdr.Function` | u16 / u16 |
| +0x20 | `TransferFlags` | u32 |
| +0x24 | `TransferBufferLength` | u32 |
| +0x28 | `TransferBuffer` | ptr |
| +0x30 | `TransferBufferMDL` | ptr |
| +0x38 | `UrbLink` | ptr |
| +0x80 | `RequestTypeReservedBits` | u8 |
| +0x81 | `Request` (bRequest) | u8 |
| +0x82 | `Value` (wValue) | u16 |
| +0x84 | `Index` (wIndex) | u16 |

URB function codes seen in the headers: `0x0018` = `URB_FUNCTION_VENDOR_INTERFACE`,
`0x001b` = `URB_FUNCTION_CLASS_INTERFACE`.

`wIndex` is sourced from the device extension's saved interface descriptor: the
device-start routine (`0x140007aff`, reads config descriptor, type byte `0x22`,
0x5c0 bytes) stores parsed interface-descriptor pointers in an array at
`[dev+0x550]` (selected vs `[dev+0x558]` by the alt-count at `[dev+0x424]==4`;
indexed elsewhere as `[dev + idx*8 + 0x550]`). Offsets +2/+3 of a
`USB_INTERFACE_DESCRIPTOR` are `bInterfaceNumber` / `bAlternateSetting`.

## 3. VENDOR_SET handler @ `0x1400051d4` (the target)

Input buffer `rdi = Irp->AssociatedIrp.SystemBuffer`; `ebx = InputBufferLength`.

```
0x1400051d4: mov   ebx, [rdx+0x10]            ; ebx = InputBufferLength
0x1400051e0: cmp   ebx, 3 / jb fail          ; require >= 3 bytes
... ExAllocatePool2(0x88,'USBP') -> rdx (URB) ...
0x14000521d: movzx r8d,[rdi+1]               ; inBuf[1]
0x140005222: movzx eax,[rdi+2]               ; inBuf[2]
0x140005226: movzx r9d,[rdi]                 ; inBuf[0]
0x14000522a: shl   r8w, 8 / or r8w, ax       ; r8w = (inBuf[1]<<8) | inBuf[2]
0x140005233: ...   rax = [dev+0x550]/[+0x558]  (iface descriptor)
0x14000524d: movzx ecx,[rax+2] ; movzx eax,[rax+3]
0x140005255: shl   cx, 8 / or cx, ax         ; cx = (ifDesc[2]<<8) | ifDesc[3]
0x14000525c: mov   [rdx+0x82], r8w           ; wValue = (inBuf[1]<<8) | inBuf[2]
0x140005264: mov   [rdx+0x84], cx            ; wIndex = (bInterfaceNumber<<8)|bAltSetting
0x14000526f: mov   dword [rdx], 0x180088     ; Function=0x0018 VENDOR_INTERFACE, Len=0x88
0x140005278: mov   [rdx+0x24], ebx           ; TransferBufferLength = InputBufferLength
0x14000527b: mov   [rdx+0x30], 0             ; TransferBufferMDL = NULL
0x14000527f: mov   [rdx+0x28], rdi           ; TransferBuffer = SystemBuffer (WHOLE inBuf)
0x140005283: mov   byte [rdx+0x80], 0        ; RequestTypeReservedBits = 0
0x14000528a: mov   byte [rdx+0x81], r9b      ; Request (bRequest) = inBuf[0]
0x140005291: mov   dword [rdx+0x20], 0       ; TransferFlags = 0  -> OUT (host->device)
0x140005295: mov   [rdx+0x38], 0             ; UrbLink = NULL
```

**It is a control transfer (`_URB_CONTROL_VENDOR_OR_CLASS_REQUEST`), NOT a bulk
transfer.** Mapping:

* Function `0x0018` = `URB_FUNCTION_VENDOR_INTERFACE` → type=vendor, recipient=interface.
* `TransferFlags = 0` → `USBD_TRANSFER_DIRECTION_IN` bit clear → **OUT** (host→device).
* `bRequest = inBuf[0]`.
* `wValue = (inBuf[1] << 8) | inBuf[2]`.
* `wIndex = (bInterfaceNumber << 8) | bAlternateSetting` (= 0x0000 for the 12fe iface 0/alt 0).
* **OUT data stage = the ENTIRE InputBuffer** (`TransferBuffer = SystemBuffer`,
  `TransferBufferLength = InputBufferLength`). usbprint does **not** strip
  `inBuf[0..2]`; the same bytes that seed bRequest/wValue **remain** at the head of
  the data payload.

## 4. VENDOR_GET worker @ `0x1400026e0` (mirror; confirms the read mapping)

Identical field assignments to SET, differing only in direction + length:

```
0x14000278f: mov   [r14+0x81], dl            ; Request = inBuf[0]
0x140002796: mov   [r14+0x84], cx            ; wIndex  = (bInterfaceNumber<<8)|bAlt
0x1400027a0: mov   [r14+0x82], r8w           ; wValue  = (inBuf[1]<<8) | inBuf[2]
0x1400027ad: mov   dword [r14], 0x180088     ; Function 0x0018 VENDOR_INTERFACE
0x1400027b7: mov   [r14+0x24], edi           ; TransferBufferLength = OutputBufferLength
0x1400027c1: mov   [r14+0x28], r15           ; TransferBuffer = SystemBuffer (reused for OUT data)
0x1400027cc: mov   dword [r14+0x20], 3       ; TransferFlags = IN | SHORT_TRANSFER_OK -> IN
```

→ vendor / interface / IN ⇒ **bmRequestType=0xC1**, `bRequest=inBuf[0]`,
`wValue=(inBuf[1]<<8)|inBuf[2]`. For the confirmed get_version inBuf `8a 00 00`
this yields `0xC1 / 0x8a / wValue=0x0000 / wIndex=iface`, **exactly the confirmed
ground truth** (byte-exact native reply `e790c184…`).

## 5. GET_1284_ID helper @ `0x140001ca0` (decode sanity cross-check)

```
0x140001d0c: mov   dword [rbx], 0x1b0088     ; Function=0x001b CLASS_INTERFACE, Len=0x88
            ; Request @0x81 NOT written -> 0 (GET_DEVICE_ID) ; Value @0x82 NOT written -> 0
0x140001d35: mov   [rbx+0x84], si  (si=ifDesc[2]<<8)  ; wIndex = bInterfaceNumber<<8
0x140001d3c: mov   dword [rbx+0x20], 3       ; TransferFlags = IN | SHORT_OK
```

→ class / interface / IN ⇒ **bmRequestType=0xA1**, `bRequest=0x00`, `wValue=0x0000`,
`wIndex=iface` — **exactly the confirmed GET_1284_ID mapping**, proving the
field-offset reading in §2–§4 is correct.

## 6. bmRequestType assembly (how USBD turns {Function, TransferFlags} into the setup byte)

```
type      : VENDOR_* (0x18) -> 0x40 (vendor)    ; CLASS_* (0x1b) -> 0x20 (class)
recipient : *_INTERFACE     -> 0x01 (interface)
direction : TransferFlags & USBD_TRANSFER_DIRECTION_IN(0x1) ? 0x80 : 0x00
```

| IOCTL | Function | TransferFlags | bmRequestType | status |
|---|---|---|---|---|
| GET_1284_ID | 0x1b CLASS_INTERFACE | 3 (IN) | **0xA1** | CONFIRMED |
| VENDOR_GET | 0x18 VENDOR_INTERFACE | 3 (IN) | **0xC1** | CONFIRMED |
| **VENDOR_SET** | **0x18 VENDOR_INTERFACE** | **0 (OUT)** | **0x41** | **DERIVED** |

## 7. Exact native transfers for the target frames

12fe service-mode device = single printer-class interface, iface 0 / alt 0 ⇒
`wIndex = 0x0000`. All three target frames carry arg bytes `00 00` ⇒
`wValue = 0x0000`.

| frame | native control transfer |
|---|---|
| set_session `81 00 00 03 2d 2d ba 2b` | **OUT** bmRequestType=**0x41** bRequest=**0x81** wValue=**0x0000** wIndex=**0x0000** data = **`81 00 00 03 2d 2d ba 2b`** (all 8 bytes) |
| set_command `85 00 00 00 00 10 07 7c 40 40 8f ec` | **OUT** bmRequestType=**0x41** bRequest=**0x85** wValue=**0x0000** wIndex=**0x0000** data = **`85 00 00 00 00 10 07 7c 40 40 8f ec`** (all 12 bytes) |
| set_command `85 00 00 00 00 0d 00 00 40 40 8f ec` | **OUT** bmRequestType=**0x41** bRequest=**0x85** wValue=**0x0000** wIndex=**0x0000** data = **`85 00 00 00 00 0d 00 00 40 40 8f ec`** (all 12 bytes) |

For the reads (sanity): get_keyword `82 …` → **IN** 0xC1/0x82/0/0; get_command
`86 …` → **IN** 0xC1/0x86/0/0; the 3-byte prefix supplies bRequest+wValue and the
read length is the OutputBufferLength.

## 8. Agreement / contradiction with the naive symmetric guess

The derived setup **agrees** on the setup-packet fields the other lane already
tried: `bmRequestType=0x41`, `bRequest=0x81` (set_session), `wValue=0x0000`,
`wIndex=0x0000`. So the symmetric guess was structurally right.

It **contradicts the data-stage handling**, which is why every split STALLed:

* usbprint puts the **WHOLE InputBuffer** into the OUT data stage
  (`TransferBuffer = SystemBuffer`, `TransferBufferLength = InputBufferLength`).
  It does **not** strip the 3-byte `[cmd][arg_hi][arg_lo]` prefix. `inBuf[0]` is
  used for `bRequest` **and is still the first data byte**; `inBuf[1..2]` seed
  `wValue` **and are still data bytes 2–3**.
* The other lane tried "various data splits of the frame" (treating part of the
  frame as setup-only and sending a stripped remainder as data). Any such split
  presents the device with a different number of data bytes / different payload
  than firmware expects for that `wLength`, so the control endpoint protocol-stalls
  (libusb "Pipe error"). The fix is to send the frame **verbatim** as the data
  stage with `wLength = len(frame)` — never strip the prefix.
* Bulk-OUT to EP 0x01 timed out because the SET path is **not** a bulk transfer at
  all; it is the EP0 vendor control-OUT above. (`URB_FUNCTION_VENDOR_INTERFACE`,
  not `URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER`.)

### Endianness caveat (wValue)

The decompile is explicit: `wValue = (inBuf[1] << 8) | inBuf[2]` (inBuf[1] is the
HIGH byte). Both confirmed captures used arg bytes `00 00` and cannot disambiguate
the order, and all three target SET frames also carry `00 00`, so `wValue = 0x0000`
regardless. If a future frame carries non-zero arg bytes, follow the decompiled
`(hi=inBuf[1], lo=inBuf[2])` order. (Note this is the *opposite* byte order from the
informal "wValue = inBuf[1] | inBuf[2]<<8" note in the task brief — the binary is
ground truth; the brief's note was an undisambiguated guess.)

## 9. Native implementation

Drafted (not yet wired into existing code) at
`src/canon_megatank/protocol/servicemode_transport.py`:
`ServiceModeTransport` is a `WicSessionDevice` that wraps an injected
`control_transfer` callable (e.g. `usb.ClaimedDevice.control_transfer`) and issues
the §6/§7 transfers — `send_command` → VENDOR_SET control-OUT (whole frame as
data), `send_and_receive`/`read_response` → VENDOR_GET control-IN, plus a
`read_1284_id` helper. It owns no USB handle and is unit-shaped; it drives
`ops.reset_absorber_wicreset` in dry-run with a recording fake (verified). It must
NOT be run against `04a9:12fe` until the SSOT promotes
`absorber_reset.status` past `derived-unvalidated` (the existing gate stack still
applies).
```
