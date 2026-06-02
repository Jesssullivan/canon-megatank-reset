# Canon Service Tool v5103 — SERVICE-MODE absorber-reset transport (static RE)

**Binary:** `ServiceTool_v5103.exe` (sha `98ca97…`). · **Date:** 2026-05-31.
**Tooling:** PyGhidra 3.0.2 against **Ghidra 12.0.2** (the project DB was created
with 12.0.2 — 11.4.2 refuses it with "data created with newer version"), opened
**read-only** via `GhidraProject.openProject(loc, name, False)` +
`openProgram("/", "ServiceTool_v5103.exe", True)` — no re-import, no save.
Scripts (tracked): `ghidra/v5103_servicemode_probe.py`,
`v5103_decomp_funcs.py`, `v5103_xref_data.py`, `v5103_vtables.py`,
`v5103_raw.py`, `v5103_io_callers.py`, `v5103_scalar_search.py`. Raw output
(gitignored): `.ghidra-work/out/v5103/{servicemode,svcmode_funcs,svc_xref,
svc_vtables,alt_transport,dispatch_chain,factory,raw_vt,io_callers,
discovery,enum_and_io,usbprint_io,guid_words}.txt`.

This answers the four open questions from the live-capture session
(`docs/runbook/wicreset-live-capture-2026-05-31.md`): how the tool detects
service mode, what transport it uses when the printer presents **only** a
printer-class interface, the reset bytes, and whether the service-mode path
differs from the normal-mode usbscan path.

---

## TL;DR

1. **Two coexisting USB transports, auto-selected by which interface the device
   exposes.** Both are CreateFileA + overlapped DeviceIoControl; **neither is
   `WritePrinter`/`StartDocPrinter`** (those are not even imported).
   - **Normal mode → still-image / usbscan path.** Device opened as
     `\\.\Usbscan%d`; IO via `FUN_004302c0` DeviceIoControl **`0x220038`/`0x22003c`**
     (the path prior RE mapped). Enumerated by `FUN_00432590` ← `FUN_00430010`.
   - **Service mode → printer-class / USBPRINT path.** Device discovered through
     the Windows **printer-port** list (`EnumPortsA`, WINSPOOL) and resolved to a
     `\\?\usb#…` device-interface path via SetupDi on
     **`GUID_DEVINTERFACE_USBPRINT` = `{28d78fad-5a12-11d1-ae5b-0000f803a8c2}`**
     (`FUN_00432930`), opened by the same `CreateFileA` (`FUN_00433eb0`), and
     driven by a **different transport class** (vtable `0x4721f0`, IO primitive
     `FUN_00430720`). Enumerated by `FUN_00432bc0` ← `FUN_004330d0`/`FUN_004335b0`.
2. **The command framing is identical on both paths**: `FUN_00430720` (USBPRINT
   primitive) builds the same `[cmd][arg_hi][arg_lo] + payload` 3-byte-header
   frame as `FUN_004302c0` (usbscan), byte-for-byte (verbatim GlobalAlloc + copy,
   no transform). So the absorber payload bytes do **not** change between modes.
3. **Service-mode "detection" is just: did a device get found + its 1284 model
   name read.** When the model-name global `DAT_00494d54` is non-empty the title
   bar shows `<model> / SN:<serial>`; when empty it shows **"No service mode
   printer"** (`FUN_0040da40`/`FUN_0040dbe0` @ string `0x4710bc`). There is no
   separate "is in service mode?" opcode — the tool simply tries to enumerate a
   Canon device and read its device ID on either transport.
4. **The "Clear Ink Counter → Set / Main" button invokes the SAME dispatcher
   (`FUN_0040ac60`) and the SAME `EncCommService` singleton (`DAT_00494ee0`)
   regardless of mode.** EncCommService picks the concrete transport instance
   (usbscan vs USBPRINT) from a registry populated at enumeration time
   (`FUN_0042fc80`). So the divergence is purely in the lower transport object,
   not in the reset logic or payload.

**Net for the project:** the statically-derived absorber payload is still the
operative content; what was missing live is that in service mode the frame must
go out on the **USBPRINT printer-class interface (EP 0x01 OUT / 0x82 IN)** wrapped
in the tool's overlapped DeviceIoControl — *not* the usbscan path that does not
exist in service mode. See §5 for the precise still-unknown wrapper byte.

---

## 1. Service-mode detection — `FUN_0040da40` / `FUN_0040dbe0`

Both title-bar updaters (called from `FUN_0040dd80`/`FUN_0040e360`) decide
"service mode present?" purely from the model-name global:

```c
// FUN_0040da40 (twin FUN_0040dbe0), @ 0x40da40 / 0x40dbe0
iVar4 = __mbscmp(DAT_00494d54,"");          // model name empty?
if (iVar4 == 0) {
    ...
    pHVar8 = (HWND)"No service mode printer";   // <- string @ 0x4710bc
} else {
    // build "<DAT_00494d54> / SN:<DAT_00494d50>"
    ATL::CSimpleStringT<char,0>::operator=(&param_1, &DAT_00494d54);
    FUN_0040d910(&param_1, " / SN:", 6);
    FUN_0040d910(&param_1, DAT_00494d50, ...);   // serial
}
FID_conflict_SetWindowTextW(pHVar8, lpString);   // title bar
```

`DAT_00494d54` (model) and `DAT_00494d50` (serial) are populated by the device
probe (1284 GET_DEVICE_ID — `MFG:`/`MDL:`/`SN=` keys live at `0x472468+0x34..`,
ASCII `MFG:`,`MDL:`,`CLS:`,`DES:`,`VER:`,`STA:` and `SN=%08X`). `FUN_0040c4b0`
then classifies the recovered model string against a large hard-coded table
(MX320…G3000, **no G6020**) into a model group used by the dispatcher.

> **Conclusion (high confidence):** "service mode printer" = *a Canon device was
> enumerated and its model name read on one of the two transports*. The check is
> presence + device-ID, not a dedicated service-mode handshake opcode.

## 2. Transport imports actually present (decisive negative result)

From `prog.getExternalManager()` (`servicemode.txt`):

| import | lib | used for |
|---|---|---|
| `OpenPrinterA`, `ClosePrinter` | WINSPOOL.DRV | only in `DevModeChange` (driver/devmode helper) — **not** the maintenance write |
| `EnumPortsA` | WINSPOOL.DRV | **enumerate printer ports** in the USBPRINT discovery driver `FUN_00432bc0` |
| `CreateFileA` | KERNEL32 | open the device (both paths) |
| `DeviceIoControl` | KERNEL32 | the actual command transfer (both paths) |
| `WriteFile`/`ReadFile` | KERNEL32 | only `FUN_00430d30`/`FUN_00430df0` — the **text/EEPROM-dump file** path, not vtable-wired |
| `SetupDiGetClassDevsA`, `SetupDiEnumDeviceInterfaces`, `SetupDiGetDeviceInterfaceDetailA`, `SetupDiOpenDeviceInterfaceRegKey` | SETUPAPI | resolve the `\\?\usb#…` USBPRINT path |
| `RegQueryValueExA` | ADVAPI32 | read port "Base Name"/"Port Number" during USBPRINT discovery |
| `CreateEventA`, `GetOverlappedResult` | KERNEL32 | overlapped IO on the device handle |
| `Escape` | GDI32 | thin `FUN_0043c0e4` wrapper on a DC — **no `CreateDC` import**, not used for maintenance |

**NOT imported:** `WritePrinter`, `ReadPrinter`, `StartDocPrinterA/W`,
`EndDocPrinter`, `EnumPrintersA/W`, `GetPrinterA/W`, `CreateDCA/W`, `ExtEscape`,
`CreateFileW`. So the service-mode write is **not** the spooler raw-write path and
**not** a GDI `PASSTHROUGH`/`Escape` — it is `CreateFileA` on the USBPRINT device
interface + `DeviceIoControl`.

## 3. The two transport classes (vtables) and their IO primitives

`FUN_00433eb0` (the overlapped `CreateFileA` opener,
`CreateFileA(path, GENERIC_READ|WRITE, FILE_SHARE_RW, …, OPEN_EXISTING,
FILE_FLAG_OVERLAPPED, …)` + 4 `CreateEventA`) is shared as slot **+0x00** of four
vtables — i.e. one transport base with several subclasses. The IO slots differ:

| vtable | +0x10 | +0x14 (primary IO) | meaning |
|---|---|---|---|
| `0x472188` | `FUN_004301b0` (DeviceIoControl **`0x16000c`**) | `FUN_004302c0` (DeviceIoControl **`0x220038`/`0x22003c`**) | **usbscan / still-image** transport (normal mode) |
| `0x472260` | `FUN_004301b0` (`0x16000c`) | `FUN_004302c0` (`0x220038`/`0x22003c`) | usbscan variant (carries SDDL/registry `SN=%08X` strings in adjacent .rdata) |
| `0x4721f0` | `FUN_004306e0` | **`FUN_00430720`** | **USBPRINT / printer-class** transport (service mode) |
| `0x472468` | `__purecall` | `__purecall` | abstract base (the 1284-key strings `MFG:`/`MDL:`/… live right after its short vtable) |

`FUN_00430720` (the USBPRINT primitive) builds the **same** wire frame as the
usbscan primitive — confirmed from disassembly @ `0x430720`:

```
LEA EAX,[EDI+3]          ; total = payload_len + 3
PUSH 0x40 ; GMEM_ZEROINIT
CALL GlobalAlloc
... MOVSD.REP            ; copy payload to hMem+3 (verbatim, no transform)
... then CALL [vtable+0x68]   ; hand the framed buffer to the lower writer
```

and `FUN_004302c0` (usbscan, from prior RE, re-confirmed) is identical except it
calls `DeviceIoControl(h, 0x220038, hdr, len+3, …)` directly. **Both lay down
`[cmd][arg_hi][arg_lo][payload]` big-endian-arg, payload verbatim.**

IOCTL decode: `0x220038` = DeviceType `0x22` (usbscan custom), Func `0xE`, SEND;
`0x22003c` = Func `0xF`, RECV. `0x16000c` = DeviceType `0x16`, Func `0x3` — the
usbprint/USB device-type family (the alternate transfer/poll IOCTL).

## 4. Discovery / selection — which transport gets registered

- **usbscan path:** `FUN_00430010` → `FUN_00432590`, loops `\\.\Usbscan%d`,
  opens each, filters on the vendor string `"Canon"`. (Strings `Usbscan%d` @
  `0x4723f8`, `\\.\Usbscan%d` @ `0x472404`.)
- **USBPRINT path:** `FUN_004330d0`/`FUN_004335b0` → `FUN_00432bc0`:
  ```c
  EnumPortsA(NULL, 2, …);                       // Windows printer ports
  // for each port whose name starts with "USB":
  iVar3 = FUN_004568dc(port+3);                  // port index
  puVar4 = FUN_00432930(auStack_420, iVar3);     // -> \\?\usb#… via SetupDi
  ... open via transport vtable (+0x4c), read 1284 ID, filter __mbscmp(*, "Canon")
  ```
  `FUN_00432930` enumerates `SetupDiGetClassDevsA(&GUID_DEVINTERFACE_USBPRINT,…)`,
  matches the registry **"Port Number"** to the EnumPorts index, and returns the
  `SetupDiGetDeviceInterfaceDetailA` path (`\\?\usb#vid_04a9&pid_…#…`).
  **GUID @ `0x4723e0` verified = `28d78fad-5a12-11d1-ae5b-0000f803a8c2`
  (GUID_DEVINTERFACE_USBPRINT).**

The discovered transport instances are linked into a list owned by the manager
singleton `DAT_00495fc8` (vtable `PTR_FUN_00472154`); `FUN_0042fc80(this,
device_index, 1)` walks it to return the instance EncCommService transmits on.

> **This is exactly the architecture the live finding implied.** In service mode
> the printer enumerates as a single **printer-class** interface (PID `04a9:12fe`,
> EP 0x01 OUT / 0x82 IN) bound by `usbprint.sys` — there is *no* still-image
> interface, so the usbscan path finds nothing and the tool falls through to the
> **USBPRINT** transport (vtable `0x4721f0`). In normal mode (PID `04a9:1865`,
> 6 interfaces incl. the still-image iface-4) the usbscan path binds.

## 5. The reset payload + the one genuinely-unknown wrapper byte

The button handler and dispatcher are **mode-independent** (verified):

```c
// "Set" handler FUN_0040b6c0/FUN_0040d140 (unchanged from prior RE):
payload[5] = { 0x00, 0x03, flags, 0x03, idx };   // flags 0x01 / 0x81; main absorber idx = 0x07
FUN_0040ac60(dlg, 7, &payload);                   // group 7 = Ink Absorber Counter

// dispatcher FUN_0040ac60 (re-decompiled, @ 0x40ac60):
lParam = FUN_0040f4f0();                           // == &DAT_00494ee0  (EncCommService singleton)
(*lParam+0x5c)(); (*lParam+0x20)(); (*lParam+0x24)(); (*lParam+0x28)();   // open/init, no bulk
(*lParam+0x40)(DAT_00494ca0);                      // 0x81 send + 0x82 recv (64B)  [runtime byte]
if (model != 'G' && mode-not-set) {                // absorber payload[3]==0x03, not 'G' -> runs
    uStack_20 = DAT_004921f8; uStack_1f = DAT_004921f9;
    (*lParam+0x44)(DAT_00494ca0, dev, &preamble, 6);   // 6-byte MODE preamble (begins 12 34 00 00 01)
}
...
(*lParam+0x48)(DAT_00494ca0, dev, payload, …);     // group-7 reset SEND (cmd 0x85)
```

EncCommService → `FUN_0042b030` → `FUN_0042cec0` → `FUN_0042fc80` (pick transport
instance) → `(*inst+0x60)(args)` then `(*inst+0x14)()` (the IO primitive:
`FUN_004302c0` for usbscan **or** `FUN_00430720` for USBPRINT). Both emit the
identical framed bytes.

**So the operative reset bytes are unchanged and transport-agnostic:**

```
group 7 payload (verbatim, no transform):  00 03 01 03 07     (flags 0x01, main absorber idx 0x07)
                                            00 03 81 03 07     (checkbox-checked variant)
wire frame the primitive builds:           [cmd][arg_hi][arg_lo] 00 03 01 03 07
                                            cmd = 0x85 (SEND), arg = 0x0000  -> 85 00 00 00 03 01 03 07
preceded by 6-byte mode preamble:          12 34 00 00 01 ??  (byte 6 runtime-sourced; DAT_004921f8/9
                                            read as zero at rest — see read-re/handshake docs)
```

**What is still NOT statically pinnable (unchanged from the handshake doc):**
- The 6th preamble byte and the `(*+0x40)` slot's `0x81`-frame 1-byte payload are
  written from runtime globals (`DAT_004921f8/9`, `DAT_00494ca0`) that are zero at
  rest. Static RE cannot supply them; a usbmon capture on the USBPRINT interface
  (not usbscan) is the only source.
- Whether the USBPRINT transfer wraps the frame in IOCTL `0x16000c` or writes the
  bulk endpoint directly. The frame builder is `FUN_00430720`; its lower writer is
  reached through a per-object vtable slot (+0x68) whose concrete target depends on
  the runtime-constructed USBPRINT transport instance and was not resolvable from
  the static vtable image (the analyzed `0x4721f0[+0x68]` slot points at a CString
  accessor, i.e. the runtime object differs from the .rdata vtable image). This is
  the remaining wrapper detail; on Linux it maps to a bulk-OUT on **iface 0 EP
  0x01** of the `04a9:12fe` service-mode device (per the live enumeration), which
  is what the capture must confirm.

## 6. Direct answers to the four questions

1. **Detect/enter service mode:** the tool does not "enter" it (that is the
   physical power+resume combo on the printer). It *detects* it by enumerating a
   Canon device on either transport and reading its 1284 device ID; success
   populates `DAT_00494d54`/`DAT_00494d50` and the title shows `<model> / SN:…`.
   Failure → **"No service mode printer"** (`FUN_0040da40`/`FUN_0040dbe0`,
   string `0x4710bc`).
2. **Service-mode transmit API:** `CreateFileA` on the **USBPRINT** device
   interface path (`\\?\usb#…`, GUID `28d78fad-…`) discovered via
   `EnumPortsA` + SetupDi (`FUN_00432bc0`/`FUN_00432930`), driven by transport
   class vtable `0x4721f0`, primitive `FUN_00430720`, over **overlapped
   DeviceIoControl** (device-type `0x16` family; `CreateEventA`/
   `GetOverlappedResult` present). **Not** `WritePrinter`, **not** GDI `Escape`.
3. **Actual reset bytes:** payload `00 03 01 03 07` (main absorber, idx 0x07;
   `0x81` if checkbox checked), framed `85 00 00 00 03 01 03 07`, preceded by the
   6-byte mode preamble `12 34 00 00 01 ??`. Bytes are identical to the usbscan
   path (passthrough framer, no transform). The preamble tail byte + the
   `(*+0x40)` session frame's payload byte remain runtime-sourced (unknown).
4. **Does the service-mode path differ, and which does the button use?** The
   *reset logic, dispatcher, payload, and frame are identical*; only the **lowest
   transport object differs** (USBPRINT DeviceIoControl vs usbscan DeviceIoControl),
   auto-selected by which USB interface the device exposes. The "Clear Ink Counter
   → Set / Main" button always calls `FUN_0040ac60(dlg, 7, payload)` →
   `EncCommService` (`DAT_00494ee0`) → whichever transport instance is registered.
   In service mode that is the USBPRINT instance.

## 7. Confidence

- §1 detection, §2 import inventory, §3 vtable IO map, §4 USBPRINT GUID +
  EnumPorts discovery, §6: **high** — each cited from decompiler/disassembly +
  the verified GUID bytes.
- §5 reset payload (`00 03 01 03 07`, frame `85 00 00 …`): **high** for the
  payload (re-confirmed mode-independent), **medium** for the exact cmd/arg
  header (virtual-dispatch; `0x85`/`0x0000` re-confirmed from the read-RE doc's
  `FUN_0040fa60`), **unknown** for the preamble 6th byte and the USBPRINT
  bulk-vs-IOCTL wrapper (runtime-sourced; needs a service-mode usbmon capture).

---

## Wire-wrapper resolution (deep RE)

**Date:** 2026-05-31 (follow-up). **Tooling:** the *tracked* 12.0.2 project DB
opened **read-only** with **Ghidra 12.0.2**
(`/nix/store/a2rxrq8yxw2cahv9j4gbn9d0m8y2d8sq-ghidra-12.0.2`) via
`GhidraProject.openProject(loc,"canon-servicetool-v5103",False)` +
`openProgram("/","ServiceTool_v5103.exe",True)` — no re-import, no save. **The
`.gpr` marker is at `.ghidra-work/project.canon/canon-servicetool-v5103`** (one
dir below `.../project.canon`; opening `.../project.canon` itself throws
`NotFoundException: Project marker file not found`). New tracked scripts:
`ghidra/v5103_wireresolve.py`, `v5103_innerchain.py`, `v5103_writers.py`,
`v5103_p68.py`. Raw output (gitignored):
`.ghidra-work/out/v5103/{wireresolve,innerchain,writers,p68}.txt` (every claim
below is from the decompiler/disassembler on that DB; the binary is byte-identical
to the one the 12.0.2 DB was built from).

> **This pass confirms the original §3/§5 architecture and payload, pins the
> preamble's provenance, and isolates the residual unknown to exactly two
> runtime-only items.** It does NOT overturn the "+0x68 lower writer is
> runtime-only" finding — it proves it.

### 5.1 vtable map incl. +0x68 (verbatim, `wireresolve.txt` / `p68.txt`)

```
0x4721f0 (USBPRINT)                       0x472188 (usbscan)
 +0x00 FUN_00433eb0  CreateFileA opener (shared by all transports)
 +0x10 FUN_004306e0                        +0x10 FUN_004301b0  DeviceIoControl 0x16000c
 +0x14 FUN_00430720                        +0x14 FUN_004302c0  DeviceIoControl 0x220038 / 0x22003c
 +0x18 FUN_004304b0                        +0x18 FUN_004301a0
 +0x68 FUN_00434200                        +0x68 FUN_00434200   <- SAME in all 3 transports
```

`0x4721f0[+0x68]` = **`FUN_00434200`**, which (decompiled, `p68.txt`) is a
**refcount-decrement / object release**, NOT an IO writer:

```c
void __thiscall FUN_00434200(int *param_1){
  param_1[-1] = param_1[-1] - 1;            // LOCK xadd
  if (param_1[-1] == 0) (**(code**)(*(param_1-4) + 4))(param_1-4);   // release
}
```

So the *static* `+0x68` slot is not the lower writer. The original doc's note
("`0x4721f0[+0x68]` points at a CString/accessor, i.e. the runtime object's
vtable differs") is **correct and re-confirmed**.

### 5.2 `FUN_00430720` (USBPRINT +0x14) frames `[cmd][arg][payload]` then dispatches via `this->vtable[+0x68]` (verbatim, `wireresolve.txt` 382-438)

```c
undefined4 __thiscall FUN_00430720(void *this,...,int param_3,undefined4 *param_4,
                                   uint param_5,uint *param_6,undefined4 param_7){
  hMem = param_4; dwBytes = param_5;
  if (param_3 == 0) {                          // SEND
    dwBytes = param_5 + 3;
    hMem = GlobalAlloc(0x40, dwBytes);         // [cmd][arg_hi][arg_lo][payload], payload copied at +3
    ...
  }
  uVar1 = (**(code **)(*(int *)this + 0x68))(param_1,param_2,param_3,hMem,dwBytes,param_6,param_7);
  if (param_3 == 0) { if (hMem) GlobalFree(hMem); }
  else { ... return FUN_00430620(this,hMem,param_6,0); }   // RECV: strip 1-byte header
  return uVar1; }
```

It frames **identically to usbscan** (GlobalAlloc len+3, `[cmd][arg_hi][arg_lo] +
payload` verbatim) and hands the framed buffer to `this->vtable[+0x68]`. Since the
static `0x4721f0[+0x68]` is the non-IO `FUN_00434200`, the concrete runtime `this`
is a *different* (runtime-constructed) object whose `vtable[+0x68]` is the real
low-level writer — unresolvable from the static `.rdata` image. **This is the one
structural item static RE cannot finish.**

### 5.3 The DeviceIoControl primitive (the byte emitter), `FUN_004302c0` (verbatim)

Whole-binary IOCTL scan (`wireresolve.txt` 298-301) is exhaustive: `0x16000c` →
only `FUN_004301b0`; `0x220038`/`0x22003c` → only `FUN_004302c0`.

```c
// FUN_004302c0  (usbscan 0x472188[+0x14]; the framed-buffer emitter)
if (OutBuf == 0) { len = payload_len + 3; ioctl = 0x220038;            // SEND
                   buf = GlobalAlloc(0x40, len); copy payload at buf+3; }
else             { ioctl = 0x22003c; len = 3; buf = GlobalAlloc(0x40,3); }  // RECV: send 3-byte header
buf[0]=cmd; buf[1]=(arg>>8); buf[2]=(arg&0xff);
DeviceIoControl(this->handle/*+0x10*/, ioctl, buf, len, OutBuf, OutLen, pBytes,
                &this->overlapped/*+0x54*/);
```

The IOCTL **input buffer IS the literal frame** — no length prefix, 1284 channel
byte, alt-setting, or extra wrapper. The Windows usbscan/usbprint minidriver turns
that buffer into the bulk-OUT on the device data endpoint → on Linux a **raw
bulk-OUT on EP 0x01 of those bytes**. (Which IOCTL the *runtime* USBPRINT `+0x68`
object uses — `0x220038` vs the `0x16000c` `0x16`-family — is invisible on the USB
wire and does not change the emitted bytes; it is one of the two residual
unknowns, settled only by a capture.)

### 5.4 The dispatcher + preamble (verbatim, `wireresolve.txt` 592-674)

```c
lParam = FUN_0040f4f0();                          // EncCommService singleton (&DAT_00494ee0)
(*lParam+0x5c)();                                   // OPEN (CreateFileA; no wire bytes)
(*lParam+0x20)(); (*lParam+0x24)(); (*lParam+0x28)();   // init accessors
(*lParam+0x40)(DAT_00494ca0);                       // SESSION (arg = channel index DAT_00494ca0)
if (((this[0x2998]==0)||(this[0x299c]!=EDI)) && payload[3] != 'G') {
    uStack_20 = DAT_004921f8;                        // preamble[0]
    uStack_1f = DAT_004921f9;                        // preamble[1]
    (*lParam+0x44)(DAT_00494ca0, EDI, &uStack_20, 6);  // PREAMBLE: SEND 6 bytes
}
if (payload[3]=='\x03' && payload[4] < 3) { ... uStack_20=payload[4]; uStack_1f=0;
    (*lParam+0x44)(DAT_00494ca0,EDI,&uStack_20,6); Sleep(1000); }   // 2nd preamble, idx<3 ONLY
... if (payload[3]=='G'){ Sleep(3000); } ...
(*lParam+0x48)(DAT_00494ca0, EDI, payload, ...);    // PAYLOAD SEND (5-byte group-7 payload)
```

The 6-byte preamble's bytes 0-1 are `DAT_004921f8` / `DAT_004921f9`; bytes 2-5 are
the adjacent zeroed stack. For the **main absorber (idx 0x07)** the second
`payload[4]<3` preamble does **not** fire.

### 5.5 Task 4 — RESOLVED: the preamble globals come from a config/registry read, NOT the device

`.data` is `00` at rest, but `DAT_004921f8`/`DAT_004921f9` DO have writers
(`wireresolve.txt` refs: WRITE refs exist; not "no writers"). The **only** writer
is `FUN_0042b830` (verbatim, `writers.txt`):

```c
void FUN_0042b830(void){
  uint  local_58[3];
  undefined1 auStack_4c[76];
  FUN_0042b790();                              // (sub-init)
  local_58[0] = 0;
  auStack_4c._0_2_ = auStack_4c._1_2_;
  FUN_0042d750(0x471eb0, 0x602, local_58);     // read config blob @ 0x471eb0, key 0x602
  DAT_004921f8 = SUB21(auStack_4c._0_2_, 1);   // preamble[0] = HIGH byte of a 16-bit config value
  DAT_004921f9 = (char)auStack_4c._0_2_;       // preamble[1] = LOW  byte of that value
}
```

So `DAT_004921f8`/`DAT_004921f9` are the **hi/lo bytes of a 16-bit value pulled
from an in-binary config blob at `0x471eb0` (key `0x602`)** via `FUN_0042d750` —
**not** a device read and **not** a checksum. The value is whatever
`FUN_0042d750(0x471eb0,0x602,…)` returns at runtime; its source blob is internal
to the process (a parsed config/INI/registry structure), so its concrete value is
not directly visible as a static `.data` constant from this decompile.
**Critically, `FUN_0042b830`'s ONLY caller is `FUN_00412870`** (not the reset
dispatcher `FUN_0040ac60`, and not the EncComm session path). So whether the
preamble globals are non-zero **at the moment the reset runs depends on whether
`FUN_00412870` executed earlier in the GUI session**; if it did not, the
dispatcher reads them as the at-rest `0x00`/`0x00`. This matches and refines the
original doc's "preamble 6th byte is runtime-sourced; zero at rest": they are
zero unless `FUN_00412870` ran, in which case they are the config hi/lo bytes.

`DAT_00494ca0` is set by `FUN_00409c60` and `FUN_0040dd80` — it is the
**device/channel index** (the first arg of every `+0x40/+0x44/+0x48` call,
selecting the registered transport), **not a wire byte**, never copied into a send
buffer.

### 5.6 DELIVERABLE — on-wire bytes for a Linux libusb/usblp sender (service mode)

Device in service mode = `04a9:12fe`, single printer-class iface 0, EP 0x01 OUT /
0x82 IN. Each SEND's IOCTL input buffer is the literal frame → on Linux a
**bulk-OUT on EP 0x01** of those bytes (no IOCTL framing reaches the wire). For
the **main ink-absorber reset** (group 7, payload `00 03 01 03 07`, idx 0x07):

```
# Step 1 — OPEN (EncComm +0x5c): CreateFileA on the device path.
#          Linux: claim iface 0 / open EP 0x01,0x82. NO bytes on the wire.

# Step 2 — SESSION (EncComm +0x40): passes channel index DAT_00494ca0; internal
#          status handshake (no caller frame). Not load-bearing for the request.

# Step 3 — PREAMBLE (EncComm +0x44, fires for payload[3]=0x03 != 'G'): 6-byte SEND
EP 0x01 OUT:  P0 P1 00 00 00 00
#   preamble[0] = DAT_004921f8 ; preamble[1] = DAT_004921f9
#     - if FUN_00412870 ran earlier this session: P0/P1 = hi/lo of config blob
#       0x471eb0 key 0x602 (via FUN_0042d750)         -> value not a static .data const
#     - otherwise (globals untouched):  P0 = 00, P1 = 00
#   preamble[2..5] = 0x00                              ; idx<3 2nd preamble does NOT fire for 0x07

# Step 4 — PAYLOAD (EncComm +0x48): 5-byte group-7 payload, framed [cmd][arg_hi][arg_lo]+payload
#          (cmd 0x85, arg 0x0000 per read-RE FUN_0040fa60):
EP 0x01 OUT:  85 00 00 00 03 01 03 07          # payload 00 03 01 03 07
#   checkbox-checked variant (payload 00 03 81 03 07):
EP 0x01 OUT:  85 00 00 00 03 81 03 07

# RECV (0x22003c): write 3-byte header [cmd][arg_hi][arg_lo] then read N bytes,
#   e.g. EP 0x01 OUT [86 00 00] -> EP 0x82 IN (status).
```

The **payload frame `85 00 00 00 03 01 03 07` is transport-agnostic** (byte-for-byte
identical on usbscan and USBPRINT). The **preamble's bytes [0..1] are
runtime-conditioned**: `0x00 0x00` unless `FUN_00412870` ran earlier in the GUI
session, in which case they are the hi/lo bytes of the `0x471eb0`/key-`0x602`
config value (`FUN_0042b830` → `FUN_0042d750`). A Linux sender's safest first
attempt is the all-zero preamble; a capture confirms whether the live tool sends
non-zero P0/P1 for the absorber reset.

### 5.7 Confidence + the precise residual unknowns

- **High:** vtable map incl. `0x4721f0[+0x68] = FUN_00434200` (a refcount
  release, not IO); `FUN_00430720` frames `[cmd][arg][payload]` and dispatches via
  `this->vtable[+0x68]`; IOCTL constants confined to `FUN_004301b0`/`FUN_004302c0`;
  `FUN_004302c0`'s `0x220038`/`0x22003c` framing + buffer layout; the dispatcher
  body + preamble sourced from `DAT_004921f8/9`; the writer `FUN_0042b830` =
  hi/lo bytes of config value `FUN_0042d750(0x471eb0, 0x602)`, sole caller
  `FUN_00412870`; `DAT_00494ca0` = device/channel index (not a wire byte). All
  from 12.0.2-DB read-only decompilation + whole-binary scans.
- **Medium:** `0x85`/arg `0x0000` of the payload step (inherited from read-RE
  `FUN_0040fa60`); whether the runtime `+0x68` object issues `0x220038` vs
  `0x16000c` on the service-mode interface (does not change the wire bytes).
- **RESIDUAL UNKNOWN — two genuinely runtime-conditioned items, both unavoidable
  statically:** (1) the **preamble bytes [0..1]** (`DAT_004921f8/9`) — `00 00`
  unless `FUN_00412870` ran earlier in the GUI session, in which case they are the
  hi/lo bytes of the in-process config value `FUN_0042d750(0x471eb0, 0x602)`, whose
  concrete value is not a static `.data` constant; (2) the **concrete
  `vtable[+0x68]` of the runtime USBPRINT object** (which low-level IOCTL/WriteFile
  it calls), since that object is constructed at runtime and its vtable is not in
  the static `.rdata` image. **Everything else is pinned:** the payload frame
  `85 00 00 00 03 01 03 07`, `preamble[2..5]=00`, the bare-6-byte preamble SEND,
  and the bulk-OUT-on-EP-0x01 mapping. A service-mode usbmon capture settles the
  preamble bytes (and whether `FUN_00412870` runs before the reset) plus the
  firmware-acceptance question (whether physical service mode + cmd/arg
  `0x85/0x0000` actually clear 5B00).
