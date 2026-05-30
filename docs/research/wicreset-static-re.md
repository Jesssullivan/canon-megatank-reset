# WICReset static RE — printerpotty.exe (T2, in progress)

**Date:** 2026-05-29 · **Binary:** `printerpotty.exe` (the real app, Inno-installed
from `PrinterPotty_WICReset.exe`), WICReset v.5.95, PE32 / Intel 80386,
`sha256 a199447db7d9237d95b11456db6e6d9898ab2eb2cae7918acaa1c700a564b3e8`, 7.48 MB.
Binary + Ghidra project are **not** committed (no redistribution).

> First pass via `strings` + import inspection (the custom Ghidra scripts are
> Jython 2.7 and **Ghidra 12 dropped Jython**, so they didn't run — see Tooling).
> Function-level decompile is the next step.

## Architecture

- **wxWidgets C++ app** (RTTI: `wx*`, `PrinterCanonSTD`, `Core::Action*`), with
  **curl statically linked** (curl doc-URL strings, GSSAPI/.netrc/HSTS markers).
- Multi-vendor: handles **Epson and Canon** (`#waste_epson` / `#waste_canon`,
  `EPSON_*_RESET*` vs the Canon class). We care about the Canon path.

## Transport (maps cleanly to our pyusb tool)

Imported DLLs: **`SETUPAPI.dll`** (SetupDi device enumeration — same family as the
Canon Service Tool), **`CreateFileW` + `DeviceIoControl`** (raw device IO),
`WS2_32` + `bcrypt` + `CRYPT32` (network + crypto, the cloud). **No WinUSB/libusb.**

So WICReset: SetupDi-enumerates the printer → opens a device handle with
`CreateFileW` → drives it with `DeviceIoControl`. This is the **same mechanism the
Canon Service Tool uses** (usbscan IOCTL `0x220038`/`0x22003c`, wire frame
`[cmd][arg_hi][arg_lo][payload]` — see `canon-tool-ghidra-notes.md`). On Linux this
maps to **pyusb bulk on interface 4 (OUT `0x03` / IN `0x86`)**, which our native
tool (T5) drives directly (`driver=none`, accessible). This also explains why Wine
couldn't surface the printer — Wine doesn't bridge this SetupDi USB enumeration.

## The functions to decompile (named in RTTI/strings)

| Symbol | Role |
|---|---|
| `PrinterCanonSTD::execute_get_command` (`commands.get_command`, `service.readcmd`) | **read** a counter/EEPROM value |
| `PrinterCanonSTD::clearCounters` → `Core::ActionCanonDeviceClearCounters` → `execute_set_command` (`service.sendcmd`) | **the absorber/waste reset** — primary target |
| `PrinterCanonSTD::execute_set_session` | opens the maintenance session |
| `PrinterCanonSTD::action_is_permitted` | **gating** — checks the key (+ cloud) before a write |
| `Core::ActionCanonDeviceQueryFeatures` / `TestHardLimit` | feature probe / limit check |

Decompiling `execute_get_command` / `execute_set_command` + the `DeviceIoControl`
call site recovers the **IOCTL code + exact command bytes** for read and reset.

## Cloud / key gating ("WIC Reset Connect")

- The reset **key is server-validated**: strings `Check Reset Key`, `Buy reset
  key(s) online`, `Enter reset key here`, `Enter keys here (maximum 100 keys)`,
  plus the bundled curl + `bcrypt`/`CRYPT32` + `WS2_32`, and the runtime msg
  "Remote server is temporarily unavailable or in maintenance mode."
- Implication: a *reset* likely requires a cloud handshake (the single-use key is
  redeemed online). A *read* (`execute_get_command`) appears local (no key) — good
  for the free-read protocol. `action_is_permitted` is where to confirm the gate.
- WICReset **backs up the printer EEPROM before reset** ("Application will backup
  printer's EEPROM now…") — same safety posture as our gate.

## Tooling note (blocker for the decompile step)

Ghidra **12.0.2** (neo, nix) **removed Jython**, so the repo's Jython-2.7 scripts
(`ghidra/*.py`) silently no-op under headless. **Next step:** port the decompile
helpers to **PyGhidra (Python 3)** — Ghidra 12's native scripting — or pin Ghidra
11.4.2. Then decompile the functions above against the saved project
(`.ghidra-work/project/wicreset-printerpotty`, already analyzed).

## Next (T2 → T3)

1. PyGhidra decompile of `execute_get_command`, `execute_set_command`,
   `clearCounters`, `action_is_permitted`, + the `DeviceIoControl` primitive.
2. Recover: IOCTL code(s), the read command bytes, the reset command bytes, the
   key→permit gate, and whether the reset packet is cloud-derived or local.
3. Cross-ref with the Canon Service Tool findings (group 7 absorber payload,
   `[cmd,arg_hi,arg_lo][payload]` framing) → the **T3 formal protocol model**.

---

## T2 progress (2026-05-29 eve): PyGhidra toolchain working; analysis incomplete

**Tooling solved.** Ghidra 12 dropped Jython and routes `.py` to PyGhidra, which
plain `analyzeHeadless` doesn't boot ("Ghidra was not started with PyGhidra").
The working bridge is the **`pyghidra` pip package** driven standalone:

```sh
GHIDRA_INSTALL_DIR=<ghidra-12>/lib/ghidra \
CMR_EXE=.ghidra-work/bin/printerpotty.exe CMR_PROJ=.ghidra-work/project \
CMR_PROJ_NAME=wicreset-printerpotty \
nix shell nixpkgs#jdk21 --command \
  uv run --no-project --with pyghidra python ghidra/pyghidra_xref_decompile.py <out.c> <csv>
```

This **runs** (CMR_START/CMR_DONE) and the byte-search is verified — `flat.findBytes(addr, regex, limit)` finds the exact command strings: `execute_set_command`, `execute_get_command`, `clearCounters`, `ActionCanonDeviceClearCounters`, `service.sendcmd` (1 occurrence each), `Canon` (30), `DeviceIoControl` (2).

**Blocker — the auto-analysis is incomplete.** Despite the strings + the
`DeviceIoControl` import being present, **nothing resolves to a function**:
- `getReferencesTo(string_addr)` → 0 (no wired string refs)
- instruction-operand scan for the string VAs → 0 matches
- `getReferencesTo(DeviceIoControl import)` (+ thunk hop) → 0 caller funcs

So the `-import` default analysis on this 7.5 MB wxWidgets/curl binary did **not**
build the reference graph (likely truncated). The function-level decompile is
blocked on that, not on the script.

### Next step (task #12 follow-on)
1. **Re-analyze fully**: re-run with all analyzers to completion (PyGhidra
   `analyze=True`, ample heap/time), or open interactively and let analysis finish,
   then re-run the anchored decompile (script is ready + reusable).
2. With refs wired, anchor on **`DeviceIoControl` import xrefs** → the single USB
   I/O primitive (as on the Service Tool) → recover the IOCTL code + read/reset
   command bytes; and on `clearCounters`/`execute_set_command` for the dispatch.
3. Feed bytes into the T3 model + native pyusb tool.

The reusable runner is `ghidra/pyghidra_xref_decompile.py` (string-, instruction-,
and import-anchored decompile-by-reference).

### ROOT CAUSE (2026-05-29 late): Ghidra imports but does NOT disassemble printerpotty.exe

Definitive diagnostic (`pyghidra`, opening the analyzed program directly):
`getFunctionCount() == 1`, **0 instructions**, yet the strings are present and the
PE imports parsed (`DeviceIoControl` is an EXTERNAL symbol at `EXTERNAL:000000fa`
with 1 reference from `0x008a0460`; the string sits at `0x0098b108`/`0x009ff40a`).

So **auto-analysis loaded the PE (sections, imports, symbols) but never
disassembled `.text`** — under *both* the 2 GB and 8 GB `-import` runs. Every prior
"0 matches" traces to this: there are no instructions/functions for the string- or
import-anchored search to hook into. (Also fixed a real bug along the way: the
runner must open the existing program *by name*, not by binary path — passing a
path re-imports a fresh, un-analyzed copy.)

**Next step (task #12):** force disassembly, then re-anchor.
1. Open the program and run **"Aggressive Instruction Finder"** + **"Decompiler
   Parameter ID"** analyzers, or issue `DisassembleCommand` over the `.text`
   block range (entry-point disassembly isn't propagating on this Delphi/BCB-style
   PE). Save the program.
2. Re-run `ghidra/pyghidra_xref_decompile.py` anchored on **`DeviceIoControl`
   xrefs** → the USB I/O primitive → IOCTL + read/reset command bytes; and on
   `clearCounters`/`execute_set_command` for dispatch.
3. (If headless disassembly keeps refusing: open once in the Ghidra GUI, select
   `.text`, press `D` to disassemble, re-run the headless anchor.)

---

## T2 BREAKTHROUGH (2026-05-30): forced disassembly → transport layer recovered

Forcing disassembly was the entire blocker. `.ghidra-work/force_da.py` issues a
`DisassembleCommand` over every executable, initialized block (`.text`
`[00401000-0089f9ff]`), then `analyzeAll`:

```
CMR funcs before: 1
CMR disasm block .text [00401000-0089f9ff]
CMR funcs after:  39096          # 1 → 39,096 functions
CMR anchor 'DeviceIoControl' -> 5 funcs
CMR_DONE wrote .ghidra-work/out/pp-forced-iocontrol.c (2482 lines)
```

With refs wired, `DeviceIoControl` resolves to **5 caller functions** — the USB
I/O primitives. They are C++ `USBPipe` methods (the decompile shows
`USBPipe::do_open`, `"Could not open the device because device path is empty."`).
Each lazily opens the handle via `CreateFileW`, caches it at `USBPipe+0x24`, then
issues one `DeviceIoControl`:

| Function | IOCTL | call shape | role |
|---|---|---|---|
| `FUN_0052ce40` | **`0x220038`** | `(h, 0x220038, inBuf, inLen, NULL, 0, &ret, NULL)` | **SEND** (write; no out-buffer) |
| `FUN_0052cab0` | **`0x22003c`** | `(h, 0x22003c, inBuf, inLen, outBuf, 5000, &ret, NULL)` | **RECEIVE** (read; out-buffer + 5000B) |
| `FUN_0052d110` | `0x220034` | `(h, 0x220034, inBuf, inLen, outBuf, 5000, …)` | read variant |
| `FUN_0052d4f0` | `0x220030` | `(h, 0x220030, inBuf, inLen, outBuf, 5000, …)` | variant |

**This independently confirms the Canon Service Tool RE.** The two tools, reversed
separately, use the **identical usbscan IOCTL family** — `0x220038` SEND /
`0x22003c` RECEIVE — over a `CreateFileW` handle. The IOCTL device type is `0x22`
(`FILE_DEVICE_UNKNOWN`/usbscan); the function codes `0x30/0x34/0x38/0x3c`
(`<<2` → method/access bits) form the maintenance-lane pipe set. On Linux this is
the **interface-4 bulk pair (OUT `0x03` / IN `0x86`)** our native tool drives.

### Handle open (all five share it)
```c
CreateFileW(devicePath, 0xc0000000 /*GENERIC_READ|WRITE*/, 3 /*FILE_SHARE_RW*/,
            NULL, 3 /*OPEN_EXISTING*/, 0xa0000000 /*FLAG_OVERLAPPED|NO_BUFFERING*/, NULL)
```

### Command frame is built by the CALLER (not these primitives)
The send/recv primitives take `param_2` = a 3-word descriptor
`{ *param_2 = buf_ptr, param_2[1] = alloc_size, param_2[2] = byte_count }`; if
`buf_ptr` is NULL they allocate `alloc_size`. So the actual
`[cmd][arg_hi][arg_lo][payload]` bytes are assembled **upstream** in
`execute_set_command` / `execute_get_command` / `sendcmd`, which then hand this
descriptor to `FUN_0052ce40`(SEND)/`FUN_0052cab0`(RECV). **That is the remaining
decompile target** — it yields the exact read/reset command bytes.

### Status of the transport in the SSOT
`maintenance.yaml::command_protocol` IOCTLs are now **corroborated by two
independent REs** (Service Tool + WICReset). Promote confidence accordingly; the
per-command payload bytes remain `pending-capture` until the frame builders are
decompiled (next) and ground-truthed in T4.

### Reusable runner
`.ghidra-work/force_da.py` (force-disasm + import-anchored decompile) — the
generalized, committed version is `ghidra/pyghidra_xref_decompile.py`; it needs the
force-disassembly preamble folded in (next commit).

---

## T2 — command-frame BUILDERS recovered (2026-05-30)

String-anchored decompile (`.ghidra-work/builders.py`, needles `service.sendcmd` /
`service.readcmd`) resolves the two frame builders:

| Function | string | role |
|---|---|---|
| `FUN_004f5820` | `service.sendcmd` | **SEND/write builder** — the reset write path |
| `FUN_004f4c40` | `service.readcmd` | **READ builder** — counter/EEPROM read |

**Architecture: WICReset is TEMPLATE-DRIVEN, not hardcoded bytes.** Both builders
substitute **`$INDEX`** and **`$VALUE`** tokens into a per-model command template
(`FUN_00422380("$INDEX")` / `("$VALUE")` + the substitution helpers
`FUN_00508e60`/`FUN_005084d0`), then assemble the wire frame with a single
buffer-append primitive `FUN_004d2510(dst_buf, src, len)`.

### `service.sendcmd` (FUN_004f5820) frame assembly, in order
1. **header blob** from `DAT_009721d0` (config/protocol-prefix global) — appended.
2. **2-byte length/checksum** `local_104 = (idx_w + 1 + val_w + ec_w + v118_w) & 0xffff`
   appended as exactly 2 bytes (the frame length field).
3. value field (`DAT_009721d8` blob) if present.
4. **`$INDEX` = `param_2` serialized as `idx_w` little-endian bytes** — the loop
   `local_d4[0] = (byte)(param_2 >> (8*k)); append 1` for `k = 0..idx_w-1`.
   (`idx_w = local_cd`, the template's index width.)
5. **1-byte op = `*param_3`** (the caller's command/operation selector).
6. **`$VALUE`** field (`local_114`, width `local_10c`).
7. finalize/validate `FUN_004ee1c0(&buf)` → on success dispatch downstream
   (`FUN_00508ef0`/`FUN_00449c60`) to the SEND IOCTL primitive (`FUN_0052ce40`,
   `0x220038`). On failure: log `service.sendcmd` error (fmt @ `0x987af0`).

### `service.readcmd` (FUN_004f4c40)
Symmetric build (same `$INDEX`/`$VALUE` template, same `DAT_009721d0`/`d4`/`e0`
header blobs, same `FUN_004d2510` appender), sends via the RECV IOCTL primitive
(`FUN_0052cab0`, `0x22003c`), then **parses `$VALUE` out of the reply**:
`*param_2 = FUN_00503170(...)` (line 434–435).

### Implication for the protocol model (T3) and key-derivation
- The **wire transport is fully pinned and two-tool-corroborated** (usbscan IOCTL
  `0x220038`/`0x22003c` → iface-4 bulk OUT `0x03`/IN `0x86`).
- The **exact G6020 reset/read bytes are data, not code**: they come from a
  per-Canon-model **template** + the `DAT_009721d0`-family config blobs (an embedded
  resource/DB). The op byte, index width, and header prefix are template fields.
- Two routes to the literal bytes:
  1. **T4 usbmon ground-truth** (capture WICReset performing the real read, then the
     real reset) — most reliable; the frame structure above tells us exactly how to
     parse the captured bytes into `[header][len][idx LE][op][value]`.
  2. **Static template extraction** — dump the `DAT_009721d0`-family region + the
     Canon command-template table from the binary (deeper dig; deferred unless T4
     can't run). Cross-check against the Service Tool's group-7 absorber payload.
- **Key/cloud gate** still to confirm in `action_is_permitted` (string present but
  not yet ref-resolved); the sendcmd path itself shows local frame assembly with no
  inline cloud call — consistent with the key being a *gate/unlock* checked
  elsewhere, not a per-byte input to the frame. To verify next.
