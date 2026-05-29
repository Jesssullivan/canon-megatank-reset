# canon-tool R3 — Ghidra static-analysis notes (Service Tool v5103)

**Ticket:** [TIN-1695](https://linear.app/tinyland/issue/TIN-1695) (Ghidra setup) — feeds [TIN-1697](https://linear.app/tinyland/issue/TIN-1697) (trace) + [TIN-1699](https://linear.app/tinyland/issue/TIN-1699) (cross-ref)
**Date:** 2026-05-29
**Binary:** `ServiceTool_v5103.exe` — SHA256 `98ca97b37a36a73d1a91630b8bde455b7dd109960073a0369295e34be6317c48`
**Internal name:** `TOOL0006V5103.exe` (Canon's "TOOL0006" = the PIXMA Service Tool product line)

> The binary and the Ghidra project are **not** committed (no binary
> redistribution — ADR 0007). This doc is the curated, tracked record of
> what static analysis found. Re-run via `services/canon-tool/ghidra/`.

---

## TL;DR — three findings that shape the whole R3/R1 plan

1. **Transport is the legacy `usbscan.sys` kernel driver, not WinUSB.**
   The Service Tool opens `\\.\Usbscan%d` with `CreateFileA` and drives it
   with `DeviceIoControl` / `WriteFile` / `ReadFile`, having enumerated the
   device via the `SETUPAPI.DLL` `SetupDi*` family. This maps **directly** to
   our Linux side: a `WriteFile` to the usbscan handle is a bulk-OUT to the
   printer; our R0 probe already pinned that as **interface 4, bulk OUT
   `0x03` / bulk IN `0x86`**. So the byte payload the Service Tool hands to
   `WriteFile` *is* the byte sequence we replay with pyusb in Phase A.

2. **v5103 has zero G6020 awareness.** Its only model strings are
   **`TS300 series`, `G3000 series`, `G3010 series`, `G4010 series`.**
   This makes the R1 spike ([TIN-1694](https://linear.app/tinyland/issue/TIN-1694))
   an explicit *family-protocol gamble*: if running v5103 in **G3010 mode**
   clears the G6020's 5B00, it is because the absorber-reset protocol is
   shared across the G-series MegaTank chipset family — **not** because the
   tool recognizes the G6020. G3010 is the closest sibling v5103 supports, so
   it is the correct test vehicle.

3. **The EEPROM/absorber anchors are recovered and addressed.** RTTI gave us
   the three `CEEPROM*` classes with vtable locations; the trace (TIN-1697)
   has concrete starting points.

---

## Environment

| | |
|---|---|
| Ghidra | 11.4.2 (nix-profile install on neo) |
| JDK | Zulu OpenJDK 21.0.8 |
| mode | headless (`support/analyzeHeadless`) |
| project | `.ghidra-work/project/canon-servicetool-v5103` (gitignored; reused by TIN-1697) |
| scripts | `services/canon-tool/ghidra/{dump_canon,dump_strings}.py` (tracked) |
| analysis | default analyzers incl. Windows PE, RTTI, Decompiler Parameter ID, exception handling (~50s for the PE exception pass) |

## Program metadata

| field | value |
|---|---|
| format | PE32 (32-bit), `x86:LE:32:default` |
| compiler | MSVC / MFC (native, not .NET) |
| image base | `0x00400000` |
| functions | 3543 |
| symbols | 14917 |
| recovered C++ classes (RTTI) | 211 |

It is a **statically-linked MFC dialog app** (CWinApp/CDialog hierarchy fully
present), which is why RTTI recovery is so rich.

---

## Finding 1 — USB transport (the key architectural fact)

Imported I/O primitives:

| function | library | role |
|---|---|---|
| `SetupDiGetClassDevsA` | SETUPAPI | enumerate device interfaces |
| `SetupDiEnumDeviceInterfaces` | SETUPAPI | " |
| `SetupDiGetDeviceInterfaceDetailA` | SETUPAPI | resolve device path |
| `SetupDiOpenDeviceInterfaceRegKey` | SETUPAPI | " |
| `SetupDiDestroyDeviceInfoList` | SETUPAPI | cleanup |
| `CreateFileA` | KERNEL32 | open `\\.\Usbscan%d` |
| `DeviceIoControl` | KERNEL32 | IOCTLs (pipe select / control xfer) |
| `WriteFile` | KERNEL32 | **bulk OUT — the command bytes** |
| `ReadFile` | KERNEL32 | bulk IN — the response |
| `CloseHandle` | KERNEL32 | cleanup |

Device path strings: `Usbscan%d` (`0x4723f8`) and `\\.\Usbscan%d` (`0x472404`).

**Interpretation.** `usbscan.sys` is a thin pass-through driver Canon's tools
have used for years. The Service Tool:
1. enumerates the USB-scan device-interface class via `SetupDi*`,
2. `CreateFileA("\\.\UsbscanN")`,
3. selects a pipe / issues control transfers via `DeviceIoControl`,
4. sends the maintenance command with `WriteFile`, reads status with `ReadFile`.

On Linux there is no usbscan layer — pyusb writes straight to the bulk
endpoint. So the **WriteFile payload == our bulk-OUT payload** on interface 4
endpoint `0x03`. This is the cleanest possible mapping and it means the R1/R2
captures and the Ghidra trace are measuring the same bytes from two sides.

Error string `No service mode printer` (`0x4710bc`) ⇒ the tool checks the
printer is in service mode before issuing commands; `An undefined command`
(`0x4720b4`) ⇒ there is a validated command dispatch (opcodes, not free-form).

---

## Finding 2 — model coverage (decides the R1 hypothesis)

Full list of model strings present in v5103 (`dump_strings.py`):

```
0x470730   TS300 series
0x4709d8   G3000 series
0x47107c   G4010 series
0x47108c   G3010 series
```

**No G6020. No G6000. No G7020.** The G-series MegaTank family it knows is
G3000 / G3010 / G4010 (+ the TS300 entry-level line). The G6020 is the same
MegaTank architecture generation as G3010, so the working hypothesis —
*absorber-reset is a chipset-family protocol, not a per-model one* — is
exactly what R1 tests. If it fails, the divergence is itself data (the
protocol is model-gated), and we fall back to R2/R3 byte capture.

---

## Finding 3 — RTTI anchors for the TIN-1697 trace

### EEPROM / absorber classes (vtable + RTTI descriptor addresses)

| class | vftable label | RTTI type descriptor |
|---|---|---|
| `CEEPROMDumpSave` | `s_CEEPROMDumpSave_0046f140` / `PTR_..._0046f160` | `.?AVCEEPROMDumpSave@@` @ `0x48264c` |
| `CEEPROMHeadDumpSave` | `s_CEEPROMHeadDumpSave_0046f378` | `.?AVCEEPROMHeadDumpSave@@` @ `0x48266c` |
| `CEEPROMInfoDlg` | `s_CEEPROMInfoDlg_0046f5a0` / `PTR_..._0046f5b0` | `.?AVCEEPROMInfoDlg@@` @ `0x482690` |
| `CPSHeadInfoSave` | — | `.?AVCPSHeadInfoSave@@` @ `0x482748` |

`EEPROM Print` (`0x4822e4`) is a labeled operation string. `CEEPROMInfoDlg`
is the most likely home of the absorber-counter display + reset control.

### App / UI structure (orientation for the GUI→handler walk)

- `CSecurityToolApp` (CWinApp) — entry point; `CSecurityToolDlg` — main dialog.
- Tabbed UI: `CDlgTabMain`, `CDlgTabAuto`, `CDlgTabOther`, `CDlgTabPro`.
- Service dialogs: `CCheckCompDlg`, `CColorCalibSave`, `CMediaInfoDlg`,
  `CMediaSizeDlg`, `CMediaTypeDlg`, `CPaperSourceDlg`, `CPaperSourcePro`.
- App window title strings: `Service Mode Tool` (`0x4a6208`).

### Symbols of direct interest (from `dump_canon.py`)

```
PTR_WriteFile_0046d2c8         indirect WriteFile thunk (xref to find the write site)
PTR_DeviceIoControl_0046d2e0   indirect DeviceIoControl thunk
s_\\.\Usbscan%d_00472404       device path (xref → CreateFileA open site)
s_No_service_mode_printer_004710bc
s_EEPROM_Print_004822e4
```

---

## The `.rsrc` gap (important caveat for TIN-1697)

Only **1223** plain defined strings were recovered, and **none** contain
"absorber", "waste", "5B00", "ink absorber counter", "cleaning", or "nozzle".
Those are GUI captions and live in the PE **resource section** (`.rsrc`
`RT_STRING` / `RT_DIALOG` tables), loaded by ID via `LoadString` — Ghidra's
default analysis did not decode them into `Data` strings.

**Consequence:** mapping the visible button "Ink Absorber Counter → Set" to a
control ID + message handler needs the resource tables. Two ways in:
1. Extract resources directly — `wrestool -x --type=dialog/string` (icoutils)
   or `wine`'s `wrc`/a PE resource viewer — to get dialog templates +
   string-table IDs, then match control IDs to handlers in Ghidra.
2. Trace structurally from `CEEPROMInfoDlg`'s message map and from the
   `\\.\Usbscan%d` `CreateFileA` xref down to the `WriteFile` call, ignoring
   captions entirely.

Recommend doing (1) first as a quick `wrestool` pass — it's cheap and gives
the control-ID → handler key that makes (2) fast.

---

## Handoff to TIN-1697 (trace) — concrete plan

1. **Resource pass:** `wrestool -x` the `.exe` for `RT_DIALOG` + `RT_STRING`;
   find the dialog containing the "Ink Absorber Counter" control + its ID and
   the owning dialog (expect `CEEPROMInfoDlg` or a `CDlgTab*`).
2. **Open site:** xref `s_\\.\Usbscan%d_00472404` → the `CreateFileA` that
   opens the handle; note where the handle is stored (member of which class).
3. **Write site:** xref `PTR_WriteFile_0046d2c8` (and `PTR_DeviceIoControl`);
   for each call, recover the buffer + length args via the decompiler.
4. **Join:** find the path from the absorber-reset control handler (step 1)
   to a step-3 write site; recover the **byte payload** + any
   `DeviceIoControl` IOCTL/setup.
5. Draft the payload into `printers/canon-g6020/maintenance.yaml::supported`
   as `status: candidate` (NOT verified — Phase A replay + TIN-1699 firmware
   cross-ref must agree first).

---

## Reproduction

See `services/canon-tool/ghidra/README.md`. Raw dumps (gitignored) at
`.ghidra-work/out/`: `v5103-ghidra-report.md`, `v5103-strings.txt`,
`v5103-string-hits.txt`.
