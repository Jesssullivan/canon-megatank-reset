# canon-tool — Ghidra headless scripts (R3 static analysis)

Reusable Jython post-scripts for the canon-r3 Ghidra arm (TIN-1695 →
TIN-1697). They run under `analyzeHeadless` against the Canon Service
Tool binary and dump structured anchors for the absorber-reset trace.

**The Service Tool binary and the Ghidra project are NOT in git** (no
binary redistribution — see ADR 0007). They live under the gitignored
`.ghidra-work/` working dir. Only these scripts + the curated findings
in `docs/research/canon-tool-ghidra-notes.md` are tracked.

## Scripts

| script | purpose |
|---|---|
| `dump_canon.py` | program metadata, recovered C++ classes (RTTI), symbols matching maintenance/USB vocabulary, imported I/O primitives, import-library histogram |
| `dump_strings.py` | every defined string → `<out>.txt`, plus a filtered model-name + maintenance-vocabulary hit list |
| `trace_usb.py` | rank + decompile functions touching WriteFile/ReadFile/DeviceIoControl/CreateFileA/SetupDi\* or the Usbscan / EEPROM anchors |
| `trace_callers.py` | decompile callers of a target function (depth 1/2) |
| `vtable_probe.py` | resolve the C++ vtable holding a target method; dump the class method table + constructors (defeats virtual-dispatch indirection) |
| `find_and_decomp.py` | byte-search for 32-bit constants (vtable installs) + decompile an explicit function list |
| `parse_dialogs.py` | (plain python) parse RT_DIALOG templates → `(dialogId, controlId, caption)`; maps button captions to control IDs |
| `find_msgmap.py` | scan `.rdata` for MFC `AFX_MSGMAP_ENTRY` (WM_COMMAND) → control-ID→handler map; decompile target handlers |
| `peek_obj.py` | read a global object's vtable pointer + dump its method table; list refs (constructor/users) |
| `dump_named_vtable.py` | dump a named C++ vftable's slots + decompile the method at a chosen offset |

**TIN-1697 recipe (button → wire):** `parse_dialogs.py` (control IDs) →
`find_msgmap.py` (ID→handler) → decompile handler → `FUN_0040ac60(group, payload)`
→ `vtable_probe.py`/`dump_named_vtable.py` resolve `EncCommService` →
the usbscan IOCTL `FUN_004302c0`. Full writeup:
`docs/research/canon-tool-ghidra-notes.md`.

## Reproduce (on neo, Ghidra 11.4.2 via nix + JDK 21)

```sh
WORK=.ghidra-work                      # gitignored
HEADLESS=$(dirname $(readlink -f $(which ghidra)))/support/analyzeHeadless
# (or: <nix-store>/ghidra-11.4.2/lib/ghidra/support/analyzeHeadless)

# pull the binary (never committed)
rsync mbp-13:canon-tool-staging/extracted/ServiceTool_v5103/ServiceTool_v5103.exe "$WORK/bin/"

# one-time: import + full auto-analysis (PE + RTTI + decompiler param-id)
"$HEADLESS" "$WORK/project" canon-servicetool-v5103 \
  -import "$WORK/bin/ServiceTool_v5103.exe"

# re-runnable: dump against the saved program (fast, no re-analysis)
"$HEADLESS" "$WORK/project" canon-servicetool-v5103 \
  -process ServiceTool_v5103.exe -noanalysis \
  -scriptPath ghidra \
  -postScript dump_canon.py "$WORK/out/v5103-ghidra-report.md"

"$HEADLESS" "$WORK/project" canon-servicetool-v5103 \
  -process ServiceTool_v5103.exe -noanalysis \
  -scriptPath ghidra \
  -postScript dump_strings.py "$WORK/out/v5103-strings.txt" "$WORK/out/v5103-string-hits.txt"
```

## Notes

- Jython 2.7: keep a `# -*- coding: utf-8 -*-` header and write output via
  `codecs.open(path, "w", "utf-8")` — em-dashes in markdown literals + non-ASCII
  binary strings otherwise blow up the default ascii codec.
- `DefinedDataIterator.definedStrings` is **absent** in Ghidra 11.4.2 — walk
  `currentProgram.getListing().getDefinedData(True)` and filter on the data
  type name instead (see `dump_strings.py`).
- These scripts are model-agnostic; point them at any `TOOL0006V****.exe`
  Service Tool to compare model coverage / class layout across versions.
