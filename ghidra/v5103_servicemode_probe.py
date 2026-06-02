#!/usr/bin/env python3
r"""Service-mode reset RE probe for ServiceTool v5103.

Goals:
 1. Find "No service mode printer" string + the function(s) that reference it
    (the service-mode gate / detection).
 2. Inventory ALL transport-capable imports: winspool.drv (OpenPrinter,
    StartDocPrinter, WritePrinter, ReadPrinter, EnumPrinters), setupapi
    (SetupDiGetClassDevs...), kernel32 CreateFileW/A + DeviceIoControl +
    WriteFile/ReadFile, and dump their callers — to see if a non-usbscan path
    exists for service mode.
 3. Dump device-path / printer-related strings (\\.\USBPRINT, \\?\usb#,
    "winspool", "RAW", printer-port style).
 4. List the import library histogram so we KNOW whether winspool.drv is even
    linked.

Read-only reuse of the existing analyzed project (no re-import).
"""
import os

import pyghidra

pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
OUT = os.environ.get("CMR_OUT", ".ghidra-work/out/v5103/servicemode.txt")

# import names we care about (transport candidates)
WANT_IMPORTS = [
    "OpenPrinterA", "OpenPrinterW", "OpenPrinter2A", "OpenPrinter2W",
    "StartDocPrinterA", "StartDocPrinterW", "StartDocPrinter",
    "WritePrinter", "ReadPrinter", "EndDocPrinter", "StartPagePrinter",
    "EndPagePrinter", "ClosePrinter", "EnumPrintersA", "EnumPrintersW",
    "GetPrinterA", "GetPrinterW", "DeviceCapabilitiesA",
    "CreateFileA", "CreateFileW", "DeviceIoControl", "WriteFile", "ReadFile",
    "SetupDiGetClassDevsA", "SetupDiGetClassDevsW",
    "SetupDiEnumDeviceInterfaces", "SetupDiGetDeviceInterfaceDetailA",
    "CreateDCA", "CreateDCW", "Escape", "ExtEscape",
]

STR_NEEDLES = [
    "service mode", "No service mode", "winspool", "USBPRINT", "usb#",
    "\\\\.\\", "Usbscan", "BJL", "BJ", "RAW", "WINSPOOL", "printer",
    "PrinterPort", "LPT", "ServiceMode", "Service Mode", "absorber",
    "Absorber", "Counter", "1284", "DeviceID", "GET_DEVICE_ID",
]


def run(flat):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    prog = flat.getCurrentProgram()
    fm = prog.getFunctionManager()
    refmgr = prog.getReferenceManager()
    st = prog.getSymbolTable()
    listing = prog.getListing()
    mon = ConsoleTaskMonitor()
    dec = DecompInterface()
    dec.openProgram(prog)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")

    def w(s=""):
        fh.write(s + "\n")

    w("CMR servicemode probe — funcs=%d" % fm.getFunctionCount())

    # --- 1. import library histogram + which transport imports exist ---
    w("\n===== EXTERNAL FUNCTIONS (transport candidates) =====")
    ext = prog.getExternalManager()
    libs = ext.getExternalLibraryNames()
    w("external libs: %s" % ", ".join(sorted(str(l) for l in libs)))
    found_imports = {}
    for lib in libs:
        it = ext.getExternalLocations(lib)
        while it.hasNext():
            loc = it.next()
            nm = loc.getLabel()
            if nm in WANT_IMPORTS:
                found_imports.setdefault(nm, []).append(str(lib))
    w("\n-- transport imports present --")
    for nm in WANT_IMPORTS:
        if nm in found_imports:
            w("  %-32s  %s" % (nm, ",".join(found_imports[nm])))
    missing = [n for n in WANT_IMPORTS if n not in found_imports]
    w("-- NOT imported: %s" % ", ".join(missing))

    # --- 2. callers of each transport import (via symbol refs) ---
    def callers_of(symname):
        out = set()
        syms = st.getSymbols(symname)
        for s in syms:
            a = s.getAddress()
            for r in refmgr.getReferencesTo(a):
                fn = fm.getFunctionContaining(r.getFromAddress())
                if fn:
                    out.add(fn.getEntryPoint().toString() + " " + fn.getName())
        return out

    w("\n===== CALLERS of winspool / printer-port transport imports =====")
    for nm in ["OpenPrinterA", "OpenPrinterW", "StartDocPrinterA", "StartDocPrinterW",
               "WritePrinter", "ReadPrinter", "EndDocPrinter", "ClosePrinter",
               "EnumPrintersA", "EnumPrintersW", "CreateDCA", "CreateDCW",
               "ExtEscape", "Escape"]:
        cs = callers_of(nm)
        if cs:
            w("  %s:" % nm)
            for c in sorted(cs):
                w("     %s" % c)

    w("\n===== CALLERS of CreateFileA/W (device opens) =====")
    for nm in ["CreateFileA", "CreateFileW"]:
        cs = callers_of(nm)
        w("  %s: %d callers" % (nm, len(cs)))
        for c in sorted(cs):
            w("     %s" % c)

    # --- 3. relevant strings + their referencing functions ---
    w("\n===== STRINGS of interest + referencing funcs =====")
    di = listing.getDefinedData(True)
    seen = 0
    hits = []
    for d in di:
        try:
            dt = d.getDataType().getName().lower()
        except Exception:
            continue
        if "string" not in dt and "unicode" not in dt and "char" not in dt:
            continue
        val = d.getValue()
        if val is None:
            continue
        s = str(val)
        low = s.lower()
        if any(n.lower() in low for n in STR_NEEDLES):
            hits.append((d.getAddress(), s))
    for addr, s in hits:
        refs = refmgr.getReferencesTo(addr)
        rfns = set()
        for r in refs:
            fn = fm.getFunctionContaining(r.getFromAddress())
            if fn:
                rfns.add(fn.getEntryPoint().toString() + " " + fn.getName())
        disp = s if len(s) < 70 else s[:67] + "..."
        w("  %s  %-72r  refs:%s" % (addr, disp, ";".join(sorted(rfns)) or "-"))
        seen += 1
    w("(%d string hits)" % seen)

    fh.close()
    print("CMR_DONE wrote", OUT)


def open_ro():
    """Open the existing analyzed program read-only via GhidraProject — no save."""
    from ghidra.base.project import GhidraProject
    from ghidra.program.flatapi import FlatProgramAPI

    proj = GhidraProject.openProject(PROJ, PROJ_NAME, False)  # restoreProject=False
    prog = None
    for nm in (PROG_NAME, PROG_NAME.replace(".exe", "")):
        try:
            prog = proj.openProgram("/", nm, True)  # readonly=True
            if prog is not None:
                print("CMR opened program:", nm)
                break
        except Exception as e:  # noqa: BLE001
            print("CMR open attempt failed for", nm, ":", e)
    return proj, prog


print("CMR project loc:", PROJ, "name:", PROJ_NAME)
_proj, _prog = open_ro()
try:
    from ghidra.program.flatapi import FlatProgramAPI
    flat = FlatProgramAPI(_prog)
    run(flat)
finally:
    _proj.close()
