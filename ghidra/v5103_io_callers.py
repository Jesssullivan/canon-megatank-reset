#!/usr/bin/env python3
r"""List ALL callers of WriteFile/ReadFile/DeviceIoControl and decompile each
caller, read-only. Disambiguates which transport functions do byte-level IO."""
import os

import pyghidra

pyghidra.start()

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
OUT = os.environ["CMR_OUT"]
APIS = os.environ.get("CMR_APIS", "WriteFile,ReadFile,DeviceIoControl").split(",")
DECOMP = os.environ.get("CMR_DECOMP", "1") == "1"


def open_ro():
    from ghidra.base.project import GhidraProject

    proj = GhidraProject.openProject(PROJ, PROJ_NAME, False)
    prog = None
    for nm in (PROG_NAME, PROG_NAME.replace(".exe", "")):
        try:
            prog = proj.openProgram("/", nm, True)
            if prog is not None:
                break
        except Exception:  # noqa: BLE001
            pass
    return proj, prog


def run(prog):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.task import ConsoleTaskMonitor

    flat = FlatProgramAPI(prog)  # noqa: F841
    fm = prog.getFunctionManager()
    st = prog.getSymbolTable()
    refmgr = prog.getReferenceManager()
    mon = ConsoleTaskMonitor()
    dec = DecompInterface()
    dec.openProgram(prog)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")

    callers = set()
    for api in APIS:
        api = api.strip()
        for s in st.getSymbols(api):
            a = s.getAddress()
            for r in refmgr.getReferencesTo(a):
                fn = fm.getFunctionContaining(r.getFromAddress())
                if fn:
                    callers.add(fn.getEntryPoint().toString())
            fh.write("// %s @ %s\n" % (api, a))
    fh.write("\n// caller functions: %s\n\n" % ", ".join(sorted(callers)))

    if DECOMP:
        for ea in sorted(callers):
            fn = fm.getFunctionAt(prog.getAddressFactory().getAddress(ea))
            if fn is None:
                continue
            fh.write("// ===================== %s @ %s =====================\n"
                     % (fn.getName(), ea))
            r = dec.decompileFunction(fn, 180, mon)
            fh.write(r.getDecompiledFunction().getC()
                     if r and r.decompileCompleted() else "// (decompile failed)\n")
            fh.write("\n")
    fh.close()
    print("CMR_DONE wrote", OUT)


_proj, _prog = open_ro()
try:
    run(_prog)
finally:
    _proj.close()
