#!/usr/bin/env python3
r"""Decompile an explicit list of functions (by address) from the existing
analyzed ServiceTool v5103 project, read-only. Address list via CMR_FUNCS
(comma-separated hex, no 0x). Also dumps callers of each (depth 1)."""
import os

import pyghidra

pyghidra.start()

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
OUT = os.environ["CMR_OUT"]
FUNCS = [f.strip() for f in os.environ.get("CMR_FUNCS", "").split(",") if f.strip()]
WITH_CALLERS = os.environ.get("CMR_CALLERS", "1") == "1"


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

    flat = FlatProgramAPI(prog)
    fm = prog.getFunctionManager()
    mon = ConsoleTaskMonitor()
    dec = DecompInterface()
    dec.openProgram(prog)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")

    def decomp(fn):
        r = dec.decompileFunction(fn, 180, mon)
        return (r.getDecompiledFunction().getC()
                if r and r.decompileCompleted() else "// (decompile failed)\n")

    for fa in FUNCS:
        a = flat.toAddr(fa)
        fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        if fn is None:
            fh.write("// no function at %s\n\n" % fa)
            continue
        fh.write("// ===================== %s @ %s =====================\n"
                 % (fn.getName(), fn.getEntryPoint()))
        if WITH_CALLERS:
            callers = sorted({c.getEntryPoint().toString() + " " + c.getName()
                              for c in fn.getCallingFunctions(mon)})
            fh.write("// callers: %s\n" % (", ".join(callers) or "(none/indirect)"))
        fh.write(decomp(fn))
        fh.write("\n\n")
    fh.close()
    print("CMR_DONE wrote", OUT)


_proj, _prog = open_ro()
try:
    run(_prog)
finally:
    _proj.close()
