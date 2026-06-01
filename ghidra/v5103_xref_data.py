#!/usr/bin/env python3
r"""Find writers/readers of given data addresses and callers of given funcs,
read-only against the existing v5103 project. Also can decompile a func list.

Env:
  CMR_DATA   comma hex addrs -> report all refs (read/write) + containing func
  CMR_CALLERS_OF comma hex func addrs -> list callers
  CMR_FUNCS  comma hex func addrs -> decompile
"""
import os

import pyghidra

pyghidra.start()

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
OUT = os.environ["CMR_OUT"]
DATA = [x.strip() for x in os.environ.get("CMR_DATA", "").split(",") if x.strip()]
CALLERS_OF = [x.strip() for x in os.environ.get("CMR_CALLERS_OF", "").split(",") if x.strip()]
FUNCS = [x.strip() for x in os.environ.get("CMR_FUNCS", "").split(",") if x.strip()]


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
    refmgr = prog.getReferenceManager()
    mon = ConsoleTaskMonitor()
    dec = DecompInterface()
    dec.openProgram(prog)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")

    def fn_of(addr):
        f = fm.getFunctionContaining(addr)
        return (f.getEntryPoint().toString() + " " + f.getName()) if f else "(no func)"

    for da in DATA:
        a = flat.toAddr(da)
        fh.write("\n===== refs to DATA %s =====\n" % da)
        for r in refmgr.getReferencesTo(a):
            fh.write("  from %s  %-10s  in %s\n"
                     % (r.getFromAddress(), r.getReferenceType(), fn_of(r.getFromAddress())))

    for fa in CALLERS_OF:
        a = flat.toAddr(fa)
        fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        fh.write("\n===== callers of %s (%s) =====\n"
                 % (fa, fn.getName() if fn else "?"))
        if fn:
            for c in sorted({c.getEntryPoint().toString() + " " + c.getName()
                             for c in fn.getCallingFunctions(mon)}):
                fh.write("  %s\n" % c)
            # also raw refs (indirect/data)
            for r in refmgr.getReferencesTo(fn.getEntryPoint()):
                fh.write("  ref %s %s in %s\n"
                         % (r.getFromAddress(), r.getReferenceType(), fn_of(r.getFromAddress())))

    for fa in FUNCS:
        a = flat.toAddr(fa)
        fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        if fn is None:
            fh.write("// no func at %s\n" % fa)
            continue
        fh.write("\n// ===================== %s @ %s =====================\n"
                 % (fn.getName(), fn.getEntryPoint()))
        r = dec.decompileFunction(fn, 180, mon)
        fh.write(r.getDecompiledFunction().getC()
                 if r and r.decompileCompleted() else "// (decompile failed)\n")

    fh.close()
    print("CMR_DONE wrote", OUT)


_proj, _prog = open_ro()
try:
    run(_prog)
finally:
    _proj.close()
