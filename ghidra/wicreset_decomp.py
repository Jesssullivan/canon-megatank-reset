#!/usr/bin/env python3
# wicreset_decomp.py — decompile an arbitrary list of functions by entry addr.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-decomp.txt")
EAS = [x for x in os.environ.get("CMR_EAS", "").split(",") if x]

with open_program(None, project_location=PROJ, project_name=NAME,
                  program_name=PROG, analyze=False) as flat:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    p = flat.getCurrentProgram()
    af = p.getAddressFactory()
    fm = p.getFunctionManager()
    mon = ConsoleTaskMonitor()
    dec = DecompInterface()
    dec.openProgram(p)
    fh = open(OUT, "w")
    for ea in EAS:
        a = af.getAddress(ea)
        fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        if not fn:
            fh.write("// %s : not a function\n\n" % ea)
            continue
        fh.write("// ===== %s @ %s =====\n" % (fn.getName(), ea))
        res = dec.decompileFunction(fn, 180, mon)
        if res and res.decompileCompleted():
            fh.write(res.getDecompiledFunction().getC())
        else:
            fh.write("// (decompile failed)\n")
        fh.write("\n\n")
    fh.close()
    print("CMR_DONE wrote %s" % OUT)
