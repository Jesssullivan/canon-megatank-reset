#!/usr/bin/env python3
r"""Decompile the inner IO object chain (vtable 0x472298) that the USBPRINT
delegators forward into, to prove it bottoms out on FUN_004302c0
(DeviceIoControl 0x220038/0x22003c). Read-only against the tracked 12.0.2 DB."""
import os
import pyghidra
pyghidra.start()
PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
OUT = os.environ["CMR_OUT"]
FUNCS = [0x430640, 0x430440, 0x4304f0, 0x4305a0, 0x430690, 0x433970,
         0x4304b0, 0x433eb0]


def main():
    from ghidra.base.project import GhidraProject
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.task import ConsoleTaskMonitor
    proj = GhidraProject.openProject(PROJ, PROJ_NAME, False)
    prog = proj.openProgram("/", "ServiceTool_v5103.exe", True)
    flat = FlatProgramAPI(prog); fm = prog.getFunctionManager()
    mon = ConsoleTaskMonitor(); dec = DecompInterface(); dec.openProgram(prog)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")
    for fa in FUNCS:
        a = flat.toAddr(fa)
        fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        if not fn:
            fh.write("\n// no func at %08x\n" % fa); continue
        fh.write("\n// ===================== %s @ %08x =====================\n"
                 % (fn.getName(), fa))
        r = dec.decompileFunction(fn, 240, mon)
        c = (r.getDecompiledFunction().getC() if r and r.decompileCompleted()
             else "// (decompile failed)\n")
        c = "".join(ch if (32 <= ord(ch) < 127 or ch == "\n") else "." for ch in c)
        fh.write(c)
    fh.close(); print("CMR_DONE wrote", OUT); proj.close()


main()
