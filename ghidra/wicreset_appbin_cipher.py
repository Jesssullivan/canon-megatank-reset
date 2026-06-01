#!/usr/bin/env python3
# wicreset_appbin_cipher.py — decompile the APP.BIN container strip/decrypt chain.
# Targets the functions between LoadResource and the wxFileSystem XFSVirtual mount:
#   FUN_004d2a10 (strip header/footer + decrypt), FUN_004d2510 (copy/append),
#   FUN_00532640, FUN_00427e70, FUN_00446570, FUN_00446570 helpers.
# Also dumps any .rdata constant tables referenced, and disassembles the byte loop.
# Read-only.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-appbin-cipher.txt")
TARGETS = os.environ.get("CMR_TARGETS",
    "004d2a10,004d2510,00532640,00427e70,00446570").split(",")


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        p = flat.getCurrentProgram()
        af = p.getAddressFactory()
        fm = p.getFunctionManager()
        listing = p.getListing()
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")

        dec = DecompInterface()
        dec.openProgram(p)
        mon = ConsoleTaskMonitor()

        def decomp(h):
            a = af.getAddress(h)
            fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            if not fn:
                w("// no function at %s" % h); return None
            res = dec.decompileFunction(fn, 240, mon)
            w("\n// ===== %s @ %s  (callees follow) =====" % (fn.getName(), h))
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")
            return fn

        def disasm(h, n=160):
            a = af.getAddress(h)
            w("\n// ----- raw disasm %s -----" % h)
            inst = listing.getInstructionAt(a)
            cnt = 0
            while inst is not None and cnt < n:
                w("  %s  %s" % (inst.getAddress(), inst.toString()))
                inst = inst.getNext()
                cnt += 1

        for h in TARGETS:
            h = h.strip()
            if not h:
                continue
            fn = decomp(h)
            disasm(h, 200)

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
