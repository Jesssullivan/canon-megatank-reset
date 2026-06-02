#!/usr/bin/env python3
# wicreset_xfs_methods.py — decompile the XFSVirtual file-access methods (vtable
# slots 0..4) + the tree builder FUN_00446570 / FUN_00444870, to locate the
# per-file DECRYPT and INFLATE (cipher placement) and the file-index structure.
# Also pull the strip-call-site disassembly to recover FUN_004d2a10 args.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-xfs-methods.txt")

FUNCS = {
    "0052fa20": "XFSVirtual vslot0",
    "0052fa50": "XFSVirtual vslot1",
    "0052fa90": "XFSVirtual vslot2",
    "0052faf0": "XFSVirtual vslot3",
    "00530670": "XFSVirtual vslot4 (CanOpen/GetFile?)",
    "00530560": "XFSVirtual vslot7",
    "00446570": "tree alloc (FUN_00446570)",
    "00444870": "XFSVirtual ctor body",
    "005228c0": "tree-descend step",
    "004d1d80": "key buffer set",
}

# disasm a window around the strip call inside the mount driver
STRIP_SITE_START = 0x00530e98
STRIP_SITE_END = 0x00530f60


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
            print(s)

        # disasm around the FUN_004d2a10 strip call
        w("===== disasm @ mount-driver strip site 0x%08x..0x%08x ====="
          % (STRIP_SITE_START, STRIP_SITE_END))
        a = af.getAddress("%08x" % STRIP_SITE_START)
        end = af.getAddress("%08x" % STRIP_SITE_END)
        ins = listing.getInstructionAt(a)
        while ins is not None and ins.getAddress().compareTo(end) < 0:
            w("  %s  %s" % (ins.getAddress(), ins.toString()))
            ins = ins.getNext()

        dec = DecompInterface()
        dec.openProgram(p)
        mon = ConsoleTaskMonitor()
        for hexea, label in FUNCS.items():
            aa = af.getAddress(hexea)
            fn = fm.getFunctionAt(aa) or fm.getFunctionContaining(aa)
            w("\n\n// ===== FUN_%s  (%s) =====" % (hexea, label))
            if not fn:
                w("// (no function)")
                continue
            res = dec.decompileFunction(fn, 150, mon)
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
