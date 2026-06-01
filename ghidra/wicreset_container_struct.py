#!/usr/bin/env python3
# wicreset_container_struct.py — LANE C container-format RE.
# Decompile the APP.BIN container pipeline to characterize the on-disk layout:
#   FUN_004d2a10  header/footer strip (what bytes does it remove? offsets/len?)
#   FUN_00530ae0  the mount driver (how files are iterated/indexed in the blob)
#   FUN_004d2510  the buffer copy/append (the resource -> buffer primitive)
#   XFSVirtual vtable @ 0x0098b5a8 method slots (how it indexes files)
#   + the per-file get-stream / decrypt / inflate chain (cipher placement)
# Read-only. Emits decompiles + vtable slot resolution.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-container-struct.txt")

# functions to decompile (container pipeline)
FUNCS = {
    "004d2a10": "header/footer strip (substring)",
    "00530ae0": "mount driver (wx app-init, builds XFSVirtual)",
    "004d2510": "buffer copy/append primitive",
    "00532270": "APP.BIN FindResource loader",
    "00532640": "Ref_count<XFSVirtual> wrap",
    "00522ac0": "dotted-path accessor",
    "00794130": "zlib inflate",
    "006d1dc0": "wxZlibInputStream wrapper a",
    "006d2370": "wxZlibInputStream wrapper b",
}

VTABLE = 0x0098b5a8   # XFSVirtual vtable


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

        dec = DecompInterface()
        dec.openProgram(p)
        mon = ConsoleTaskMonitor()

        def fname(a):
            f = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            return f.getName() if f else "?"

        # --- XFSVirtual vtable slots ---
        w("===== XFSVirtual vtable @ 0x%08x (method slots) =====" % VTABLE)
        vt = af.getAddress("%08x" % VTABLE)
        for i in range(20):
            a = vt.add(i * 4)
            d = listing.getDataAt(a)
            tgt = None
            if d is not None and d.isPointer():
                try:
                    tgt = d.getValue()
                except Exception:
                    tgt = None
            if tgt is None:
                # read 4 raw bytes
                try:
                    raw = p.getMemory().getInt(a) & 0xFFFFFFFF
                    tgt = af.getAddress("%08x" % raw)
                except Exception:
                    tgt = None
            if tgt is not None:
                w("  slot[%2d] @%s -> %s  %s" % (i, a, tgt, fname(tgt)))

        # --- decompiles ---
        for hexea, label in FUNCS.items():
            a = af.getAddress(hexea)
            fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            w("\n\n// ===== FUN_%s  (%s) =====" % (hexea, label))
            if not fn:
                w("// (no function at %s)" % hexea)
                continue
            res = dec.decompileFunction(fn, 180, mon)
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
