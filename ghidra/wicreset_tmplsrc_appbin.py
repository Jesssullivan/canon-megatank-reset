#!/usr/bin/env python3
# wicreset_tmplsrc_appbin.py — trace the APP.BIN resource template pipeline.
#
# Found: resource "APP.BIN"/"DATA" (571,596 B, entropy ~8.0 => packed/encrypted)
# is loaded by FUN_00532270 (FindResource/LoadResource/LockResource) into a
# buffer via FUN_004d2510(0, ptr, size, 1).  This is the bundled model-template
# DB candidate.  Resolve:
#   1. WHO calls FUN_00532270 (the loader) -> the parse/decrypt driver.
#   2. WHAT FUN_004d2510 does (a memcpy/append? into which global/object?).
#   3. The parse chain: who turns the (decrypted) blob into the dotted-path tree
#      that FUN_00522ac0 reads. Look for zlib/inflate, a block cipher, base64,
#      or a JSON/property-tree parser between the loader and the tree.
#   4. Also resolve callers of the CSQUERY resource path if any.
#
# Read-only.  Emits caller chains + decompiles of the driver funcs.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-appbin-trace.txt")

LOADER = "00532270"   # the APP.BIN FindResource loader
COPY = "004d2510"     # the buffer append/copy used on the locked resource


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        p = flat.getCurrentProgram()
        af = p.getAddressFactory()
        fm = p.getFunctionManager()
        refmgr = p.getReferenceManager()
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")
            print(s)

        def func_of(addr):
            f = fm.getFunctionContaining(addr)
            return f.getName() + "@" + f.getEntryPoint().toString() if f else "?@" + addr.toString()

        def callers_of(hexea):
            a = af.getAddress(hexea)
            fn = fm.getFunctionAt(a)
            res = []
            if fn:
                it = refmgr.getReferencesTo(a)
                for r in it:
                    fa = r.getFromAddress()
                    if str(r.getReferenceType()).find("CALL") >= 0 or True:
                        res.append((fa, func_of(fa), str(r.getReferenceType())))
            return res

        w("===== callers of APP.BIN loader FUN_%s =====" % LOADER)
        loader_callers = callers_of(LOADER)
        seen = set()
        for fa, fn, rt in loader_callers:
            w("  %s  %s  [%s]" % (fa, fn, rt))
            seen.add(fn.split("@")[-1])

        w("\n===== callers of buffer-copy FUN_%s (sample) =====" % COPY)
        cc = callers_of(COPY)
        w("  (%d total call sites)" % len(cc))
        for fa, fn, rt in cc[:25]:
            w("  %s  %s" % (fa, fn))

        # decompile loader callers + the loader to see the parse/decrypt driver
        dec = DecompInterface()
        dec.openProgram(p)
        mon = ConsoleTaskMonitor()
        targets = list({h for h in seen if h and h != "?"})
        w("\n\n===== decompiles of APP.BIN loader callers (parse/decrypt drivers) =====")
        for h in targets:
            a = af.getAddress(h)
            fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            if not fn:
                continue
            res = dec.decompileFunction(fn, 180, mon)
            w("\n// ===== %s @ %s =====" % (fn.getName(), h))
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
