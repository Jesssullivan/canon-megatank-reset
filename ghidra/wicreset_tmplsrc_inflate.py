#!/usr/bin/env python3
# wicreset_tmplsrc_inflate.py — find the zlib-inflate driver in the APP.BIN VFS
# path and any pre-inflate de-obfuscation (the reason APP.BIN is high-entropy).
# We locate the zlib 'inflate' function by the error-string table it references
# (incorrect header check @ ~0x547e48 region => the inflate() func references it),
# then walk callers up toward the XFS read.  Read-only.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-inflate-trace.txt")

# anchor strings whose code-xref reveals zlib inflate/inflateInit
ANCHORS = {
    "incorrect header check": None,
    "unknown compression method": None,
    "need dictionary": None,
    "invalid window size": None,
}


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        p = flat.getCurrentProgram()
        af = p.getAddressFactory()
        fm = p.getFunctionManager()
        refmgr = p.getReferenceManager()
        listing = p.getListing()
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")
            print(s)

        def func_of(addr):
            f = fm.getFunctionContaining(addr)
            return f.getName() + "@" + f.getEntryPoint().toString() if f else "?"

        # find anchor string addresses
        di = listing.getDefinedData(True)
        addr_for = {}
        while di.hasNext():
            d = di.next()
            v = d.getValue()
            if v is None:
                continue
            s = str(v)
            if s in ANCHORS:
                addr_for[s] = d.getAddress()

        w("===== zlib error-string anchors + their referencing funcs (=> inflate) =====")
        inflate_funcs = set()
        for s, a in addr_for.items():
            if a is None:
                continue
            it = refmgr.getReferencesTo(a)
            w("\n## %r @ %s" % (s, a))
            for r in it:
                fa = r.getFromAddress()
                fn = func_of(fa)
                w("    ref from %s in %s" % (fa, fn))
                inflate_funcs.add(fn.split("@")[-1])

        # callers of the inflate funcs
        w("\n===== callers of the inflate func(s) =====")
        layer2 = set()
        for h in list(inflate_funcs):
            if not h or h == "?":
                continue
            a = af.getAddress(h)
            fn = fm.getFunctionAt(a)
            if not fn:
                continue
            it = refmgr.getReferencesTo(a)
            w("\n## callers of %s @ %s" % (fn.getName(), h))
            cnt = 0
            for r in it:
                if str(r.getReferenceType()).find("CALL") < 0:
                    continue
                fa = r.getFromAddress()
                w("    %s  %s" % (fa, func_of(fa)))
                layer2.add(func_of(fa).split("@")[-1])
                cnt += 1
            if cnt == 0:
                w("    (no direct CALL refs; may be reached via thunk)")

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
