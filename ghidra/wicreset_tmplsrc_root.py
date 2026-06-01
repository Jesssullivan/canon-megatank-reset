#!/usr/bin/env python3
# wicreset_tmplsrc_root.py — final: confirm the model-template TREE ROOT is loaded
# from the APP.BIN VFS path (default/userdata) and is net-free.  Read-only.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-tmplsrc-root.txt")

# VFS path strings whose code-xrefs reveal the template-tree loader
PATHS = {
    "default/userdata": "0096e290",
    "runtime/language": "0096ccdc",
    "update/last_seen_package": "00981d9c",
    "url/action": None,
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

        loaders = set()
        w("===== funcs referencing the VFS template-root paths =====")
        for name, hexa in PATHS.items():
            if hexa is None:
                continue
            a = af.getAddress(hexa)
            it = refmgr.getReferencesTo(a)
            w("\n## %r @ %s" % (name, hexa))
            for r in it:
                fa = r.getFromAddress()
                fn = func_of(fa)
                w("    ref from %s in %s" % (fa, fn))
                loaders.add(fn.split("@")[-1])

        # decompile the default/userdata referrers (the model-template loaders)
        dec = DecompInterface()
        dec.openProgram(p)
        mon = ConsoleTaskMonitor()
        a = af.getAddress(PATHS["default/userdata"])
        ud_funcs = set()
        for r in refmgr.getReferencesTo(a):
            ud_funcs.add(func_of(r.getFromAddress()).split("@")[-1])
        w("\n\n===== decompiles: default/userdata referrers (template-tree loaders) =====")
        for h in sorted(ud_funcs):
            if not h or h == "?":
                continue
            fa = af.getAddress(h)
            fn = fm.getFunctionAt(fa) or fm.getFunctionContaining(fa)
            if not fn:
                continue
            res = dec.decompileFunction(fn, 200, mon)
            w("\n// ===== %s @ %s =====" % (fn.getName(), h))
            if res and res.decompileCompleted():
                c = res.getDecompiledFunction().getC()
                w(c[:6000])
            else:
                w("// (decompile failed)")

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
