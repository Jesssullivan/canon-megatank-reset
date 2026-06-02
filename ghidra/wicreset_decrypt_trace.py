#!/usr/bin/env python3
# wicreset_decrypt_trace.py — find the APP.BIN decrypt. The mount driver after
# strip calls FUN_00427e70() then (**(vtbl+8))() -> bool (the parse/decrypt of
# the file index). Decompile that chain + scan for the byte-transform: look for
# functions that read the stripped buffer and produce the std::_Tree<uint> of
# file nodes (ptr,size). Also dump FUN_00427e70 and the vtable[8] target.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-decrypt-trace.txt")

# the buffer object whose vtable is queried in the mount driver:
#   piVar10 = FUN_00427e70();  local_29d = (**(*piVar10 + 8))();
FUNCS = {
    "00427e70": "buffer accessor (returns obj with vtbl)",
    "00427f10": "post-parse cleanup",
    "00427d20": "wxMemoryBuffer helper",
    "004d2ee0": "per-file iter a",
    "004d2e50": "per-file iter b",
    "0044e280": "tree node alloc",
    "00444610": "XFS GetNext?",
    "00444790": "XFS GetFile node",
}

# Scan: find callers of zlib inflate wrappers and the stripped-buffer consumer.
# Also resolve vtable[8] of the object returned by FUN_00427e70 by reading the
# global vtable it installs (we decompile and inspect).


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

        def func_of(a):
            f = fm.getFunctionContaining(a)
            return (f.getName() + "@" + f.getEntryPoint().toString()) if f else ("?@" + a.toString())

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

        # callers of the zlib inflate wrappers (find where APP.BIN files get inflated)
        for tgt, lab in (("006d1dc0", "wxZlibInputStream::OnSysRead"),
                         ("00794130", "zlib inflate")):
            w("\n\n===== callers of FUN_%s (%s) =====" % (tgt, lab))
            a = af.getAddress(tgt)
            it = refmgr.getReferencesTo(a)
            seen = set()
            for r in it:
                fa = r.getFromAddress()
                fo = func_of(fa)
                if fo in seen:
                    continue
                seen.add(fo)
                w("  %s  %s  [%s]" % (fa, fo, r.getReferenceType()))

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
