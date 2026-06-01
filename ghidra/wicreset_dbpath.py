#!/usr/bin/env python3
# wicreset_dbpath.py — LANE C closeout: resolve the LOCAL devices.srs source.
#  - decompile FUN_0051b040 (the StartupParseAllDatabases local fallback loader),
#  - find + decompile xrefs of "DatabasePath" (where the DB file path is built),
#  - find + decompile xrefs of "Data received from the server do not pass sanity
#    check." (the server-DB ingest sanity gate),
#  - find APP.BIN / devices-archive resource access (is the bundled DB a PE
#    resource or an on-disk file next to the exe?).
# Read-only, open-by-name.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-dbpath.txt")

DECOMP_EAS = ["0051b040"]
STR_NEEDLES = [
    "DatabasePath",
    "Data received from the server do not pass sanity check.",
    "Data is not found in archive...",
    "APP.BIN", "DATA",
]


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        p = flat.getCurrentProgram()
        fm = p.getFunctionManager()
        rm = p.getReferenceManager()
        af = p.getAddressFactory()
        listing = p.getListing()
        mon = ConsoleTaskMonitor()
        dec = DecompInterface()
        dec.openProgram(p)
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")

        # string xrefs
        to_decomp = {}
        w("===== string -> referencing functions =====")
        di = listing.getDefinedData(True)
        hits = {}
        while di.hasNext():
            d = di.next()
            v = d.getValue()
            if v is None:
                continue
            s = str(v) if not isinstance(v, str) else v
            for n in STR_NEEDLES:
                if s == n:
                    hits.setdefault(n, []).append(d.getAddress())
        for n in STR_NEEDLES:
            w("\n--- %r ---" % n)
            for addr in hits.get(n, []):
                for r in rm.getReferencesTo(addr):
                    cfn = fm.getFunctionContaining(r.getFromAddress())
                    if cfn:
                        ea = cfn.getEntryPoint().toString()
                        w("    str@%s <- %s %s" % (addr, ea, cfn.getName()))
                        to_decomp[ea] = cfn.getName()
            if not hits.get(n):
                w("    (exact string not found as defined data)")

        for ea in DECOMP_EAS:
            to_decomp[ea] = None

        w("\n\n===== decompiles =====")
        for ea in sorted(to_decomp):
            a = af.getAddress(ea)
            fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            if not fn:
                continue
            w("\n// ===== %s @ %s =====" % (fn.getName(), ea))
            res = dec.decompileFunction(fn, 180, mon)
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")

        fh.close()
        print("CMR_DONE wrote %s n=%d" % (OUT, len(to_decomp)))


main()
