#!/usr/bin/env python3
# wicreset_db_callers.py — LANE C: confirm WHEN the device DB loads by walking
# UP from StartupParseAllDatabases (0x00434310) and the Remote/Common loaders,
# and resolve the app.ini path-construction (FUN_00530ae0) + network-discovery
# object (NETPipeDiscoveryStatic) to settle whether the cloud fetch is required.
#
# Read-only. Reuses the open-by-name pattern.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-db-callers.txt")

# functions whose CALLERS we want (to date the load), and functions to decompile.
CALLERS_OF = ["00434310", "00433ab0", "00433300"]
DECOMP = ["00530ae0"]  # app.ini path builder


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        p = flat.getCurrentProgram()
        fm = p.getFunctionManager()
        rm = p.getReferenceManager()
        af = p.getAddressFactory()
        st = p.getSymbolTable()
        mon = ConsoleTaskMonitor()
        dec = DecompInterface()
        dec.openProgram(p)
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")

        w("===== callers of DB-load functions (to date WHEN the DB loads) =====")
        for tgt in CALLERS_OF:
            a = af.getAddress(tgt)
            fn = fm.getFunctionAt(a)
            nm = fn.getName() if fn else "?"
            w("\n--- callers of %s (%s) ---" % (tgt, nm))
            refs = rm.getReferencesTo(a)
            seen = set()
            for r in refs:
                cfn = fm.getFunctionContaining(r.getFromAddress())
                if cfn:
                    key = cfn.getEntryPoint().toString()
                    if key in seen:
                        continue
                    seen.add(key)
                    w("    <- %s  %s  (%s)" % (key, cfn.getName(), r.getReferenceType()))
            if not seen:
                w("    (no callers — likely a vtable/indirect entry or top-level)")

        # symbols near NETPipeDiscovery to confirm the cloud client object
        w("\n===== NETPipeDiscovery* symbols (the network device-list client) =====")
        it = st.getSymbolIterator()
        cnt = 0
        while it.hasNext() and cnt < 60:
            s = it.next()
            n = s.getName()
            if "NETPipe" in n or "NETHttp" in n or "Discovery" in n or "RemoteControl" in n:
                w("    %s  %s" % (s.getAddress(), n))
                cnt += 1

        # decompile app.ini path builder
        w("\n\n===== app.ini path/config builder =====")
        for ea in DECOMP:
            a = af.getAddress(ea)
            fn = fm.getFunctionAt(a)
            if not fn:
                w("// %s not a function" % ea)
                continue
            w("\n// ===== %s @ %s =====" % (fn.getName(), ea))
            res = dec.decompileFunction(fn, 180, mon)
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
