#!/usr/bin/env python3
# wicreset_template_load.py — LANE C: find WHERE/WHEN the per-model device
# template is loaded into memory and from WHAT source (bundled file vs cloud).
#
# Anchors on the on-disk/template/cloud strings discovered via `strings`:
#   devices.xml, devices.srs, network/devices, network/enabled, app.ini,
#   <commands><raw>, Core::UpdateSupportList, Core::UpdatePresentList,
# resolves their xref'ing functions, and decompiles each so we can see:
#   - is devices.xml/.srs opened from disk (CreateFileW/fopen/wxFile) or
#     written from an HTTP body?
#   - does an HTTP POST to network/devices populate the template tree?
#   - when (startup ctor, key entry, device select) is the loader called?
#
# Read-only: opens the EXISTING analyzed program by name; never re-imports.
#
#   GHIDRA_INSTALL_DIR=<...>/lib/ghidra \
#   CMR_PROJ=$PWD/.ghidra-work/project-full \
#   .ghidra-work/.pgvenv12/bin/python ghidra/wicreset_template_load.py
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-template-load.txt")

NEEDLES = [
    "devices.xml", "devices.srs", "app.ini",
    "network/devices", "network/enabled",
    "<commands><raw>", "</raw></commands>",
    "Core::UpdateSupportList", "Core::UpdatePresentList",
    "Update devices list.",
    "Failed sending HTTP POST request", "network/",
]


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        p = flat.getCurrentProgram()
        mem = p.getMemory()
        listing = p.getListing()
        fm = p.getFunctionManager()
        rm = p.getReferenceManager()
        mon = ConsoleTaskMonitor()
        dec = DecompInterface()
        dec.openProgram(p)
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")

        # 1. locate each needle string in memory, then find the functions that
        #    reference it (via defined-data address xrefs).
        decompiled = {}  # addr -> name, to dedup
        w("===== needle string -> referencing functions =====")
        di = listing.getDefinedData(True)
        hits = {}
        while di.hasNext():
            d = di.next()
            v = d.getValue()
            if v is None:
                continue
            s = str(v) if not isinstance(v, str) else v
            for n in NEEDLES:
                if n in s and (s == n or n in ("network/", )):
                    hits.setdefault(n, []).append((d.getAddress(), s))

        funcs_to_decomp = {}
        for n in NEEDLES:
            w("\n--- %r ---" % n)
            for (addr, s) in hits.get(n, []):
                refs = rm.getReferencesTo(addr)
                callers = set()
                for r in refs:
                    fa = r.getFromAddress()
                    fn = fm.getFunctionContaining(fa)
                    if fn:
                        callers.add((fn.getEntryPoint().toString(), fn.getName()))
                w("  str@%s  %r" % (addr, (s[:60] + "..." if len(s) > 60 else s)))
                if not callers:
                    w("    (no wired xrefs to this data)")
                for (ea, nm) in sorted(callers):
                    w("    <- %s  %s" % (ea, nm))
                    funcs_to_decomp[ea] = nm

        # 2. decompile each referencing function
        w("\n\n===== decompiled referencing functions =====")
        for ea, nm in sorted(funcs_to_decomp.items()):
            af = p.getAddressFactory()
            a = af.getAddress(ea)
            fn = fm.getFunctionAt(a)
            if not fn:
                continue
            w("\n// ===== %s @ %s =====" % (nm, ea))
            res = dec.decompileFunction(fn, 180, mon)
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")

        fh.close()
        print("CMR_DONE wrote %s funcs=%d" % (OUT, len(funcs_to_decomp)))


main()
