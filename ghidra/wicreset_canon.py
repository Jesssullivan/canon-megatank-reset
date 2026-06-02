#!/usr/bin/env python3
# wicreset_canon.py — resolve the PrinterCanonSTD method strings to FUNCTIONS,
# decompile the Canon reset chain, and detect any network (curl) call inside it.
#
# Strategy: the method-name strings (e.g. "PrinterCanonSTD::clearCounters") are
# C++ __FUNCTION__ literals embedded in their own function bodies (MSVC habit) or
# referenced by logging. For each needle string we:
#   1. find its address,
#   2. find instruction xrefs to it,
#   3. the containing function = the Canon method (or a close caller),
#   4. decompile it,
#   5. scan its decompilation + its direct callees for WS2_32/WSOCK32 ordinals
#      and curl 'easy_perform'/'http' markers => network-touch flag.
import os
import re
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-canon.txt")

NEEDLES = [
    "PrinterCanonSTD::clearCounters",
    "PrinterCanonSTD::action_is_permitted",
    "PrinterCanonSTD::execute_set_command",
    "PrinterCanonSTD::execute_get_command",
    "PrinterCanonSTD::execute_set_session",
    "PrinterCanonSTD::service_send_buffer",
    "PrinterCanonSTD::service_read_buffer",
    "PrinterCanonSTD::service_perform_command_single",
    "PrinterCanonSTD::service_perform_command_common",
    "PrinterCanonSTD::functor_encryption_003",
    "PrinterCanonSTD::execute_one_command",
    "Core::ActionCanonDeviceClearCounters",
    "Core::ActionCanonDeviceQueryFeatures",
    "Core::ActionCanonDeviceTestHardLimit",
]


def find_string_addr(flat, mem, s):
    """Find address(es) of an ASCII C-string via findBytes(start, regex, limit)."""
    needle = re.escape(s.encode("ascii"))
    uniq = []
    seen = set()
    # mem.findBytes(start, bytes-pattern, mask, forward, monitor) is finicky;
    # use flat.findBytes(start, regexStr, matchLimit) which returns Address[].
    start = mem.getMinAddress()
    res = flat.findBytes(start, needle, 8)
    if res is not None:
        try:
            it = list(res)
        except TypeError:
            it = [res]
        for x in it:
            if x and x.toString() not in seen:
                seen.add(x.toString())
                uniq.append(x)
    return uniq


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        p = flat.getCurrentProgram()
        fm = p.getFunctionManager()
        st = p.getSymbolTable()
        refmgr = p.getReferenceManager()
        mem = p.getMemory()
        em = p.getExternalManager()
        mon = ConsoleTaskMonitor()

        # Build a set of WS2_32/WSOCK32 import addresses -> label, for callee net detection
        net_addrs = {}
        for lib in ("WS2_32.DLL", "WSOCK32.DLL"):
            it = em.getExternalLocations(lib)
            while it.hasNext():
                loc = it.next()
                for sym in st.getSymbols(loc.getLabel()):
                    net_addrs[sym.getAddress().toString()] = "%s!%s" % (lib, loc.getLabel())

        dec = DecompInterface()
        dec.openProgram(p)

        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")
            print(s)

        def callees_net(fn):
            """Does fn call any WS2_32/WSOCK32 import directly?"""
            hits = set()
            body = fn.getBody()
            ai = p.getListing().getInstructions(body, True)
            while ai.hasNext():
                ins = ai.next()
                for ref in ins.getReferencesFrom():
                    ta = ref.getToAddress().toString()
                    if ta in net_addrs:
                        hits.add(net_addrs[ta])
            return hits

        resolved = {}
        for s in NEEDLES:
            addrs = find_string_addr(flat, mem, s)
            if not addrs:
                w("## %-50s : STRING NOT FOUND" % s)
                continue
            funcs = {}
            for a in addrs:
                for r in refmgr.getReferencesTo(a):
                    fn = fm.getFunctionContaining(r.getFromAddress())
                    if fn:
                        funcs[fn.getEntryPoint().toString()] = fn
            w("## %-50s str@%s -> %d ref-fn(s): %s" % (
                s, addrs[0], len(funcs),
                ", ".join("%s" % k for k in sorted(funcs))))
            for ea, fn in funcs.items():
                resolved[ea] = (s, fn)

        w()
        w("===== DECOMPILE Canon methods + NET-TOUCH flag =====")
        for ea in sorted(resolved):
            label, fn = resolved[ea]
            net = callees_net(fn)
            w("\n// ===== %s  @%s  (tag:%s)  NET=%s =====" % (
                fn.getName(), ea, label, ("YES " + ",".join(sorted(net))) if net else "no"))
            res = dec.decompileFunction(fn, 120, mon)
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")
        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
