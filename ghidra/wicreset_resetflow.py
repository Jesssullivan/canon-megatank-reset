#!/usr/bin/env python3
# wicreset_resetflow.py — walk the reset-button call graph and find where (if
# anywhere) curl/sockets are invoked relative to the Canon USB write.
#
#  UP:   from ActionCanonDeviceClearCounters / clearCounters, climb callers N
#        levels; flag any function whose subtree calls WS2_32/WSOCK32 (net).
#  KEY:  resolve the key/license UI strings -> referencing functions; for each,
#        does it (or its callees, 1 level) call net?  -> key-validation transport.
#  Also: identify the curl 'easy perform' entry (the function that ALL socket
#        funcs funnel through) so we know the single cloud choke point.
import os
import re
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-resetflow.txt")

# Canon write/reset anchors (entry points found earlier)
ANCHORS = {
    "0043fbc0": "ActionCanonDeviceClearCounters",
    "004ecae0": "PrinterCanonSTD::clearCounters",
    "004ec120": "PrinterCanonSTD::service_perform_command_common",
    "004ea540": "PrinterCanonSTD::service_send_buffer/execute_set_command",
}
KEY_STRINGS = [
    "Check Reset Key", "Enter reset key here", "Enter key here",
    "reset key may be lost", "one time trial key", "type the word `trial`",
    "stable internet connection and a reset key", "purchase and use a reset key",
    "Reset key, that will be used",
]


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        p = flat.getCurrentProgram()
        af = p.getAddressFactory()
        fm = p.getFunctionManager()
        st = p.getSymbolTable()
        refmgr = p.getReferenceManager()
        mem = p.getMemory()
        em = p.getExternalManager()
        listing = p.getListing()
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")
            print(s)

        # net import address set
        net_addrs = {}
        for lib in ("WS2_32.DLL", "WSOCK32.DLL"):
            it = em.getExternalLocations(lib)
            while it.hasNext():
                loc = it.next()
                for sym in st.getSymbols(loc.getLabel()):
                    net_addrs[sym.getAddress().toString()] = "%s!%s" % (lib, loc.getLabel())

        def fn_at(ea_str):
            a = af.getAddress(ea_str)
            return fm.getFunctionAt(a) or fm.getFunctionContaining(a)

        def direct_callees(fn):
            outs = set()
            ai = listing.getInstructions(fn.getBody(), True)
            while ai.hasNext():
                ins = ai.next()
                for ref in ins.getReferencesFrom():
                    ta = ref.getToAddress()
                    cf = fm.getFunctionContaining(ta)
                    if cf and cf.getEntryPoint() != fn.getEntryPoint():
                        outs.add(cf)
                    if ta.toString() in net_addrs:
                        outs.add(("NET", net_addrs[ta.toString()]))
            return outs

        def subtree_net(fn, maxnodes=4000):
            """BFS down from fn; return set of net labels reachable."""
            seen = set()
            stack = [fn]
            found = set()
            n = 0
            while stack and n < maxnodes:
                cur = stack.pop()
                if isinstance(cur, tuple):
                    if cur[0] == "NET":
                        found.add(cur[1])
                    continue
                ep = cur.getEntryPoint().toString()
                if ep in seen:
                    continue
                seen.add(ep)
                n += 1
                for c in direct_callees(cur):
                    if isinstance(c, tuple):
                        found.add(c[1])
                    else:
                        stack.append(c)
            return found, n

        def callers(fn):
            out = {}
            for r in refmgr.getReferencesTo(fn.getEntryPoint()):
                cf = fm.getFunctionContaining(r.getFromAddress())
                if cf:
                    out[cf.getEntryPoint().toString()] = cf
            return out

        # ---- UP-walk from anchors ----
        w("===== UP-WALK from Canon write anchors (caller levels), net-subtree flag =====")
        for ea, label in ANCHORS.items():
            fn = fn_at(ea)
            if not fn:
                w("anchor %s (%s): NOT A FUNCTION" % (ea, label))
                continue
            w("\n# anchor %s %s" % (ea, label))
            frontier = {ea: fn}
            allseen = set(frontier)
            for level in range(0, 4):
                nextf = {}
                for cea, cfn in frontier.items():
                    netset, nodes = subtree_net(cfn, maxnodes=1500)
                    flag = ("NET{%s}" % ",".join(sorted(netset))) if netset else "no-net"
                    w("  L%d %s %-44s subtree=%d %s" % (
                        level, cea, cfn.getName(), nodes, flag))
                    for kea, kfn in callers(cfn).items():
                        if kea not in allseen:
                            nextf[kea] = kfn
                            allseen.add(kea)
                frontier = nextf
                if not frontier:
                    w("  L%d (no more callers)" % (level + 1))
                    break

        # ---- KEY strings ----
        w("\n===== KEY / LICENSE strings -> functions + net flag =====")
        for s in KEY_STRINGS:
            needle = re.escape(s.encode("ascii"))
            res = flat.findBytes(mem.getMinAddress(), needle, 4)
            if res is None:
                w("  %r : NOT FOUND" % s)
                continue
            try:
                addrs = list(res)
            except TypeError:
                addrs = [res]
            fns = {}
            for a in addrs:
                for r in refmgr.getReferencesTo(a):
                    cf = fm.getFunctionContaining(r.getFromAddress())
                    if cf:
                        fns[cf.getEntryPoint().toString()] = cf
            if not fns:
                w("  %r @%s : (no code xref)" % (s, addrs[0]))
            for cea, cfn in fns.items():
                netset, nodes = subtree_net(cfn, maxnodes=2500)
                flag = ("NET{%s}" % ",".join(sorted(netset))) if netset else "no-net"
                w("  %r -> %s %s subtree=%d %s" % (s[:34], cea, cfn.getName(), nodes, flag))

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
