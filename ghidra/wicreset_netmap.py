#!/usr/bin/env python3
# wicreset_netmap.py — map the (curl) network bottom-half and the URL/cloud
# strings, to answer local-vs-cloud.
#
#  (a) WS2_32 ordinal call sites: Ordinal_4=closesocket, _9=getpeername(?),
#      _16=recv, _19=send, _23=socket, _4=connect order varies; we just dump
#      callers of EVERY WS2_32/WSOCK32 ordinal so the curl socket funcs surface.
#  (b) cloud/URL/host strings + their referencing functions (the HTTP targets).
#  (c) "Reset Key"/license strings + referencing functions (the key gate).
import os
import re
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-netmap.txt")

URL_PATTERNS = [
    rb"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,}",
    rb"wic[a-z._-]*", rb"reset[a-z._-]*connect", rb"[a-z0-9.-]+\.com\b",
]
KEYWORDS = [b"Reset Key", b"reset key", b"reset_key", b"license", b"License",
            b"WIC Reset Connect", b"Remote server", b"redeem", b"token",
            b"activation", b"Check Reset", b"Buy reset", b"serial"]


def fns_referencing(p, fm, refmgr, addr):
    out = set()
    for r in refmgr.getReferencesTo(addr):
        fn = fm.getFunctionContaining(r.getFromAddress())
        if fn is not None:
            out.add((fn.getEntryPoint().toString(), fn.getName()))
        else:
            out.add(("(data@%s)" % r.getFromAddress(), ""))
    return out


with open_program(None, project_location=PROJ, project_name=NAME,
                  program_name=PROG, analyze=False) as flat:
    from ghidra.program.model.address import AddressSet
    p = flat.getCurrentProgram()
    fm = p.getFunctionManager()
    st = p.getSymbolTable()
    refmgr = p.getReferenceManager()
    mem = p.getMemory()
    listing = p.getListing()
    fh = open(OUT, "w")

    def w(s=""):
        fh.write(s + "\n")
        print(s)

    # (a) WS2_32 / WSOCK32 ordinal callers
    w("===== WS2_32 / WSOCK32 ORDINAL CALL SITES (curl socket bottom-half) =====")
    em = p.getExternalManager()
    for lib in ("WS2_32.DLL", "WSOCK32.DLL"):
        it = em.getExternalLocations(lib)
        while it.hasNext():
            loc = it.next()
            label = loc.getLabel()
            for sym in st.getSymbols(label):
                callers = {}
                for r in refmgr.getReferencesTo(sym.getAddress()):
                    fn = fm.getFunctionContaining(r.getFromAddress())
                    if fn:
                        callers[fn.getEntryPoint().toString()] = fn.getName()
                    else:
                        for r2 in refmgr.getReferencesTo(r.getFromAddress()):
                            fn2 = fm.getFunctionContaining(r2.getFromAddress())
                            if fn2:
                                callers[fn2.getEntryPoint().toString()] = fn2.getName()
                if callers:
                    w("  %-12s %-14s -> %s" % (lib, label,
                      ", ".join("%s" % a for a in sorted(callers))))

    # (b)+(c) defined-string search and referencing functions
    w()
    w("===== URL / CLOUD / KEY STRINGS + referencing functions =====")
    pats = [re.compile(x, re.I) for x in URL_PATTERNS]
    seen = set()
    sit = listing.getDefinedData(True)
    count = 0
    while sit.hasNext() and count < 400000:
        d = sit.next()
        count += 1
        try:
            v = d.getValue()
        except Exception:
            continue
        if not isinstance(v, str):
            continue
        bs = v.encode("latin-1", "ignore")
        hit = None
        for kw in KEYWORDS:
            if kw in bs:
                hit = v
                break
        if hit is None:
            for pat in pats:
                if pat.search(bs):
                    hit = v
                    break
        if hit is not None:
            addr = d.getAddress()
            key = addr.toString()
            if key in seen:
                continue
            seen.add(key)
            refs = fns_referencing(p, fm, refmgr, addr)
            disp = hit if len(hit) < 90 else hit[:90] + "..."
            w("  @%s  %r" % (addr, disp))
            for ea, nm in sorted(refs):
                w("        <- %s %s" % (ea, nm))
    fh.close()
    print("CMR_DONE wrote %s" % OUT)
