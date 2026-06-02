#!/usr/bin/env python3
# wicreset_keyword_extract.py — recover the EXACT USB transfer commands.get_keyword
# performs, from the saved read-only Ghidra DB of printerpotty.exe.
#
# Goal: find execute_get_keyword (the function that issues commands.get_keyword),
# decompile it + its send/recv callee, and the functor_initialization (0x004e72b0)
# caller that consumes the keyword, to learn:
#   - the literal [cmd] byte (and arg) get_keyword SENDs (bulk-OUT primer),
#   - the RECV length the keyword reply is read into,
#   - whether it is a SEND-then-RECV (in-band frame) or an EP0 control transfer.
#
# Read-only: opens the EXISTING analyzed program by name; never re-imports.
#
#   GHIDRA_INSTALL_DIR=<...>/lib/ghidra \
#   CMR_PROJ=$PWD/.ghidra-work/project-full \
#   .ghidra-work/.pgvenv12/bin/python ghidra/wicreset_keyword_extract.py
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-keyword-extract.txt")

# functor_initialization (consumes the keyword); the SEND/RECV IOCTL primitives.
FUNCTOR_INIT = "004e72b0"
SEND_PRIM = "0052ce40"   # DeviceIoControl(0x220038) SEND
RECV_PRIM = "0052cab0"   # DeviceIoControl(0x22003c) RECV
# Strings that anchor the get_keyword path.
ANCHOR_STRINGS = [
    "commands.get_keyword", "get_keyword", "keyword", "service.getkeyword",
    "getkeyword", "GetKeyword", "execute_get_keyword",
]


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        p = flat.getCurrentProgram()
        af = p.getAddressFactory()
        listing = p.getListing()
        fm = p.getFunctionManager()
        st = p.getSymbolTable()
        refmgr = p.getReferenceManager()
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        mon = ConsoleTaskMonitor()
        dec = DecompInterface()
        dec.openProgram(p)
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")
            print(s)

        def decomp(fn, tag=""):
            w("// ===== %s %s @ %s =====" % (fn.getName(), tag, fn.getEntryPoint()))
            res = dec.decompileFunction(fn, 200, mon)
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")
            w("")

        # 1. find symbols named *get_keyword* / *getkeyword* / execute_get_keyword
        w("===== named symbols matching keyword/get_keyword =====")
        kw_funcs = set()
        it = st.getSymbolIterator()
        while it.hasNext():
            s = it.next()
            nm = s.getName()
            low = nm.lower()
            if "keyword" in low and ("get" in low or "execute" in low or "fun" in low):
                w("  %-40s @ %s  (%s)" % (nm, s.getAddress(), s.getSymbolType()))
                fn = fm.getFunctionAt(s.getAddress())
                if fn:
                    kw_funcs.add(fn.getEntryPoint().toString())

        # 2. locate the string literals + their data addresses, then xref to code
        w("\n===== string anchors + code xrefs (the function that USES get_keyword) =====")
        di = listing.getDefinedData(True)
        anchor_addrs = {}
        while di.hasNext():
            d = di.next()
            v = d.getValue()
            if v is None:
                continue
            s = str(v)
            if not isinstance(s, str):
                continue
            for a in ANCHOR_STRINGS:
                if s == a or (a == "keyword" and s in ("keyword.index", "keyword.codes")):
                    anchor_addrs.setdefault(s, []).append(d.getAddress())
        caller_funcs = set()
        for s, addrs in anchor_addrs.items():
            for da in addrs:
                refs = refmgr.getReferencesTo(da)
                for r in refs:
                    fa = r.getFromAddress()
                    fn = fm.getFunctionContaining(fa)
                    nm = fn.getName() if fn else "?"
                    ea = fn.getEntryPoint().toString() if fn else "?"
                    w("  str %-22r @ %s  used-by %s @ %s (from %s)" % (s, da, nm, ea, fa))
                    if fn:
                        caller_funcs.add(ea)

        # 3. decompile functor_initialization + every get_keyword caller/func we found
        w("\n===== decompiles =====")
        targets = set()
        targets.update(kw_funcs)
        targets.update(caller_funcs)
        fi = fm.getFunctionAt(af.getAddress(FUNCTOR_INIT))
        if fi:
            targets.add(fi.getEntryPoint().toString())
        # also: who calls functor_initialization (the session setup that runs get_keyword)
        if fi:
            for r in refmgr.getReferencesTo(af.getAddress(FUNCTOR_INIT)):
                cfn = fm.getFunctionContaining(r.getFromAddress())
                if cfn:
                    targets.add(cfn.getEntryPoint().toString())
                    w("  functor_initialization called-by %s @ %s" % (
                        cfn.getName(), cfn.getEntryPoint()))

        for ea in sorted(targets):
            fn = fm.getFunctionAt(af.getAddress(ea))
            if fn:
                decomp(fn)

        # 4. ALSO decompile the SEND/RECV primitives so we can read the [cmd] byte
        #    and the RECV length used along the keyword path.
        w("\n===== SEND / RECV primitives (for cmd byte + recv length) =====")
        for ea in (SEND_PRIM, RECV_PRIM):
            fn = fm.getFunctionAt(af.getAddress(ea))
            if fn:
                decomp(fn, tag="(IO primitive)")

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
