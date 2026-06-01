#!/usr/bin/env python3
# wicreset_tmplsrc_trace.py — LANE A: resolve the template-table SOURCE fork.
#
# Question: the Canon reset frame is built from a dotted-path template tree
# (functions.waste, commands.*, command.index/codes/shift, keyword.*, functor).
# WHERE does that tree's DATA come from?  Four candidates:
#   (a) .rdata constant table   (b) embedded PE resource (FindResource/LoadResource)
#   (c) file parsed from disk    (d) filled from a network/curl response
#
# Strategy (all read-only against the saved analyzed DB):
#   1. Resolve the dotted-path ACCESSOR funcs (FUN_00522ac0 etc.) and the array
#      readers (FUN_0045ee10 "command.index"...). Walk UP N levels of callers to
#      find the tree BUILDER / loader.
#   2. Map the PE-resource API call sites (FindResourceW/LoadResource/LockResource/
#      SizeofResource) and their callers — does any feed a parser that the reset
#      path consumes?
#   3. Map the parser entry points (look for the string keys' xrefs: which funcs
#      reference 'functions.waste'/'command.index'/'commands.set_command'?). The
#      func that references the MOST of these keys is the template consumer; the
#      func that PRODUCES the tree it reads is the loader.
#   4. Cross-ref the curl/network funcs already identified (QUERY_KEYS 0x0051c700,
#      RESET_DATA 0x0051da40, and any curl_easy_perform) to see if the tree is
#      populated from a response buffer.
#
#   GHIDRA_INSTALL_DIR=<...>/lib/ghidra CMR_PROJ=$PWD/.ghidra-work/project-full \
#   .ghidra-work/.pgvenv12/bin/python ghidra/wicreset_tmplsrc_trace.py
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-tmplsrc-trace.txt")

# template string keys whose code xrefs reveal the consumer/loader funcs
TEMPLATE_KEY_ADDRS = {
    "functions.waste": "0097a494",
    "commands.set_command": "009869b4",
    "commands.get_command": "0098699c",
    "commands.set_session": "009868cc",
    "commands.get_keyword": "0098695c",
    "command.index": "0098663c",
    "command.codes": "00986664",
    "command.shift": "00986654",
    "keyword.index": "00986534",
    "keyword.codes": "0098656c",
    "functor": "00986ae8",
    "encoders": "00986f10",
    "statuses": "00986fe4",
    "indexes": "009867a4",
    "special": "009867ac",
    "model.value": "0096efcc",
}

# resource API thunks — resolve by external symbol name
RES_APIS = ["FindResourceW", "LoadResource", "LockResource", "SizeofResource",
            "FindResourceExW"]
NET_APIS = ["recv", "WSARecv"]


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        p = flat.getCurrentProgram()
        af = p.getAddressFactory()
        fm = p.getFunctionManager()
        st = p.getSymbolTable()
        refmgr = p.getReferenceManager()
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")
            print(s)

        def func_of(addr):
            f = fm.getFunctionContaining(addr)
            return f.getName() + "@" + f.getEntryPoint().toString() if f else "?"

        def code_xrefs_to(addr):
            res = []
            it = refmgr.getReferencesTo(addr)
            for r in it:
                fa = r.getFromAddress()
                res.append((fa, func_of(fa), str(r.getReferenceType())))
            return res

        # ---- 1. who references each template key string ------------------
        w("===== funcs that reference each template-key string (the CONSUMERS) =====")
        consumer_count = {}
        for key, hexa in TEMPLATE_KEY_ADDRS.items():
            a = af.getAddress(hexa)
            xs = code_xrefs_to(a)
            w("\n## %-22s @ %s  (%d xref)" % (key, hexa, len(xs)))
            for fa, fn, rt in xs:
                w("    %s  in %s  [%s]" % (fa, fn, rt))
                consumer_count[fn] = consumer_count.get(fn, 0) + 1
        w("\n--- consumer funcs ranked by #distinct template keys referenced ---")
        for fn, c in sorted(consumer_count.items(), key=lambda x: -x[1]):
            w("    %3d  %s" % (c, fn))

        # ---- 2. resource API call sites + callers -------------------------
        w("\n\n===== PE-resource API call sites (FindResource/LoadResource/...) =====")
        for api in RES_APIS:
            syms = st.getGlobalSymbols(api)
            if not syms:
                # try external
                syms = [s for s in st.getAllSymbols(False) if s.getName() == api]
            hit_any = False
            for sym in syms:
                a = sym.getAddress()
                xs = code_xrefs_to(a)
                if not xs:
                    continue
                hit_any = True
                w("\n## %s @ %s  (%d call site)" % (api, a, len(xs)))
                for fa, fn, rt in xs:
                    w("    called from %s  in %s" % (fa, fn))
            if not hit_any:
                w("\n## %s : no resolved call sites via symbol table" % api)

        # ---- 3. network recv sites ---------------------------------------
        w("\n\n===== network recv() / WSARecv() call sites =====")
        for api in NET_APIS:
            syms = [s for s in st.getAllSymbols(False) if s.getName() == api]
            for sym in syms:
                a = sym.getAddress()
                xs = code_xrefs_to(a)
                if not xs:
                    continue
                w("\n## %s @ %s  (%d call site)" % (api, a, len(xs)))
                for fa, fn, rt in xs[:30]:
                    w("    called from %s  in %s" % (fa, fn))

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
