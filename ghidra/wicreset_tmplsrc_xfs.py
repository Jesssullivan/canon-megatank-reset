#!/usr/bin/env python3
# wicreset_tmplsrc_xfs.py — resolve the XFSVirtual filesystem that wraps APP.BIN
# and find the per-file DECRYPT/INFLATE, plus how the template tree is built from
# files inside it.  Read-only.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-xfs-trace.txt")

NAME_SUBSTR = ["XFS", "Virtual", "inflate", "Inflate", "zlib", "uncompress",
               "Crypt", "crypt", "Cipher", "AES", "Blowfish", "rc4", "RC4",
               "decrypt", "Decrypt", "ptree", "property_tree", "json", "JSON",
               "parse", "Parse", "wxZip", "ZipInputStream", "Decompress"]


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        p = flat.getCurrentProgram()
        st = p.getSymbolTable()
        af = p.getAddressFactory()
        fm = p.getFunctionManager()
        refmgr = p.getReferenceManager()
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")
            print(s)

        # 1. symbols whose name hints VFS/crypt/inflate/parse
        w("===== symbols matching VFS/crypt/inflate/parse hints =====")
        hits = []
        for s in st.getAllSymbols(False):
            n = s.getName()
            for sub in NAME_SUBSTR:
                if sub in n:
                    hits.append((s.getAddress().toString(), n))
                    break
        seen = set()
        for a, n in sorted(hits):
            if (a, n) in seen:
                continue
            seen.add((a, n))
            w("  %s  %s" % (a, n))

        # 2. find the XFSVirtual vftable + its method slots
        w("\n===== XFSVirtual vftable methods =====")
        vt = None
        for s in st.getAllSymbols(False):
            if s.getName() == "vftable" and s.getParentNamespace() and \
               "XFSVirtual" in str(s.getParentNamespace().getName()):
                vt = s.getAddress()
        # fall back: name search
        if vt is None:
            for s in st.getAllSymbols(False):
                if "XFSVirtual::vftable" in s.getName():
                    vt = s.getAddress()
        if vt:
            w("  XFSVirtual::vftable @ %s" % vt)
            listing = p.getListing()
            for i in range(12):
                a = vt.add(i * 4)
                d = listing.getDataAt(a)
                if d is None:
                    continue
                val = d.getValue()
                w("    slot[%2d] @ %s -> %s  (%s)" % (i, a, val, func_name(fm, af, val)))
        else:
            w("  (XFSVirtual::vftable symbol not found)")

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


def func_name(fm, af, val):
    try:
        a = af.getAddress(hex(val.getOffset())[2:]) if hasattr(val, "getOffset") else None
    except Exception:
        a = None
    if a is None:
        return "?"
    f = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
    return f.getName() if f else "?"


main()
