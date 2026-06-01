#!/usr/bin/env python3
# wicreset_tmplsrc_crypt.py — find the WinCrypt key-derivation for the APP.BIN
# VFS decrypt, and whether the key material is STATIC (hardcoded) in the binary.
# Read-only.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-crypt-trace.txt")

CRYPT_APIS = ["CryptAcquireContextW", "CryptImportKey", "CryptHashData",
              "CryptCreateHash", "CryptDecrypt", "CryptDeriveKey",
              "CryptStringToBinaryW", "CryptDecodeObjectEx", "CryptGetHashParam"]


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

        def func_of(addr):
            f = fm.getFunctionContaining(addr)
            return f.getName() + "@" + f.getEntryPoint().toString() if f else "?@" + addr.toString()

        crypt_callers = set()
        w("===== WinCrypt API call sites =====")
        for api in CRYPT_APIS:
            syms = [s for s in st.getAllSymbols(False) if s.getName() == api]
            for sym in syms:
                a = sym.getAddress()
                it = refmgr.getReferencesTo(a)
                rows = []
                for r in it:
                    fa = r.getFromAddress()
                    rows.append((fa, func_of(fa)))
                if rows:
                    w("\n## %s @ %s (%d sites)" % (api, a, len(rows)))
                    for fa, fn in rows:
                        w("    %s  %s" % (fa, fn))
                        crypt_callers.add(fn.split("@")[-1])

        # decompile each distinct crypt-caller to reveal the key material
        dec = DecompInterface()
        dec.openProgram(p)
        mon = ConsoleTaskMonitor()
        w("\n\n===== decompiles of WinCrypt callers (look for hardcoded key/pwd) =====")
        for h in sorted(crypt_callers):
            if not h or h == "?":
                continue
            a = af.getAddress(h)
            fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            if not fn:
                continue
            res = dec.decompileFunction(fn, 200, mon)
            w("\n// ===== %s @ %s =====" % (fn.getName(), h))
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
