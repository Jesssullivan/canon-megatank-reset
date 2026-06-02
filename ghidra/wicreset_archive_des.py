#!/usr/bin/env python3
# wicreset_archive_des.py — pin the APP.BIN cipher. FUN_00427e70 installs
# archive::des::vftable; FUN_00427f10 installs archive::zip::vftable.
# Dump both vtables, decompile the method at vtable+8 (the parse/decrypt the
# mount driver calls and branches on), and locate DES S-boxes / key schedule /
# the key string. Read-only.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-archive-des.txt")


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        p = flat.getCurrentProgram()
        st = p.getSymbolTable()
        af = p.getAddressFactory()
        fm = p.getFunctionManager()
        listing = p.getListing()
        mem = p.getMemory()
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")
            print(s)

        def fname(a):
            f = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            return f.getName() if f else "?"

        def full_path(sym):
            ns = sym.getParentNamespace()
            if ns is None:
                return sym.getName()
            try:
                return ns.getName(True) + "::" + sym.getName()
            except Exception:
                return ns.getName() + "::" + sym.getName()

        # locate the archive::* vtable symbols
        vtabs = {}
        for s in st.getAllSymbols(False):
            if s.getName() == "vftable":
                path = full_path(s)
                ns = s.getParentNamespace()
                nm = ns.getName() if ns else ""
                if "archive" in path or nm in ("des", "zip", "tar", "archive"):
                    vtabs[path] = s.getAddress()

        w("===== archive::* vftables =====")
        for path, addr in sorted(vtabs.items()):
            w("  %s @ %s" % (path, addr))

        dec = DecompInterface()
        dec.openProgram(p)
        mon = ConsoleTaskMonitor()

        slot_targets = []
        for path, addr in sorted(vtabs.items()):
            w("\n----- %s slots -----" % path)
            for i in range(16):
                a = addr.add(i * 4)
                try:
                    raw = mem.getInt(a) & 0xFFFFFFFF
                except Exception:
                    break
                ta = af.getAddress("%08x" % raw)
                w("  slot[%2d] @%s -> %08x  %s" % (i, a, raw, fname(ta)))
                if ("::des" in path) and i in (1, 2, 3, 8):
                    slot_targets.append((path, i, raw))

        # decompile interesting des slots (1,2,3,8) + the methods
        w("\n\n===== decompiled archive::des candidate methods =====")
        done = set()
        for path, i, raw in slot_targets:
            if raw in done:
                continue
            done.add(raw)
            ta = af.getAddress("%08x" % raw)
            fn = fm.getFunctionAt(ta) or fm.getFunctionContaining(ta)
            w("\n// ----- %s slot[%d] -> FUN_%08x -----" % (path, i, raw))
            if fn:
                res = dec.decompileFunction(fn, 150, mon)
                if res and res.decompileCompleted():
                    w(res.getDecompiledFunction().getC())
                else:
                    w("// (decompile failed)")

        # search for DES standard constants: the PC1/IP tables are byte arrays,
        # but the easiest tell is the DES S-box first entry or "DES"/key strings.
        w("\n\n===== string scan: DES / key-ish literals =====")
        DI = listing.getDefinedData(True)
        wanted = ("DES", "des", "key", "Key", "passphrase", "password",
                  "archive", "deflate", "inflate", "blowfish", "Blowfish")
        cnt = 0
        for d in DI:
            dt = d.getDataType().getName().lower()
            if "char" in dt or "string" in dt or "unicode" in dt:
                try:
                    v = d.getValue()
                except Exception:
                    continue
                if v is None:
                    continue
                sv = str(v)
                if 3 <= len(sv) <= 40 and any(k in sv for k in wanted):
                    w("  %s  %r" % (d.getAddress(), sv))
                    cnt += 1
                    if cnt > 80:
                        break

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
