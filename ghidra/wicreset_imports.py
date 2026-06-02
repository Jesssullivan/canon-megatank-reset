#!/usr/bin/env python3
# wicreset_imports.py — enumerate the PE import table by external library,
# plus search for curl/TLS/HTTP marker strings, to settle whether the network
# stack is named-imported (WinINet/WinHTTP) or statically-linked curl on WS2_32.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-imports.txt")

with open_program(None, project_location=PROJ, project_name=NAME,
                  program_name=PROG, analyze=False) as flat:
    p = flat.getCurrentProgram()
    st = p.getSymbolTable()
    em = p.getExternalManager()
    fh = open(OUT, "w")

    def w(s=""):
        fh.write(s + "\n")
        print(s)

    w("# external libraries / import table")
    libs = list(em.getExternalLibraryNames())
    for lib in sorted(libs):
        names = []
        it = em.getExternalLocations(lib)
        while it.hasNext():
            loc = it.next()
            names.append(loc.getLabel())
        w("LIB %-16s (%d): %s" % (lib, len(names), ", ".join(sorted(names))))
    fh.close()
    print("CMR_DONE wrote %s" % OUT)
