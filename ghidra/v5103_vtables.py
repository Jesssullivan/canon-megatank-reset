#!/usr/bin/env python3
r"""Dump pointer tables (vtables) at given addresses + decompile each slot's
target, read-only. Also dumps the function containing a 'no-func' write addr by
disassembling around it. Env CMR_VT=comma hex base addrs; CMR_VT_SLOTS=count."""
import os

import pyghidra

pyghidra.start()

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
OUT = os.environ["CMR_OUT"]
VT = [x.strip() for x in os.environ.get("CMR_VT", "").split(",") if x.strip()]
SLOTS = int(os.environ.get("CMR_VT_SLOTS", "32"))
# addresses to disassemble-around (resolve which function contains a write)
NEAR = [x.strip() for x in os.environ.get("CMR_NEAR", "").split(",") if x.strip()]


def open_ro():
    from ghidra.base.project import GhidraProject

    proj = GhidraProject.openProject(PROJ, PROJ_NAME, False)
    prog = None
    for nm in (PROG_NAME, PROG_NAME.replace(".exe", "")):
        try:
            prog = proj.openProgram("/", nm, True)
            if prog is not None:
                break
        except Exception:  # noqa: BLE001
            pass
    return proj, prog


def run(prog):
    from ghidra.program.flatapi import FlatProgramAPI

    flat = FlatProgramAPI(prog)
    fm = prog.getFunctionManager()
    mem = prog.getMemory()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")

    def rd32(addr):
        return mem.getInt(addr) & 0xFFFFFFFF

    def fname(va):
        a = flat.toAddr("%08x" % va)
        fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        return (fn.getName() + " @ " + fn.getEntryPoint().toString()) if fn else "(no func)"

    for base in VT:
        fh.write("\n===== vtable @ %s =====\n" % base)
        a = flat.toAddr(base)
        for i in range(SLOTS):
            try:
                ptr = rd32(a.add(i * 4))
            except Exception as e:  # noqa: BLE001
                fh.write("  [+%#04x] <read fail %s>\n" % (i * 4, e))
                break
            if ptr < 0x401000 or ptr > 0x4a0000:
                fh.write("  [+%#04x] %08x  (non-code; stop?)\n" % (i * 4, ptr))
                # don't stop hard; tables can have gaps, but flag
            else:
                fh.write("  [+%#04x] %08x  %s\n" % (i * 4, ptr, fname(ptr)))

    for n in NEAR:
        a = flat.toAddr(n)
        fn = fm.getFunctionContaining(a)
        fh.write("\n===== near %s -> %s =====\n"
                 % (n, (fn.getName() + " @ " + fn.getEntryPoint().toString()) if fn else "(no func)"))

    fh.close()
    print("CMR_DONE wrote", OUT)


_proj, _prog = open_ro()
try:
    run(_prog)
finally:
    _proj.close()
