#!/usr/bin/env python3
r"""Dump raw 32-bit words at an address range and disassembly listing of given
function addresses (even tiny/thunk ones). Read-only.
Env CMR_WORDS="addr:count" pairs comma-sep; CMR_DIS=comma func addrs."""
import os

import pyghidra

pyghidra.start()

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
OUT = os.environ["CMR_OUT"]
WORDS = [x.strip() for x in os.environ.get("CMR_WORDS", "").split(",") if x.strip()]
DIS = [x.strip() for x in os.environ.get("CMR_DIS", "").split(",") if x.strip()]


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
    listing = prog.getListing()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")

    def fname(va):
        a = flat.toAddr("%08x" % va)
        fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        return (fn.getName()) if fn else "-"

    for spec in WORDS:
        base, cnt = spec.split(":")
        cnt = int(cnt)
        a = flat.toAddr(base)
        fh.write("\n===== words @ %s (%d) =====\n" % (base, cnt))
        for i in range(cnt):
            try:
                v = mem.getInt(a.add(i * 4)) & 0xFFFFFFFF
            except Exception as e:  # noqa: BLE001
                fh.write("  +%#04x  <fail %s>\n" % (i * 4, e))
                continue
            # ascii view
            chars = "".join(chr(b) if 32 <= b < 127 else "." for b in
                            [(v) & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff])
            fh.write("  +%#04x  %08x  '%s'  %s\n" % (i * 4, v, chars, fname(v)))

    for fa in DIS:
        a = flat.toAddr(fa)
        fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        fh.write("\n===== disasm %s (%s) =====\n" % (fa, fn.getName() if fn else "?"))
        start = fn.getEntryPoint() if fn else a
        instr = listing.getInstructionAt(start)
        n = 0
        while instr is not None and n < 60:
            fh.write("  %s  %s\n" % (instr.getAddress(), instr.toString()))
            if fn and not fn.getBody().contains(instr.getAddress()):
                break
            instr = instr.getNext()
            n += 1

    fh.close()
    print("CMR_DONE wrote", OUT)


_proj, _prog = open_ro()
try:
    run(_prog)
finally:
    _proj.close()
