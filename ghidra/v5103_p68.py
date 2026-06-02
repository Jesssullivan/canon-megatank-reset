#!/usr/bin/env python3
r"""Resolve vtable +0x68 targets for the three transports, and decompile
FUN_0042b000 (device-read primitive used by the FUN_0042b830 preamble-seed)
and FUN_0042b8a0 if present. Read-only 12.0.2 DB."""
import os
import pyghidra
pyghidra.start()
PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
OUT = os.environ["CMR_OUT"]


def main():
    from ghidra.base.project import GhidraProject
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.task import ConsoleTaskMonitor
    proj = GhidraProject.openProject(PROJ, PROJ_NAME, False)
    prog = proj.openProgram("/", "ServiceTool_v5103.exe", True)
    flat = FlatProgramAPI(prog); fm = prog.getFunctionManager(); mem = prog.getMemory()
    mon = ConsoleTaskMonitor(); dec = DecompInterface(); dec.openProgram(prog)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")

    def clean(s):
        return "".join(c if (32 <= ord(c) < 127 or c == "\n") else "." for c in s)
    def rd32(a): return mem.getInt(flat.toAddr(a)) & 0xFFFFFFFF
    def fname(a):
        f = fm.getFunctionAt(flat.toAddr(a)) or fm.getFunctionContaining(flat.toAddr(a))
        return f.getName() if f else "-"
    def dump(fa, tag=""):
        a = flat.toAddr(fa); fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        if not fn:
            fh.write("\n// no func at %08x %s\n" % (fa, tag)); return
        fh.write("\n// ===== %s @ %08x %s =====\n" % (fn.getName(), fa, tag))
        r = dec.decompileFunction(fn, 200, mon)
        fh.write(clean(r.getDecompiledFunction().getC() if r and r.decompileCompleted() else "//fail\n"))

    fh.write("######## vtable +0x68 targets ########\n")
    for base, lbl in ((0x472188, "usbscan"), (0x4721f0, "USBPRINT"), (0x472260, "variant")):
        t = rd32(base + 0x68)
        fh.write("  %-8s 0x%08x +0x68 -> %08x %s\n" % (lbl, base, t, fname(t)))

    # decompile the +0x68 target (FUN_00434200), FUN_0042b000 (device read),
    # FUN_0042afe0/aff0 (open/close), FUN_0042b800 if exists
    dump(0x434200, "(0x4721f0 +0x68)")
    dump(0x42b000, "(device-read primitive used to seed DAT_004921f8)")
    dump(0x42afe0, "(open)")
    dump(0x42aff0, "(close)")
    # is there a FUN_0042b800?
    fn = fm.getFunctionAt(flat.toAddr(0x42b800))
    if fn: dump(0x42b800, "(?)")
    else: fh.write("\n// FUN_0042b800 does not exist\n")

    # who calls FUN_0042b830 (the preamble-seed writer)?
    fh.write("\n######## callers of FUN_0042b830 ########\n")
    fn = fm.getFunctionAt(flat.toAddr(0x42b830))
    if fn:
        for c in fn.getCallingFunctions(mon):
            fh.write("  %s @ %s\n" % (c.getName(), c.getEntryPoint()))

    fh.close(); print("CMR_DONE wrote", OUT); proj.close()


main()
