#!/usr/bin/env python3
r"""Decompile the WRITERS of the runtime globals (DAT_004921f8/9, DAT_00494ca0)
and resolve the USBPRINT transport's [this+0x68] lower writer. Read-only,
12.0.2 DB. Also dumps FUN_004302c0's actual call site to confirm the usbscan
vtable+0x68 vs the USBPRINT one, and the transport-construction site that sets
the runtime vtable for the printer-class object."""
import os
import pyghidra
pyghidra.start()
PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
OUT = os.environ["CMR_OUT"]

# writers of the runtime globals + the EncComm-wrapper slot funcs that call
# transport+0x60..+0x68, + the discovery/construction funcs.
FUNCS = [
    0x42b830,   # WRITE DAT_004921f8/9
    0x409c60,   # WRITE DAT_00494ca0
    0x40dd80,   # WRITE DAT_00494ca0 (title-bar/probe)
    0x402490, 0x40aa30,  # READers of the preamble globals (sibling dispatchers)
    0x4306a0, 0x430620,  # helpers used by FUN_00430720 (the +0x68 caller)
    0x430830, 0x430850,  # USBPRINT vtable +0x48/+0x4c
    0x4308e0,            # vtable +0x50 (returns sub-object)
    0x42cec0, 0x42ca40, 0x42c950, 0x42ca00,  # EncComm send wrappers
    0x42fc80,            # transport picker
]


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

    def dump(fa):
        a = flat.toAddr(fa); fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        if not fn:
            fh.write("\n// no func at %08x\n" % fa); return
        fh.write("\n// ===================== %s @ %08x =====================\n"
                 % (fn.getName(), fa))
        r = dec.decompileFunction(fn, 240, mon)
        fh.write(clean(r.getDecompiledFunction().getC() if r and r.decompileCompleted()
                       else "// (decompile failed)\n"))

    for fa in FUNCS:
        dump(fa)

    # what is USBPRINT vtable 0x4721f0 +0x68 ? and usbscan 0x472188 +0x68 ?
    fh.write("\n\n######## vtable +0x68 targets ########\n")
    def rd32(a): return mem.getInt(flat.toAddr(a)) & 0xFFFFFFFF
    def fname(a):
        f = fm.getFunctionAt(flat.toAddr(a)) or fm.getFunctionContaining(flat.toAddr(a))
        return f.getName() if f else "-"
    for base, lbl in ((0x472188, "usbscan"), (0x4721f0, "USBPRINT"), (0x472260, "variant")):
        t = rd32(base + 0x68)
        fh.write("  %s 0x%08x +0x68 -> %08x %s\n" % (lbl, base, t, fname(t)))
        # decompile that target
        fn = fm.getFunctionAt(flat.toAddr(t)) or fm.getFunctionContaining(flat.toAddr(t))
        if fn:
            r = dec.decompileFunction(fn, 200, mon)
            fh.write(clean(r.getDecompiledFunction().getC() if r and r.decompileCompleted() else "//fail\n"))

    fh.close(); print("CMR_DONE wrote", OUT); proj.close()


main()
