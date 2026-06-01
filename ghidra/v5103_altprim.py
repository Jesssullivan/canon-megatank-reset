#!/usr/bin/env python3
r"""Disassemble + decompile the 0x16000c ALT primitive (FUN_004301b0 region) and
its USBPRINT twin FUN_004306e0, to settle whether 0x16000c is an in-place
same-buffer-in/out DeviceIoControl (control/exchange) or a framed directional op.
Read-only 12.0.2 DB, same open pattern as v5103_wireresolve.py."""
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
    flat = FlatProgramAPI(prog)
    fm = prog.getFunctionManager()
    listing = prog.getListing()
    mon = ConsoleTaskMonitor()
    dec = DecompInterface()
    dec.openProgram(prog)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")

    def disasm_range(start, end, tag):
        fh.write("\n===== disasm %08x..%08x %s =====\n" % (start, end, tag))
        a = flat.toAddr(start)
        enda = flat.toAddr(end)
        ins = listing.getInstructionAt(a)
        if ins is None:
            # try to disassemble on the fly
            from ghidra.app.cmd.disassemble import DisassembleCommand
            from ghidra.program.model.address import AddressSet
            cmd = DisassembleCommand(AddressSet(a, enda), None, True)
            cmd.applyTo(prog, mon)
            ins = listing.getInstructionAt(a)
        while ins is not None and ins.getAddress().getOffset() <= end:
            fh.write("  %08x  %s\n" % (ins.getAddress().getOffset(), ins.toString()))
            ins = ins.getNext()

    def decomp(fa, tag):
        fn = fm.getFunctionAt(flat.toAddr(fa)) or fm.getFunctionContaining(flat.toAddr(fa))
        fh.write("\n===== decomp %08x %s =====\n" % (fa, tag))
        if fn is None:
            fh.write("// no defined function at %08x\n" % fa)
            return
        r = dec.decompileFunction(fn, 200, mon)
        fh.write(r.getDecompiledFunction().getC() if r and r.decompileCompleted() else "//fail\n")

    # The 0x16000c alt op: scan said constant at 004301fa, vtable slot points 004301b0.
    disasm_range(0x4301b0, 0x4302b0, "FUN_004301b0 (usbscan +0x10, 0x16000c alt op)")
    decomp(0x4301b0, "FUN_004301b0")
    # USBPRINT twin +0x10
    disasm_range(0x4306e0, 0x430720, "FUN_004306e0 (USBPRINT +0x10 alt op)")
    decomp(0x4306e0, "FUN_004306e0")
    # the +0x18 op too (FUN_004301a0 / FUN_004304b0) for completeness
    disasm_range(0x4301a0, 0x4301b0, "FUN_004301a0 (usbscan +0x18)")

    fh.close()
    print("CMR_DONE wrote", OUT)
    proj.close()


main()
