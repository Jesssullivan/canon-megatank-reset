#!/usr/bin/env python3
"""Lane A read-body RE — resolve the transport object + the counter-read request.

The dispatcher FUN_0040ac60 gets its transport object from FUN_0040f4f0() and
calls vtable slots (0x20/0x24/0x28/0x40/0x44/0x48/0x4c/0x5c). The SET path uses
0x48 (send payload). A READ should use a RECV slot. To find the read request:

  1. Decompile FUN_0040f4f0 — what object/global does it return? (find the vtable)
  2. From that object's vtable, dump the slot function pointers and decompile the
     RECV-side method(s) (the ones that call FUN_004302c0 with mode!=0 → 0x22003c).
  3. Decompile the EEPROM/counter READ dialog handlers (functions referencing the
     EEPROM/Counter strings at the addresses found by the read extractor:
     0046f141.. for "EEPROM", 0048017c for "Counter", 0047110f for "Read").

Output lets us see whether a read is (cmd=0x86 + a request body selecting the
counter) and what that body is. Reuses the scaffold; env identical.
"""
import os

import pyghidra

pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "v5103rd2")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
EXE = os.environ.get("CMR_EXE", "")
OUT = os.environ.get("CMR_OUT", ".ghidra-work/out/v5103/readbody.txt")

# Functions to decompile directly (by address, same binary).
FUNCS = [
    "0040f4f0",  # transport getter (returns lParam object)
    "0040f1e0",  # helper near it
    "0040f1f0",
    "004302c0",  # IOCTL primitive (mode!=0 = RECV 0x22003c)
]

# String addresses from the read extractor — decompile their referencing funcs.
READ_STRING_VAS = ["0046f141", "0048017c", "0047110f", "0047f9c0", "0047203c"]


def run(flat):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    prog = flat.getCurrentProgram()
    fm = prog.getFunctionManager()
    refmgr = prog.getReferenceManager()
    mon = ConsoleTaskMonitor()
    dec = DecompInterface()
    dec.openProgram(prog)
    print("CMR funcs:", fm.getFunctionCount())

    targets: dict[str, object] = {}

    # direct address targets
    for fa in FUNCS:
        a = flat.toAddr(fa)
        fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        if fn is not None:
            targets[fn.getEntryPoint().toString()] = fn

    # functions referencing the read strings
    for va in READ_STRING_VAS:
        a = flat.toAddr(va)
        for r in refmgr.getReferencesTo(a):
            fn = fm.getFunctionContaining(r.getFromAddress())
            if fn is not None:
                targets[fn.getEntryPoint().toString()] = fn

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as fh:
        fh.write("CMR read-body extract — transport getter + read dialogs\n")
        fh.write("targets: %d\n\n" % len(targets))
        for ea, fn in targets.items():
            fh.write("// ===== %s @ %s =====\n" % (fn.getName(), ea))
            r = dec.decompileFunction(fn, 150, mon)
            fh.write(r.getDecompiledFunction().getC()
                     if r and r.decompileCompleted() else "// (decompile failed)\n")
            fh.write("\n\n")
    print("CMR_DONE wrote", OUT)


def already_imported():
    return os.path.isdir(os.path.join(PROJ, PROJ_NAME + ".rep"))


if already_imported():
    print("CMR opening existing project program by name")
    with open_program(None, project_location=PROJ, project_name=PROJ_NAME,
                      program_name=PROG_NAME, analyze=False) as flat:
        run(flat)
else:
    print("CMR importing + analyzing", EXE)
    with open_program(EXE, project_location=PROJ, project_name=PROJ_NAME,
                      analyze=True) as flat:
        run(flat)
