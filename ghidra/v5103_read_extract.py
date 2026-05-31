#!/usr/bin/env python3
"""Lane A read-path follow-up — recover the READ (cmd, arg) from v5103.

The reset path is group-7 SEND. The COUNTER READ is the get-command path: the
Service Tool reads EEPROM/counter values to display them (the "Read" / EEPROM
info dialogs). We want the literal (cmd, arg) for a counter/EEPROM read so the
native tool can issue ONE live read over the maintenance lane.

Strategy: the IOCTL primitive FUN_004302c0(this, cmd, arg, mode, ...) uses
mode!=0 → 0x22003c RECV. We find functions that reference the RECV path and the
EEPROM/counter read strings, and decompile the dispatchers that pass the literal
(cmd, arg) for a read. Cross-anchor on the read-related strings.

Reuses the open/import scaffold; env identical to v5103_absorber_extract.py.
"""
import os

import pyghidra

pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "v5103fu")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
EXE = os.environ.get("CMR_EXE", "")
OUT = os.environ.get("CMR_OUT", ".ghidra-work/out/v5103/read.txt")

# Read-path string anchors (EEPROM/counter read vocabulary).
NEEDLES = [
    "EEPROM", "eeprom", "Read", "read", "Counter", "counter",
    "get_command", "readcmd", "EEPROM Information", "EEPROM Dump",
    "absorber", "Ink", "Waste", "0x22003c",
]


def run(flat):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    prog = flat.getCurrentProgram()
    fm = prog.getFunctionManager()
    refmgr = prog.getReferenceManager()
    mon = ConsoleTaskMonitor()
    dec = DecompInterface()
    dec.openProgram(prog)
    minA = prog.getMinAddress()
    print("CMR funcs:", fm.getFunctionCount())

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as fh:
        fh.write("CMR read-path extract — ServiceTool_v5103\n\n")

        fh.write("===== READ-PATH STRING ANCHORS =====\n")
        for nd in NEEDLES:
            res = flat.findBytes(minA, nd, 30)
            addrs = list(res) if res else []
            fh.write("  %-22r -> %d  %s\n"
                     % (nd, len(addrs), ", ".join(a.toString() for a in addrs[:6])))
        fh.write("\n")

        # The IOCTL primitive FUN_004302c0 — find its callers (the dispatchers
        # that pass the literal cmd/arg). It's a virtual method so direct callers
        # may be 0; also scan for the RECV mode usage.
        prim = flat.toAddr("004302c0")
        fh.write("===== FUN_004302c0 (IOCTL primitive) callers =====\n")
        callers = {}
        for r in refmgr.getReferencesTo(prim):
            fn = fm.getFunctionContaining(r.getFromAddress())
            if fn is not None:
                callers[fn.getEntryPoint().toString()] = fn
        fh.write("  direct callers: %d\n\n" % len(callers))

        # Decompile the get/read dispatchers near the group-7 set handler. The
        # set handler is FUN_0040b6c0; the read counterpart is typically adjacent
        # (same dialog class). Decompile a window of the 0x40xxxx app range
        # functions that reference EEPROM/read strings.
        targets = dict(callers)
        for nd in ("get_command", "readcmd", "EEPROM Information", "EEPROM Dump"):
            res = flat.findBytes(minA, nd, 10)
            for sa in (list(res) if res else []):
                for r in refmgr.getReferencesTo(sa):
                    fn = fm.getFunctionContaining(r.getFromAddress())
                    if fn is not None:
                        targets[fn.getEntryPoint().toString()] = fn

        fh.write("===== candidate read dispatchers (decompiled) =====\n\n")
        for ea, fn in list(targets.items())[:12]:
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
