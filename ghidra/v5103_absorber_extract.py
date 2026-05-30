#!/usr/bin/env python3
"""Lane A static RE — recover the G-series absorber-reset (5B00) literals from the
Canon Service Tool v5103 binary.

Self-contained: if the named project does not yet hold the program, it imports
the staged binary and runs full auto-analysis; otherwise it opens the existing
analyzed program by name. Then it:

  1. Dumps DAT_0048295c (absorber idx table) raw bytes — stride-8 interpretation.
  2. Decompiles the Set handlers + group dispatcher + comparison op
     (FUN_0040b6c0 / FUN_0040d140 / FUN_0040ac60 / FUN_0040c220 / FUN_0040a8a0)
     and the preamble globals DAT_004921f8/9.
  3. Decompiles the EncCommService send path (FUN_0040fb40), the object getter
     (FUN_0040f4f0), the ctor (FUN_0042aa20), and the transport helpers
     (FUN_0042b030 / FUN_0042cec0 / FUN_004302c0 / FUN_0042ae40).

Cross-anchors by string + dumps the EncCommService vtable + singleton so the
slot 0x44 / 0x48 method pointers and preamble bytes can be read directly.

Env:
  GHIDRA_INSTALL_DIR   <ghidra>/lib/ghidra
  CMR_PROJ             project dir   (e.g. .ghidra-work/project.canon)
  CMR_PROJ_NAME        project name  (e.g. canon-servicetool-v5103)
  CMR_PROG_NAME        program name in project (ServiceTool_v5103.exe)
  CMR_EXE              path to staged binary (for first-time import)
  CMR_OUT              output text file
"""
import os

import jpype
import pyghidra

pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
EXE = os.environ.get("CMR_EXE", "")
OUT = os.environ.get("CMR_OUT", ".ghidra-work/out/v5103/absorber.txt")

FUNCS = [
    "0040b6c0", "0040d140", "0040ac60", "0040c220", "0040a8a0",
    "0040f4f0", "0040fb40", "0042aa20", "0042b030", "0042cec0",
    "004302c0", "0042ae40",
]

DATA = [
    ("0048295c", 128),
    ("004921f8", 16),
    ("00494ca0", 16),
    ("00494ee0", 16),
    ("00471dec", 64),
    ("00494fd0", 8),
]

NEEDLES = [
    "absorber", "Absorber", "Ink Absorber Counter",
    "EncComm", "TOOL_0006", "TOOL0006",
    "G3010 series", "G4010 series", "G6000", "G6020",
    "A function was finished", "An undefined command",
]


def hexrow(bs):
    return " ".join("%02x" % (b & 0xff) for b in bs)


def already_imported():
    # crude check: a .rep dir for the project exists
    rep = os.path.join(PROJ, PROJ_NAME + ".rep")
    return os.path.isdir(rep)


def run(flat):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.program.model.address import AddressSet

    prog = flat.getCurrentProgram()
    mem = prog.getMemory()
    fm = prog.getFunctionManager()
    mon = ConsoleTaskMonitor()
    minA = prog.getMinAddress()

    nfuncs = fm.getFunctionCount()
    print("CMR funcs in opened program:", nfuncs)

    if nfuncs < 1000:
        for blk in mem.getBlocks():
            if blk.isExecute() and blk.isInitialized():
                print("CMR disasm block %s [%s-%s]"
                      % (blk.getName(), blk.getStart(), blk.getEnd()))
                try:
                    DisassembleCommand(
                        blk.getStart(),
                        AddressSet(blk.getStart(), blk.getEnd()), True
                    ).applyTo(prog, mon)
                except Exception as e:
                    print("CMR disasm err:", str(e))
        flat.analyzeAll(prog)
        print("CMR funcs after force-disasm:", fm.getFunctionCount())

    dec = DecompInterface()
    dec.openProgram(prog)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as fh:
        fh.write("CMR Lane A — ServiceTool_v5103 absorber extract\n")
        fh.write("function count: %d\n\n" % fm.getFunctionCount())

        fh.write("===== STRING ANCHORS =====\n")
        for nd in NEEDLES:
            res = flat.findBytes(minA, nd, 50)
            addrs = list(res) if res else []
            fh.write("  %-28r -> %d  %s\n"
                     % (nd, len(addrs), ", ".join(a.toString() for a in addrs[:8])))
        fh.write("\n")

        fh.write("===== DATA GLOBALS (raw bytes) =====\n")
        for addr_s, n in DATA:
            a = flat.toAddr(addr_s)
            try:
                bs = flat.getBytes(a, n)
            except Exception as e:
                fh.write("  %s [%d]: <getBytes failed: %s>\n" % (addr_s, n, e))
                continue
            fh.write("  %s [%d bytes]:\n" % (addr_s, n))
            for off in range(0, len(bs), 16):
                chunk = bs[off:off + 16]
                fh.write("    +%03x  %s\n" % (off, hexrow(chunk)))
            fh.write("\n")

        fh.write("===== DAT_0048295c stride-8 interpretation =====\n")
        a = flat.toAddr("0048295c")
        try:
            bs = flat.getBytes(a, 128)
            for sel in range(16):
                base = sel * 8
                row = bs[base:base + 8]
                if len(row) < 8:
                    break
                fh.write("  sel=%2d  DAT[sel*8]=0x%02x   row: %s\n"
                         % (sel, row[0] & 0xff, hexrow(row)))
        except Exception as e:
            fh.write("  <failed: %s>\n" % e)
        fh.write("\n")

        fh.write("===== DECOMPILED FUNCTIONS =====\n\n")
        for fa in FUNCS:
            a = flat.toAddr(fa)
            fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            fh.write("// ===== %s @ 0x%s =====\n"
                     % (fn.getName() if fn else "<none>", fa))
            if fn is None:
                fh.write("// (no function at this address)\n\n")
                continue
            r = dec.decompileFunction(fn, 180, mon)
            if r is not None and r.decompileCompleted():
                fh.write(r.getDecompiledFunction().getC())
            else:
                fh.write("// (decompile failed/timeout)\n")
            fh.write("\n\n")

    print("CMR_DONE wrote", OUT)


def save_prog(flat):
    # Persist the analyzed program so reruns skip the expensive disasm/analyze.
    try:
        from ghidra.util.task import ConsoleTaskMonitor
        prog = flat.getCurrentProgram()
        prog.save("CMR Lane A analysis", ConsoleTaskMonitor())
        print("CMR saved program")
    except Exception as e:
        print("CMR save failed:", str(e))


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
        save_prog(flat)
