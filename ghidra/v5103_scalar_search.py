#!/usr/bin/env python3
r"""Find instructions that reference given 32-bit constants (vtable installs),
and dump RTTI class name preceding a vtable (Ghidra puts the type-info ptr at
vtable-4). Read-only. Env CMR_SCALARS=comma hex values."""
import os

import pyghidra

pyghidra.start()

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
OUT = os.environ["CMR_OUT"]
SCALARS = [int(x.strip(), 16) for x in os.environ.get("CMR_SCALARS", "").split(",") if x.strip()]


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
    listing = prog.getListing()
    mem = prog.getMemory()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")

    targets = set(SCALARS)
    # also auto-include the .rdata typeinfo ptr at vtable-4 dereference
    fh.write("scanning instructions for scalar operands: %s\n"
             % ", ".join("%08x" % s for s in SCALARS))

    ins = listing.getInstructions(True)
    count = 0
    for instr in ins:
        n = instr.getNumOperands()
        hit = None
        for i in range(n):
            objs = instr.getOpObjects(i)
            for o in objs:
                try:
                    v = o.getValue() & 0xFFFFFFFF
                except Exception:  # noqa: BLE001
                    continue
                if v in targets:
                    hit = v
        # also check scalar in address refs
        if hit is None:
            for ref in instr.getReferencesFrom():
                try:
                    tv = int(ref.getToAddress().getOffset()) & 0xFFFFFFFF
                except Exception:  # noqa: BLE001
                    continue
                if tv in targets:
                    hit = tv
        if hit is not None:
            fn = fm.getFunctionContaining(instr.getAddress())
            fh.write("  %08x  ref %08x  %-40s in %s\n"
                     % (instr.getAddress().getOffset(), hit, instr.toString(),
                        (fn.getName() + "@" + fn.getEntryPoint().toString()) if fn else "(no func)"))
            count += 1
    fh.write("(%d instruction hits)\n" % count)

    # RTTI name at vtable-4 (Locator/typeinfo)
    for s in SCALARS:
        a = flat.toAddr("%08x" % s)
        try:
            col = mem.getInt(a.subtract(4)) & 0xFFFFFFFF  # complete object locator
            fh.write("\nvtable %08x : col@-4 = %08x\n" % (s, col))
        except Exception as e:  # noqa: BLE001
            fh.write("\nvtable %08x : col read fail %s\n" % (s, e))

    fh.close()
    print("CMR_DONE wrote", OUT)


_proj, _prog = open_ro()
try:
    run(_prog)
finally:
    _proj.close()
