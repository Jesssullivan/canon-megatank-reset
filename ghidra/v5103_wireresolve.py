#!/usr/bin/env python3
r"""Resolve the USBPRINT transport's real lower writer + the on-wire frame.

Opens the TRACKED 12.0.2 project DB READ-ONLY (no re-import, no save), exactly
as the prior RE: GhidraProject.openProject(loc,name,False) +
openProgram("/","ServiceTool_v5103.exe",True). Dumps:
  * the four transport vtables out to +0x80 (so +0x60/+0x64/+0x68 show)
  * every .rdata/.data vtable whose +0x00 == FUN_00433eb0 (concrete transport)
  * brute IOCTL scan: which funcs reference 0x16000c/0x220038/0x22003c, and
    which vtable slots point at them (-> the real inner IO object)
  * full decompiles of the transport/inner/dispatcher/frame-builder funcs
  * at-rest bytes + writers of DAT_004921f8/9 and DAT_00494ca0
"""
import os

import pyghidra

pyghidra.start()

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
OUT = os.environ["CMR_OUT"]

VTABLES = {
    0x472188: "usbscan transport (normal)",
    0x4721f0: "USBPRINT transport (service)",
    0x472260: "usbscan variant",
    0x472468: "abstract base",
    0x472154: "EncCommService / manager (PTR_FUN_00472154)",
}

FUNCS = [
    0x4306E0, 0x430720, 0x4304B0,          # USBPRINT transport methods +0x10/+0x14/+0x18
    0x4301B0, 0x4302C0, 0x4301A0,          # usbscan transport methods
    0x433EB0,                              # shared overlapped opener (+0x00)
    0x40AC60, 0x40FA60,                    # dispatcher + frame builder
    0x42CA40, 0x42C950, 0x42CA00, 0x42CEC0, 0x42BC80,  # EncComm slot methods
    0x42FC80, 0x4308E0, 0x430880, 0x4308A0,            # transport picker + accessors
    0x4330D0, 0x4335B0, 0x432BC0, 0x432930,            # USBPRINT discovery/construction
    0x430900, 0x42FC00, 0x42FCE0,                       # manager ctors
]


def open_ro():
    from ghidra.base.project import GhidraProject
    proj = GhidraProject.openProject(PROJ, PROJ_NAME, False)
    prog = proj.openProgram("/", PROG_NAME, True)
    return proj, prog


def run(prog):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.scalar import Scalar
    from ghidra.util.task import ConsoleTaskMonitor

    flat = FlatProgramAPI(prog)
    fm = prog.getFunctionManager()
    mem = prog.getMemory()
    mon = ConsoleTaskMonitor()
    dec = DecompInterface()
    dec.openProgram(prog)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fh = open(OUT, "w")

    def addr(v):
        return flat.toAddr(v)

    def rd32(a):
        return mem.getInt(addr(a)) & 0xFFFFFFFF

    def rdbytes(a, n):
        b = bytearray(n)
        mem.getBytes(addr(a), b)
        return bytes(b)

    def fname(a):
        f = fm.getFunctionAt(addr(a)) or fm.getFunctionContaining(addr(a))
        return f.getName() if f else "-"

    def decomp(fn):
        r = dec.decompileFunction(fn, 240, mon)
        return (r.getDecompiledFunction().getC()
                if r and r.decompileCompleted() else "// (decompile failed)\n")

    # ---- vtable dumps to +0x80 ----
    fh.write("######## VTABLE DUMPS (to +0x80) ########\n")
    for base, label in VTABLES.items():
        fh.write("\n===== %s @ %08x =====\n" % (label, base))
        for off in range(0, 0x84, 4):
            try:
                tgt = rd32(base + off)
                fh.write("  +0x%02x  %08x  %s\n" % (off, tgt, fname(tgt)))
            except Exception as e:  # noqa: BLE001
                fh.write("  +0x%02x  <err %s>\n" % (off, e))

    # ---- vtables whose +0x00 == shared opener ----
    fh.write("\n\n######## vtables w/ +0x00 == FUN_00433eb0 ########\n")
    for blk in mem.getBlocks():
        if blk.getName() not in (".rdata", ".data"):
            continue
        a = blk.getStart().getOffset()
        end = blk.getEnd().getOffset()
        while a < end - 4:
            try:
                if rd32(a) == 0x433EB0:
                    fh.write("  candidate @ %08x (%s)\n" % (a, blk.getName()))
                    for off in range(0, 0x70, 4):
                        fh.write("      +0x%02x %08x %s\n" % (off, rd32(a + off), fname(rd32(a + off))))
            except Exception:  # noqa: BLE001
                pass
            a += 4

    # ---- brute IOCTL scan ----
    fh.write("\n\n######## IOCTL constant scan ########\n")
    listing = prog.getListing()
    targets = {0x16000C: [], 0x220038: [], 0x22003C: []}
    for ins in listing.getInstructions(True):
        for i in range(ins.getNumOperands()):
            for obj in ins.getOpObjects(i):
                if isinstance(obj, Scalar):
                    v = obj.getUnsignedValue()
                    if v in targets:
                        f = fm.getFunctionContaining(ins.getAddress())
                        ent = f.getEntryPoint().getOffset() if f else ins.getAddress().getOffset()
                        if ent not in targets[v]:
                            targets[v].append(ent)
    ioctl_funcs = set()
    for v, lst in targets.items():
        fh.write("  IOCTL 0x%06x in: %s\n" %
                 (v, ", ".join("%s@%08x" % (fname(e), e) for e in lst) or "(none)"))
        ioctl_funcs.update(lst)
    fh.write("\n  vtables w/ +0x10/14/18/1c -> an IOCTL func:\n")
    for blk in mem.getBlocks():
        if blk.getName() not in (".rdata", ".data"):
            continue
        a = blk.getStart().getOffset()
        end = blk.getEnd().getOffset()
        while a < end - 4:
            try:
                for off in (0x10, 0x14, 0x18, 0x1c):
                    if rd32(a + off) in ioctl_funcs:
                        fh.write("    vtable @ %08x +0x%02x -> %08x %s\n"
                                 % (a, off, rd32(a + off), fname(rd32(a + off))))
                        for o2 in range(0, 0x20, 4):
                            fh.write("        +0x%02x %08x %s\n" % (o2, rd32(a + o2), fname(rd32(a + o2))))
                        break
            except Exception:  # noqa: BLE001
                pass
            a += 4

    # ---- decompiles ----
    fh.write("\n\n######## DECOMP ########\n")
    for fa in FUNCS:
        fn = fm.getFunctionAt(addr(fa)) or fm.getFunctionContaining(addr(fa))
        if fn is None:
            fh.write("\n// no function at %08x\n" % fa)
            continue
        fh.write("\n// ===================== %s @ %s =====================\n"
                 % (fn.getName(), fn.getEntryPoint()))
        callers = sorted({c.getEntryPoint().toString() + " " + c.getName()
                          for c in fn.getCallingFunctions(mon)})
        fh.write("// callers: %s\n" % (", ".join(callers) or "(none/indirect)"))
        fh.write(decomp(fn))

    # ---- at-rest data + writers ----
    fh.write("\n\n######## AT-REST DATA ########\n")
    for nm, a, n in (("DAT_004921f8", 0x4921F8, 8),
                     ("DAT_00494ca0", 0x494CA0, 8),
                     ("DAT_00494d54", 0x494D54, 8),
                     ("GUID 0x4723e0", 0x4723E0, 16)):
        try:
            fh.write("  %-20s = %s\n" % (nm, rdbytes(a, n).hex(" ")))
        except Exception as e:  # noqa: BLE001
            fh.write("  %-20s <err %s>\n" % (nm, e))
    fh.write("\n  refs (R/W) to globals:\n")
    for nm, a in (("DAT_004921f8", 0x4921F8), ("DAT_004921f9", 0x4921F9),
                  ("DAT_00494ca0", 0x494CA0)):
        for r in flat.getReferencesTo(addr(a)):
            fh.write("    %s <- %s %s (%s)\n"
                     % (nm, r.getFromAddress(), fname(r.getFromAddress().getOffset()),
                        r.getReferenceType()))
    fh.close()
    print("CMR_DONE wrote", OUT)


_proj, _prog = open_ro()
try:
    run(_prog)
finally:
    _proj.close()
