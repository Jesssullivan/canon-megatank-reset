#!/usr/bin/env python3
"""Lane A follow-up — close the two PENDING items from the v5103 static RE:

  1. EXACT (cmd, arg) for the group-7 transmit. The Set handler calls
     FUN_0040ac60(this, 7, &payload); the transmit is the EncCommService vtable
     slot 0x48 target, which calls FUN_004302c0(this, cmd, arg, ...). We resolve
     the EncCommService::vftable, read slots 0x44 (preamble send) and 0x48
     (payload transmit) function pointers, and decompile those targets to read
     the literal cmd/arg they pass to the IOCTL primitive.

  2. idx LABELS. DAT_0048295c is an array of { u32 idx; char* label }. We follow
     each label pointer and read the string, so sel -> (idx, name) tells us which
     idx is the 5B00 MAIN absorber vs platen/secondary.

Reuses the open/import scaffold from v5103_absorber_extract.py. Env identical.
"""
import os

import pyghidra

pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "canon-servicetool-v5103")
PROG_NAME = os.environ.get("CMR_PROG_NAME", "ServiceTool_v5103.exe")
EXE = os.environ.get("CMR_EXE", "")
OUT = os.environ.get("CMR_OUT", ".ghidra-work/out/v5103/followup.txt")

# EncCommService::vftable symbol (from the prior run, FUN_0042aa20 ctor sets
# *param_1 = EncCommService::vftable). We resolve its address by symbol, then
# read the slot function pointers.
VTABLE_SYMBOL = "EncCommService::vftable"
VTABLE_SLOTS = [0x40, 0x44, 0x48]   # byte offsets seen in FUN_0040ac60

# DAT_0048295c label table: 16 structs of {u32 idx, u32 label_ptr}.
IDX_TABLE = "0048295c"
IDX_ROWS = 16


def hexrow(bs):
    return " ".join("%02x" % (b & 0xFF) for b in bs)


def read_cstr(flat, va, maxlen=64):
    """Read a NUL-terminated ASCII string at virtual address va."""
    if va == 0:
        return ""
    a = flat.toAddr(va)
    out = bytearray()
    for i in range(maxlen):
        try:
            b = flat.getBytes(a.add(i), 1)[0] & 0xFF
        except Exception:  # noqa: BLE001
            break
        if b == 0:
            break
        out.append(b)
    try:
        return out.decode("ascii", "replace")
    except Exception:  # noqa: BLE001
        return repr(bytes(out))


def le32(bs, off):
    return (
        (bs[off] & 0xFF)
        | ((bs[off + 1] & 0xFF) << 8)
        | ((bs[off + 2] & 0xFF) << 16)
        | ((bs[off + 3] & 0xFF) << 24)
    )


def run(flat):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    prog = flat.getCurrentProgram()
    fm = prog.getFunctionManager()
    st = prog.getSymbolTable()
    mon = ConsoleTaskMonitor()
    dec = DecompInterface()
    dec.openProgram(prog)

    print("CMR funcs:", fm.getFunctionCount())
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as fh:
        # ── 1. EncCommService vtable slots 0x40/0x44/0x48 ──────────────────
        fh.write("===== EncCommService vtable slots =====\n")
        syms = list(st.getSymbols(VTABLE_SYMBOL))
        vtable_targets = []
        if not syms:
            fh.write("  <vtable symbol %r not found>\n" % VTABLE_SYMBOL)
        else:
            vaddr = syms[0].getAddress()
            fh.write("  %s @ %s\n" % (VTABLE_SYMBOL, vaddr))
            for slot in VTABLE_SLOTS:
                try:
                    bs = flat.getBytes(vaddr.add(slot), 4)
                    fnptr = le32(bs, 0)
                    fh.write("  slot +0x%02x -> 0x%08x\n" % (slot, fnptr))
                    if slot in (0x44, 0x48) and fnptr:
                        vtable_targets.append((slot, "%08x" % fnptr))
                except Exception as e:  # noqa: BLE001
                    fh.write("  slot +0x%02x: <read failed: %s>\n" % (slot, e))
        fh.write("\n")

        # decompile the 0x44 (preamble) and 0x48 (transmit) targets — these set
        # the literal cmd/arg passed to the IOCTL primitive FUN_004302c0.
        fh.write("===== vtable target functions (cmd/arg live here) =====\n\n")
        for slot, fa in vtable_targets:
            a = flat.toAddr(fa)
            fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            fh.write("// ===== slot +0x%02x -> %s @ 0x%s =====\n"
                     % (slot, fn.getName() if fn else "<none>", fa))
            if fn is None:
                fh.write("// (no function)\n\n")
                continue
            r = dec.decompileFunction(fn, 180, mon)
            fh.write(r.getDecompiledFunction().getC()
                     if r and r.decompileCompleted() else "// (decompile failed)\n")
            fh.write("\n\n")

        # ── 2. idx table label resolution ──────────────────────────────────
        fh.write("===== DAT_0048295c sel -> (idx, label) =====\n")
        a = flat.toAddr(IDX_TABLE)
        try:
            bs = flat.getBytes(a, IDX_ROWS * 8)
            for sel in range(IDX_ROWS):
                base = sel * 8
                if base + 8 > len(bs):
                    break
                idx = le32(bs, base)
                label_ptr = le32(bs, base + 4)
                label = read_cstr(flat, label_ptr)
                fh.write("  sel=%2d  idx=0x%02x  label_ptr=0x%08x  label=%r\n"
                         % (sel, idx & 0xFF, label_ptr, label))
        except Exception as e:  # noqa: BLE001
            fh.write("  <failed: %s>\n" % e)
        fh.write("\n")

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
