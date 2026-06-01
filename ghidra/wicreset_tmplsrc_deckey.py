#!/usr/bin/env python3
# wicreset_tmplsrc_deckey.py — hunt the APP.BIN decryptor + decide if its key is
# STATIC.  Strategy: from the APP.BIN driver FUN_00530ae0 and its callees, list
# every DATA reference into .rdata/.data that points at a >=16-byte constant blob
# (candidate cipher key / S-box / IV). Also decompile the early driver callees
# (FUN_006d7110, FUN_0064fc00, FUN_00532640's wxFileSystem ctor) to spot a stream
# filter / xor loop. Read-only.
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-deckey-trace.txt")

# functions in/around the APP.BIN load->VFS->parse pipeline to inspect for a
# byte-transform loop and the static key it reads.
PIPE_FUNCS = ["00530ae0", "006d7110", "0064fc00", "00446570", "0051ae10",
              "0051b6a0", "005c7d40"]


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        p = flat.getCurrentProgram()
        af = p.getAddressFactory()
        fm = p.getFunctionManager()
        listing = p.getListing()
        mem = p.getMemory()
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")
            print(s)

        def in_data(addr):
            blk = mem.getBlock(addr)
            return blk is not None and blk.getName() in (".rdata", ".data")

        # For each pipeline func, list data refs to .rdata/.data and dump 32 bytes
        w("===== static-data references from the APP.BIN VFS pipeline funcs =====")
        for h in PIPE_FUNCS:
            a = af.getAddress(h)
            fn = fm.getFunctionAt(a)
            if not fn:
                w("\n## %s : not a function entry" % h)
                continue
            w("\n## %s @ %s" % (fn.getName(), h))
            body = fn.getBody()
            ins = listing.getInstructions(body, True)
            seen = set()
            while ins.hasNext():
                i = ins.next()
                for ref in i.getReferencesFrom():
                    ta = ref.getToAddress()
                    if ta is None or not ta.isMemoryAddress():
                        continue
                    if not in_data(ta):
                        continue
                    key = ta.toString()
                    if key in seen:
                        continue
                    seen.add(key)
                    # dump first bytes to spot a key/S-box
                    try:
                        bs = bytes((mem.getByte(ta.add(k)) & 0xff) for k in range(24))
                        hexs = " ".join("%02x" % x for x in bs)
                    except Exception:
                        hexs = "(unreadable)"
                    w("    %s -> %s  [%s] %s" % (i.getAddress(), ta,
                                                 str(ref.getReferenceType()), hexs))

        # decompile the two early gate funcs that run before the VFS parse
        dec = DecompInterface()
        dec.openProgram(p)
        mon = ConsoleTaskMonitor()
        for h in ["006d7110", "0064fc00"]:
            a = af.getAddress(h)
            fn = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            if not fn:
                continue
            res = dec.decompileFunction(fn, 200, mon)
            w("\n\n// ===== %s @ %s =====" % (fn.getName(), h))
            if res and res.decompileCompleted():
                w(res.getDecompiledFunction().getC())
            else:
                w("// (decompile failed)")

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
