#!/usr/bin/env python3
import os
# Standalone PyGhidra runner (Ghidra 12). Reuses the saved analyzed project.
# Stripped binary: identifier strings ("PrinterCanonSTD::clearCounters",
# "service.sendcmd") are NOT auto-defined as string data, so we BYTE-SEARCH the
# raw memory for each exact string, then resolve the referencing function via
# (a) direct references to the string address, or (b) the pointer-to-string
# (LE 32-bit address) loaded in code. Decompile each unique function.
#
# Run: GHIDRA_INSTALL_DIR=<ghidra> uv run --no-project --with pyghidra python \
#        decomp_standalone.py <out.c> <exact_string_csv>
import sys
import jpype
import pyghidra

pyghidra.start()
from pyghidra import open_program  # noqa: E402

OUT = sys.argv[1]
NEEDLES = [s for s in sys.argv[2].split(",") if s]
PROJ = os.environ["CMR_PROJ"]
PROJ_NAME = os.environ.get("CMR_PROJ_NAME", "program")
# Open the EXISTING analyzed program by name (do NOT pass a binary path — that
# re-imports a fresh, UN-analyzed copy => 0 functions). CMR_PROG_NAME is the
# program name inside the project (e.g. 'printerpotty.exe').
PROG_NAME = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
print("CMR_START needles=%r" % NEEDLES)

JByte = jpype.JArray(jpype.JByte)


def jbytes(bs):
    return JByte([((b + 128) % 256) - 128 for b in bs])


with open_program(None, project_location=PROJ, project_name=PROJ_NAME,
                  program_name=PROG_NAME, analyze=False) as flat:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    prog = flat.getCurrentProgram()
    print("CMR funcs in opened program:", prog.getFunctionManager().getFunctionCount())
    mem = prog.getMemory()
    refmgr = prog.getReferenceManager()
    fm = prog.getFunctionManager()
    mon = ConsoleTaskMonitor()
    minA = prog.getMinAddress()

    def all_occurrences(pattern):
        # FlatProgramAPI.findBytes(Address, String regex, int matchLimit) -> Address[]
        res = flat.findBytes(minA, pattern, 500)
        return list(res) if res is not None else []

    # 1) string VAs of interest
    va_needle = {}   # int VA -> needle
    for needle in NEEDLES:
        sas = all_occurrences(needle)
        print("CMR needle %-34r -> %d occurrences" % (needle, len(sas)))
        for sa in sas:
            va_needle[sa.getOffset()] = needle

    # 1b) import-symbol anchoring (DeviceIoControl, CreateFileW, ...): Ghidra wires
    #     references to import thunks, so xrefs -> the I/O-primitive functions.
    targets = {}   # entry str -> Function
    hits = []      # (needle, how, fn name, entry)
    st = prog.getSymbolTable()
    for needle in NEEDLES:
        seeds = [s.getAddress() for s in st.getSymbols(needle)]
        nfound = 0
        seen = set()
        queue = list(seeds)
        for seed in queue:
            for r in refmgr.getReferencesTo(seed):
                fa = r.getFromAddress()
                fn = fm.getFunctionContaining(fa)
                if fn is not None:
                    targets[fn.getEntryPoint().toString()] = fn
                    hits.append((needle, "import", fn.getName(), fn.getEntryPoint().toString()))
                    nfound += 1
                elif fa.toString() not in seen:        # thunk / IAT slot -> hop again
                    seen.add(fa.toString())
                    for r2 in refmgr.getReferencesTo(fa):
                        fn2 = fm.getFunctionContaining(r2.getFromAddress())
                        if fn2 is not None:
                            targets[fn2.getEntryPoint().toString()] = fn2
                            hits.append((needle, "import2", fn2.getName(), fn2.getEntryPoint().toString()))
                            nfound += 1
        print("CMR import-symbol %r -> %d caller funcs" % (needle, nfound))

    # 2) direct references first (cheap)
    for va, needle in va_needle.items():
        addr = flat.toAddr(va)
        for r in refmgr.getReferencesTo(addr):
            fn = fm.getFunctionContaining(r.getFromAddress())
            if fn is not None:
                targets[fn.getEntryPoint().toString()] = fn
                hits.append((needle, "ref", fn.getName(), fn.getEntryPoint().toString()))

    # 3) reliable pass: any instruction whose operand scalar/address == a string VA
    if len(targets) < len(va_needle):
        it = prog.getListing().getInstructions(True)
        while it.hasNext():
            ins = it.next()
            matched_needle = None
            for opi in range(ins.getNumOperands()):
                sc = ins.getScalar(opi)
                if sc is not None and (sc.getUnsignedValue() & 0xFFFFFFFF) in va_needle:
                    matched_needle = va_needle[sc.getUnsignedValue() & 0xFFFFFFFF]
                    break
                for o in ins.getOpObjects(opi):
                    try:
                        ov = o.getOffset()
                    except Exception:
                        continue
                    if ov in va_needle:
                        matched_needle = va_needle[ov]
                        break
                if matched_needle:
                    break
            if matched_needle:
                fn = fm.getFunctionContaining(ins.getAddress())
                if fn is not None:
                    targets[fn.getEntryPoint().toString()] = fn
                    hits.append((matched_needle, "insn", fn.getName(), fn.getEntryPoint().toString()))

    print("CMR matched %d functions from %d hits" % (len(targets), len(hits)))
    dec = DecompInterface()
    dec.openProgram(prog)
    with open(OUT, "w") as fh:
        fh.write("# byte-anchored decompile; needles=%r\n# needle -> (how) function:\n" % NEEDLES)
        for nd, how, nm, ea in hits:
            fh.write("#  %-34s %-4s %s @ %s\n" % (nd, how, nm, ea))
        fh.write("\n")
        for ea, fn in targets.items():
            fh.write("// ===== %s @ %s =====\n" % (fn.getName(), ea))
            res = dec.decompileFunction(fn, 120, mon)
            if res is not None and res.decompileCompleted():
                fh.write(res.getDecompiledFunction().getC())
            else:
                fh.write("// (decompile failed/timeout)\n")
            fh.write("\n\n")
print("CMR_DONE wrote to %s" % OUT)
