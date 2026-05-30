# PyGhidra (Python 3) — Ghidra 12. String-anchored decompile.
#
# printerpotty.exe (and the Canon Service Tool) are stripped release binaries:
# the readable identifiers ("PrinterCanonSTD::clearCounters", "service.sendcmd")
# are STRING LITERALS (log/assert/RTTI tags), not function symbols. So we locate
# the implementation by: string -> references-to -> the referencing function ->
# decompile it.
#
# postScript args: <out.c> <comma-separated string substrings (lowercased match)>
# e.g.  ... pyghidra_decompile_xrefs.py out.c "clearcounters,execute_set_command,action_is_permitted"

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

print("CMR_START decompile_xrefs")
args = getScriptArgs()  # noqa: F821 (injected)
out_path = args[0]
needles = [s.strip().lower() for s in args[1].split(",") if s.strip()]
print("CMR needles=%r out=%s" % (needles, out_path))

prog = currentProgram          # noqa: F821 (injected)
listing = prog.getListing()
refmgr = prog.getReferenceManager()
fm = prog.getFunctionManager()

target_funcs = {}   # entry addr str -> Function
hits = []           # (string, fn name, entry)

di = listing.getDefinedData(True)
while di.hasNext():
    d = di.next()
    try:
        dt = d.getDataType().getName().lower()
    except Exception:
        dt = ""
    if not ("unicode" in dt or "string" in dt or "char" in dt):
        continue
    val = d.getValue()
    if val is None:
        continue
    s = str(val)
    sl = s.lower()
    if not any(n in sl for n in needles):
        continue
    addr = d.getAddress()
    refs = refmgr.getReferencesTo(addr)
    for r in refs:
        fn = fm.getFunctionContaining(r.getFromAddress())
        if fn is not None:
            target_funcs[fn.getEntryPoint().toString()] = fn
            hits.append((s[:70], fn.getName(), fn.getEntryPoint().toString()))

print("CMR matched %d distinct functions from %d string hits" % (len(target_funcs), len(hits)))

dec = DecompInterface()
dec.openProgram(prog)
mon = ConsoleTaskMonitor()

with open(out_path, "w") as fh:
    fh.write("# string-anchored decompile; needles=%r\n" % needles)
    fh.write("# ---- string -> referencing function ----\n")
    for s, nm, ea in hits:
        fh.write("#  %-72s %s @ %s\n" % (repr(s), nm, ea))
    fh.write("\n")
    for ea, fn in target_funcs.items():
        fh.write("// ===== %s @ %s =====\n" % (fn.getName(), ea))
        res = dec.decompileFunction(fn, 90, mon)
        if res is not None and res.decompileCompleted():
            fh.write(res.getDecompiledFunction().getC())
        else:
            fh.write("// (decompile failed/timeout)\n")
        fh.write("\n\n")

print("CMR_DONE wrote %d functions to %s" % (len(target_funcs), out_path))
