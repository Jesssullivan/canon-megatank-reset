# -*- coding: utf-8 -*-
# canon-tool R3 TIN-1697 — find where 32-bit constants are loaded (e.g. vtable
# bases installed by constructors) + decompile an explicit list of functions.
#
# postScript args: <out.c> <search_hex_csv> <decomp_hex_csv>
#   search_hex_csv : comma list of 32-bit values to byte-search for (LE), e.g. 0x47219c,0x472274
#   decomp_hex_csv : comma list of function addrs to decompile, e.g. 0x433d40,0x433d70

import codecs
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
OUT = args[0]
SEARCH = [s for s in args[1].split(",") if s] if len(args) > 1 and args[1] != "-" else []
DECOMP = [s for s in args[2].split(",") if s] if len(args) > 2 and args[2] != "-" else []

prog = currentProgram
fm = prog.getFunctionManager()
monitor = ConsoleTaskMonitor()
di = DecompInterface()
di.openProgram(prog)

lines = []
def w(s=u""):
    if not isinstance(s, unicode):
        s = unicode(str(s), "utf-8", "replace")
    lines.append(s)

def le_pattern(val):
    b = [val & 0xff, (val >> 8) & 0xff, (val >> 16) & 0xff, (val >> 24) & 0xff]
    return "".join("\\x%02x" % x for x in b)

decomp_targets = set()

# (1) constant byte-search → who loads these vtable bases
for hx in SEARCH:
    val = long(hx, 16)
    w(u"## byte-search for %s (LE %s)" % (hx, le_pattern(val)))
    a = prog.getMinAddress()
    pat = le_pattern(val)
    found_any = False
    while True:
        try:
            found = findBytes(a, pat)
        except Exception:
            found = None
        if found is None:
            break
        cont = fm.getFunctionContaining(found)
        cont_s = cont.getName() if cont is not None else "-"
        w(u"- hit at %s  in=%s" % (found, cont_s))
        if cont is not None:
            decomp_targets.add(cont.getEntryPoint())
        found_any = True
        a = found.add(1)
    if not found_any:
        w(u"  (no hits)")
    w()

# (2) explicit decomp list
for hx in DECOMP:
    f = fm.getFunctionContaining(toAddr(long(hx, 16)))
    if f is not None:
        decomp_targets.add(f.getEntryPoint())

w(u"## decompiled functions (%d)" % len(decomp_targets))
w()
for ep in sorted(decomp_targets, key=lambda x: x.getOffset()):
    func = fm.getFunctionAt(ep)
    code = u""
    try:
        res = di.decompileFunction(func, 90, monitor)
        if res is not None and res.decompileCompleted():
            code = res.getDecompiledFunction().getC()
    except Exception as e:
        code = u"// decompile failed: %s" % e
    w(u"// ===== %s @ %s =====" % (func.getName(), ep))
    w(unicode(code))
    w()

f = codecs.open(OUT, "w", "utf-8")
f.write(u"\n".join(lines))
f.write(u"\n")
f.close()
println("CANON_FIND search=%d decomp=%d" % (len(SEARCH), len(decomp_targets)))
