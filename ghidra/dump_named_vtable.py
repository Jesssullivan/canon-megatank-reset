# -*- coding: utf-8 -*-
# canon-tool R3 TIN-1697 — dump a named C++ vftable's slots and decompile the
# method at a chosen offset (e.g. the EncCommService send method at +0x48).
#
# postScript args: <out.c> <name_substr> <mark_off_hex>

import codecs
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
OUT = args[0]
NAME = args[1]
MARK = long(args[2], 16) if len(args) > 2 else 0x48

prog = currentProgram
fm = prog.getFunctionManager()
st = prog.getSymbolTable()
monitor = ConsoleTaskMonitor()

lines = []
def w(s=u""):
    if not isinstance(s, unicode):
        s = unicode(str(s), "utf-8", "replace")
    lines.append(s)

def u32(off):
    try:
        return getInt(toAddr(off)) & 0xffffffff
    except Exception:
        return None

def fname(off):
    try:
        a = toAddr(off)
        f = fm.getFunctionAt(a)
        if f is not None:
            return f.getName()
        s = getSymbolAt(a)
        return s.getName() if s is not None else ""
    except Exception:
        return ""

# find the vftable symbol
vtbls = []
it = st.getAllSymbols(True)
for sym in it:
    nm = sym.getName(True)
    if NAME in nm and ("vftable" in nm.lower() or "vtable" in nm.lower()):
        vtbls.append((nm, sym.getAddress().getOffset()))

decomp_fn = set()
di = DecompInterface()
di.openProgram(prog)

for nm, base in vtbls:
    w(u"## %s @ %s" % (nm, hex(base)))
    w(u"| offset | ptr | function |")
    w(u"|---|---|---|")
    off = 0
    while off <= 0xa0:
        p = u32(base + off)
        if p is None:
            break
        fn = fname(p)
        if fm.getFunctionAt(toAddr(p)) is None and fn == "" and off > 0x10:
            break
        mark = u"  <== +0x%x (target)" % MARK if off == MARK else u""
        w(u"| +0x%x | %s | %s%s |" % (off, hex(p) if p else "0", fn, mark))
        if off == MARK and p:
            f = fm.getFunctionContaining(toAddr(p))
            if f is not None:
                decomp_fn.add(f.getEntryPoint())
        off += 4
    w()

w(u"## decompiled target-slot method(s)")
w()
for ep in decomp_fn:
    func = fm.getFunctionAt(ep)
    code = u""
    try:
        res = di.decompileFunction(func, 120, monitor)
        if res is not None and res.decompileCompleted():
            code = res.getDecompiledFunction().getC()
    except Exception as e:
        code = u"// decompile failed: %s" % e
    w(u"// ===== %s @ %s =====" % (func.getName(), ep))
    w(unicode(code))
    w()

f = codecs.open(OUT, "w", "utf-8")
f.write(u"\n".join(lines)); f.write(u"\n"); f.close()
println("CANON_VFT tables=%d decomp=%d" % (len(vtbls), len(decomp_fn)))
