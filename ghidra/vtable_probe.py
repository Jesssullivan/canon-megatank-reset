# -*- coding: utf-8 -*-
# canon-tool R3 TIN-1697 — resolve the vtable holding a target method, dump the
# class's method table + find its constructors/xrefs. Used to get past C++
# virtual-dispatch indirection when getCallingFunctions() returns nothing.
#
# postScript args: <target_hex_addr> <out.txt>

import codecs
from ghidra.program.model.symbol import RefType

args = getScriptArgs()
TARGET = long(args[0], 16)
OUT = args[1]

prog = currentProgram
fm = prog.getFunctionManager()
mem = prog.getMemory()
refmgr = prog.getReferenceManager()

lines = []
def w(s=u""):
    if not isinstance(s, unicode):
        s = unicode(str(s), "utf-8", "replace")
    lines.append(s)

def fname(off):
    try:
        a = toAddr(off)
        f = fm.getFunctionAt(a)
        if f is not None:
            return f.getName()
        sym = getSymbolAt(a)
        return sym.getName() if sym is not None else ""
    except Exception:
        return ""

def rdptr(off):
    try:
        return getInt(toAddr(off)) & 0xffffffff
    except Exception:
        return None

taddr = toAddr(TARGET)
w(u"# vtable probe for %s (%s)" % (fname(TARGET), hex(TARGET)))
w()

# (1) all references TO the target — data refs are vtable slots
w(u"## References to target")
slot_addrs = []
for r in refmgr.getReferencesTo(taddr):
    fa = r.getFromAddress()
    rt = r.getReferenceType()
    cont = fm.getFunctionContaining(fa)
    cont_s = cont.getName() if cont is not None else "-"
    w(u"- from %s  type=%s  in=%s" % (fa, rt, cont_s))
    # data ref (pointer) => vtable slot
    if rt == RefType.DATA or rt.isData():
        slot_addrs.append(fa.getOffset())
w()

# (2) for each vtable slot, dump the surrounding method table
for slot in slot_addrs:
    w(u"## vtable window around slot %s" % hex(slot))
    # walk backward to find table start (consecutive code pointers)
    start = slot
    for i in range(1, 64):
        p = rdptr(slot - i * 4)
        if p is None or fm.getFunctionAt(toAddr(p)) is None:
            start = slot - (i - 1) * 4
            break
    w(u"table start ~ %s" % hex(start))
    w(u"| slot | offset | ptr | function |")
    w(u"|---|---|---|---|")
    idx = 0
    a = start
    while idx < 48:
        p = rdptr(a)
        if p is None:
            break
        fn = fname(p)
        if fm.getFunctionAt(toAddr(p)) is None and fn == "":
            break  # end of table
        mark = "  <== TARGET" if p == TARGET else ""
        w(u"| %d | +0x%x | %s | %s%s |" % (idx, a - start, hex(p), fn, mark))
        idx += 1
        a += 4
    w()
    # (3) refs to the vtable base (constructors install it)
    w(u"### refs to vtable base %s (constructors / installers)" % hex(start))
    for r in refmgr.getReferencesTo(toAddr(start)):
        fa = r.getFromAddress()
        cont = fm.getFunctionContaining(fa)
        w(u"- from %s  in=%s" % (fa, cont.getName() if cont is not None else "-"))
    w()

f = codecs.open(OUT, "w", "utf-8")
f.write(u"\n".join(lines))
f.write(u"\n")
f.close()
println("CANON_VTABLE slots=%d" % len(slot_addrs))
