# -*- coding: utf-8 -*-
# canon-tool R3 TIN-1697 — peek a global C++ object: read its vtable pointer,
# dump the vtable method table (marking a slot of interest), and list refs to
# the object (constructor / users).
#
# postScript args: <out.txt> <obj_addr_hex> [mark_offset_hex]

import codecs

args = getScriptArgs()
OUT = args[0]
OBJ = long(args[1], 16)
MARK = long(args[2], 16) if len(args) > 2 else 0x48

prog = currentProgram
fm = prog.getFunctionManager()
refmgr = prog.getReferenceManager()

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

w(u"# peek object @ %s" % hex(OBJ))
vt = u32(OBJ)
w(u"vtable ptr (static value at obj+0) = %s  %s" % (hex(vt) if vt is not None else "?", fname(vt) if vt else ""))
w()

# if vt looks like a code-pointer table, dump it
if vt and 0x400000 <= vt <= 0x4f0000:
    w(u"## vtable @ %s" % hex(vt))
    w(u"| offset | ptr | function |")
    w(u"|---|---|---|")
    off = 0
    while off <= 0x90:
        p = u32(vt + off)
        if p is None:
            break
        nm = fname(p)
        if fm.getFunctionAt(toAddr(p)) is None and nm == "":
            if off > 0x10:
                break
        mark = "  <== +0x%x" % MARK if off == MARK else ""
        w(u"| +0x%x | %s | %s%s |" % (off, hex(p) if p else "0", nm, mark))
        off += 4
    w()

# refs to the object (constructor installs vtable; users call methods)
w(u"## references to object %s" % hex(OBJ))
for r in refmgr.getReferencesTo(toAddr(OBJ)):
    fa = r.getFromAddress()
    cont = fm.getFunctionContaining(fa)
    w(u"- from %s  type=%s  in=%s" % (fa, r.getReferenceType(), cont.getName() if cont is not None else "-"))

f = codecs.open(OUT, "w", "utf-8")
f.write(u"\n".join(lines)); f.write(u"\n"); f.close()
println("CANON_PEEK obj=%s vt=%s" % (hex(OBJ), hex(vt) if vt else "none"))
