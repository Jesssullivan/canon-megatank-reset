# -*- coding: utf-8 -*-
# canon-tool R3 TIN-1697 — scan for MFC AFX_MSGMAP_ENTRY records → button-click
# handlers, mapping dialog control ID -> handler function. Then decompile the
# handlers for a set of target control IDs (the absorber "Set" buttons).
#
# AFX_MSGMAP_ENTRY (32-bit MFC): 6 x u32 = 24 bytes
#   +0 nMessage   (WM_COMMAND = 0x111)
#   +4 nCode      (BN_CLICKED/command notify = 0)
#   +8 nID
#   +12 nLastID
#   +16 nSig
#   +20 pfn       (handler function pointer)
#
# postScript args: <out.c> <target_ids_csv>   (ids decimal, e.g. 1015,1020,1032,1100)

import codecs
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
OUT = args[0]
TARGET_IDS = set(int(x) for x in args[1].split(",")) if len(args) > 1 and args[1] != "-" else set()

prog = currentProgram
fm = prog.getFunctionManager()
mem = prog.getMemory()
monitor = ConsoleTaskMonitor()

WM_COMMAND = 0x111

def u32(off):
    try:
        return getInt(toAddr(off)) & 0xffffffff
    except Exception:
        return None

def is_code(off):
    a = toAddr(off)
    return fm.getFunctionContaining(a) is not None

lines = []
def w(s=u""):
    if not isinstance(s, unicode):
        s = unicode(str(s), "utf-8", "replace")
    lines.append(s)

# scan all initialized memory at 4-byte alignment for msgmap entries
entries = []   # (addr, nID, nCode, pfn)
for block in mem.getBlocks():
    if not block.isInitialized():
        continue
    start = block.getStart().getOffset()
    end = block.getEnd().getOffset()
    a = (start + 3) & ~3
    while a + 24 <= end:
        w0 = u32(a)
        if w0 == WM_COMMAND:
            nID = u32(a + 8)
            nLast = u32(a + 12)
            pfn = u32(a + 20)
            nCode = u32(a + 4)
            if (nID is not None and pfn is not None and nID == nLast
                    and 0 < nID < 0x10000 and is_code(pfn)):
                entries.append((a, nID, nCode, pfn))
        a += 4

w(u"# MFC WM_COMMAND message-map entries: %d" % len(entries))
w(u"")
w(u"| entry | nID (dec) | nID (hex) | nCode | handler |")
w(u"|---|---|---|---|---|")
id_to_pfn = {}
for addr, nID, nCode, pfn in sorted(entries, key=lambda e: e[1]):
    fn = fm.getFunctionContaining(toAddr(pfn))
    fnname = fn.getName() if fn is not None else "?"
    mark = "  <== TARGET" if nID in TARGET_IDS else ""
    w(u"| %s | %d | 0x%x | 0x%x | %s%s |" % (hex(addr), nID, nID, nCode, fnname, mark))
    id_to_pfn.setdefault(nID, set()).add(pfn)
w(u"")

# decompile handlers for target ids
di = DecompInterface()
di.openProgram(prog)
w(u"## decompiled handlers for target IDs %s" % sorted(TARGET_IDS))
w(u"")
done = set()
for nID in sorted(TARGET_IDS):
    for pfn in sorted(id_to_pfn.get(nID, [])):
        fn = fm.getFunctionContaining(toAddr(pfn))
        if fn is None or fn.getEntryPoint() in done:
            continue
        done.add(fn.getEntryPoint())
        code = u""
        try:
            res = di.decompileFunction(fn, 90, monitor)
            if res is not None and res.decompileCompleted():
                code = res.getDecompiledFunction().getC()
        except Exception as e:
            code = u"// decompile failed: %s" % e
        w(u"// ===== id=%d  handler %s @ %s =====" % (nID, fn.getName(), fn.getEntryPoint()))
        w(unicode(code))
        w(u"")

f = codecs.open(OUT, "w", "utf-8")
f.write(u"\n".join(lines)); f.write(u"\n"); f.close()
println("CANON_MSGMAP entries=%d targets=%d handlers=%d" %
        (len(entries), len(TARGET_IDS), len(done)))
