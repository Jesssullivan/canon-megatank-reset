# -*- coding: utf-8 -*-
# canon-tool R3 TIN-1697 — decompile the callers of a target function.
#
# Used to walk UP from the low-level USB IOCTL function (FUN_004302c0) to the
# command layer, where the literal (cmd_byte, arg16) opcodes are passed as
# constants — that's where the absorber-reset command lives.
#
# postScript args: <target_hex_addr> <out.c> [depth]
#   depth 1 = direct callers (default), 2 = callers + their callers

import codecs
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
TARGET = long(args[0], 16)
OUT = args[1]
DEPTH = int(args[2]) if len(args) > 2 else 1

prog = currentProgram
fm = prog.getFunctionManager()
monitor = ConsoleTaskMonitor()

target_func = fm.getFunctionContaining(toAddr(TARGET))

def callers_of(func):
    out = set()
    if func is None:
        return out
    for f in func.getCallingFunctions(monitor):
        out.add(f)
    return out

level = {f: 1 for f in callers_of(target_func)}
if DEPTH >= 2:
    for f in list(level.keys()):
        for c in callers_of(f):
            if c not in level:
                level[c] = 2

di = DecompInterface()
di.openProgram(prog)

f = codecs.open(OUT, "w", "utf-8")
f.write(u"// callers of %s (%s), depth=%d, %d functions\n\n" %
        (target_func.getName() if target_func else hex(TARGET),
         hex(TARGET), DEPTH, len(level)))

for func in sorted(level.keys(), key=lambda x: (level[x], x.getEntryPoint().getOffset())):
    code = u""
    try:
        res = di.decompileFunction(func, 90, monitor)
        if res is not None and res.decompileCompleted():
            code = res.getDecompiledFunction().getC()
    except Exception as e:
        code = u"// decompile failed: %s" % e
    f.write(u"// ===== L%d  %s @ %s =====\n" % (level[func], func.getName(), func.getEntryPoint()))
    f.write(unicode(code))
    f.write(u"\n\n")
f.close()

println("CANON_CALLERS target=%s callers=%d" % (hex(TARGET), len(level)))
