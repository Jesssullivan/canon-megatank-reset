# -*- coding: utf-8 -*-
# canon-tool R3 TIN-1697 — decompile the USB transport + command-buffer code.
#
# Finds the functions that (a) call WriteFile/ReadFile/DeviceIoControl/CreateFileA,
# (b) reference the \\.\Usbscan%d device path, or (c) reference the CEEPROM*
# vtables / EEPROM op strings — then decompiles them to C and writes the corpus
# to <out>, ranked so the USB write path floats to the top.
#
# postScript arg: <out.c>

import codecs
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
OUT = args[0]

prog = currentProgram
fm = prog.getFunctionManager()
st = prog.getSymbolTable()
refmgr = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()

TARGET_FUNCS = ["WriteFile", "ReadFile", "DeviceIoControl", "CreateFileA",
                "SetupDiGetClassDevsA", "SetupDiEnumDeviceInterfaces",
                "SetupDiGetDeviceInterfaceDetailA"]

# data/string/vtable addresses of interest (from TIN-1695 dump)
TARGET_ADDRS = {
    0x472404: "str:\\\\.\\Usbscan%d",
    0x4723f8: "str:Usbscan%d",
    0x4822e4: "str:EEPROM Print",
    0x4710bc: "str:No service mode printer",
    0x4720b4: "str:An undefined command",
    0x46f140: "vtbl:CEEPROMDumpSave",
    0x46f378: "vtbl:CEEPROMHeadDumpSave",
    0x46f5a0: "vtbl:CEEPROMInfoDlg",
}

func_reasons = {}          # entry -> (func, set(reason))
callsite_counts = {}       # target name -> count

def add(func, reason):
    if func is None:
        return
    ep = func.getEntryPoint()
    if ep not in func_reasons:
        func_reasons[ep] = (func, set())
    func_reasons[ep][1].add(reason)

# (1) callers of target imported functions
for name in TARGET_FUNCS:
    cnt = 0
    for sym in st.getSymbols(name):
        for r in refmgr.getReferencesTo(sym.getAddress()):
            caller = fm.getFunctionContaining(r.getFromAddress())
            if caller is not None:
                add(caller, "calls:" + name)
                cnt += 1
    callsite_counts[name] = cnt

# (2) referrers of target addrs
for a, label in TARGET_ADDRS.items():
    addr = toAddr(a)
    if addr is None:
        continue
    for r in refmgr.getReferencesTo(addr):
        caller = fm.getFunctionContaining(r.getFromAddress())
        if caller is not None:
            add(caller, "uses:" + label)

# rank: USB device path + DeviceIoControl/WriteFile float to the top
def score(item):
    func, reasons = item
    s = 0
    for r in reasons:
        if "Usbscan" in r:          s += 100
        if "DeviceIoControl" in r:  s += 60
        if "WriteFile" in r:        s += 50
        if "ReadFile" in r:         s += 30
        if "CreateFileA" in r:      s += 40
        if "CEEPROM" in r:          s += 25
        if "EEPROM Print" in r:     s += 20
        if "SetupDi" in r:          s += 10
    return -s

items = list(func_reasons.values())
items.sort(key=score)

di = DecompInterface()
di.openProgram(prog)

MAX = 50
f = codecs.open(OUT, "w", "utf-8")
f.write(u"// canon-tool R3 TIN-1697 — USB transport decompilation corpus\n")
f.write(u"// callsite counts: %s\n" % callsite_counts)
f.write(u"// candidate functions: %d (dumping top %d)\n\n" % (len(items), min(MAX, len(items))))

dumped = 0
for func, reasons in items[:MAX]:
    code = u""
    try:
        res = di.decompileFunction(func, 90, monitor)
        if res is not None and res.decompileCompleted():
            code = res.getDecompiledFunction().getC()
    except Exception as e:
        code = u"// decompile failed: %s" % e
    f.write(u"// ===== %s @ %s  [%s] =====\n" %
            (func.getName(), func.getEntryPoint(), u", ".join(sorted(reasons))))
    f.write(unicode(code))
    f.write(u"\n\n")
    dumped += 1
f.close()

println("CANON_TRACE candidates=%d dumped=%d callsites=%s" %
        (len(items), dumped, callsite_counts))
