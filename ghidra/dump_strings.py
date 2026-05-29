# -*- coding: utf-8 -*-
# Dump ALL defined strings from the analyzed program to a file, plus a
# filtered model/command-vocabulary hit list. Robust against Ghidra 11.x
# API drift (no DefinedDataIterator dependency — walks getDefinedData).
#
# postScript args: <all_strings_out> <hits_out>

import codecs

args = getScriptArgs()
ALL_OUT = args[0]
HITS_OUT = args[1]

prog = currentProgram
listing = prog.getListing()

# Model names + maintenance/command vocabulary we care about.
MODELS = ["g6020", "g6000", "g6010", "g3000", "g3010", "g3020", "g4010",
          "g4020", "g5000", "g7020", "g7000", "gm2", "gm4", "maxify",
          "pixma", "ts3", "tr4"]
VOCAB = ["absorber", "waste", "ink", "counter", "eeprom", "5b00", "reset",
         "service mode", "maintenance", "usbscan", "bulk", "ioctl",
         "scsi", "print", "head", "purge", "platen", "borderless",
         "cleaning", "nozzle", "support code", "operator", "set "]

def is_string_data(d):
    try:
        dt = d.getDataType().getName().lower()
    except Exception:
        return False
    return ("unicode" in dt) or ("string" in dt) or (dt == "char" or dt.startswith("char["))

all_rows = []      # (addr, dtype, value)
it = listing.getDefinedData(True)
while it.hasNext():
    d = it.next()
    if not is_string_data(d):
        continue
    try:
        val = d.getValue()
    except Exception:
        continue
    if val is None:
        continue
    sval = unicode(val)
    if len(sval.strip()) == 0:
        continue
    try:
        dtype = d.getDataType().getName()
    except Exception:
        dtype = "?"
    all_rows.append((str(d.getAddress()), dtype, sval))

# ---- write the full string table -----------------------------------------
f = codecs.open(ALL_OUT, "w", "utf-8")
f.write(u"# v5103 defined strings (%d)\n" % len(all_rows))
for addr, dtype, sval in all_rows:
    one = sval.replace(u"\n", u"\\n").replace(u"\r", u"\\r").replace(u"\t", u"\\t")
    f.write(u"%s\t%s\t%s\n" % (addr, dtype, one))
f.close()

# ---- filtered hits ---------------------------------------------------------
def hits_for(sval, kws):
    low = sval.lower()
    return [k for k in kws if k in low]

model_hits = []
vocab_hits = []
for addr, dtype, sval in all_rows:
    mh = hits_for(sval, MODELS)
    vh = hits_for(sval, VOCAB)
    if mh:
        model_hits.append((addr, mh, sval))
    if vh:
        vocab_hits.append((addr, vh, sval))

g = codecs.open(HITS_OUT, "w", "utf-8")
g.write(u"# v5103 string hits\n\n")
g.write(u"## MODEL-NAME hits (%d) — decides the family-shared-protocol question\n\n" % len(model_hits))
for addr, mh, sval in model_hits:
    one = sval.replace(u"\n", u"\\n").replace(u"\r", u"\\r")
    if len(one) > 160:
        one = one[:160] + u"..."
    g.write(u"%s\t[%s]\t%s\n" % (addr, u",".join(sorted(set(mh))), one))
g.write(u"\n## VOCAB hits (%d)\n\n" % len(vocab_hits))
for addr, vh, sval in vocab_hits:
    one = sval.replace(u"\n", u"\\n").replace(u"\r", u"\\r")
    if len(one) > 160:
        one = one[:160] + u"..."
    g.write(u"%s\t[%s]\t%s\n" % (addr, u",".join(sorted(set(vh))), one))
g.close()

println("CANON_STRINGS total=%d model_hits=%d vocab_hits=%d" %
        (len(all_rows), len(model_hits), len(vocab_hits)))
