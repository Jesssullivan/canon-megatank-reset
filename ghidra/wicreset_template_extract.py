#!/usr/bin/env python3
# wicreset_template_extract.py — recover, from the saved read-only Ghidra DB of
# printerpotty.exe, the LITERAL structure of the Canon reset-frame encryption:
#
#   1. the dotted-path template KEYS the Canon class reads at runtime to build a
#      reset frame and its cipher (functions.waste, commands.set_command,
#      command.index/codes/shift, keyword.index/codes, functor, encoders, ...),
#   2. the functor_encryption_003 envelope layout (the [00 12][01][cmdByte][16
#      deterministic LCG bytes] header) by disassembling 0x4e8410..0x4e8620,
#   3. the deterministic 16-byte MSVC-rand() header sequence (seed 0x12345678,
#      mul 0x343fd, add 0x269ec3, byte = (seed>>16)&0xff).
#
# Read-only: opens the EXISTING analyzed program by name; never re-imports.
#
#   GHIDRA_INSTALL_DIR=<...>/lib/ghidra \
#   CMR_PROJ=$PWD/.ghidra-work/project-full \
#   .ghidra-work/.pgvenv12/bin/python ghidra/wicreset_template_extract.py
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-template-extract.txt")

# dotted-path keys + spec strings that prove the reset frame + cipher are
# template-driven (the absorber idx/op/cmd live in the runtime model template,
# NOT as static .data constants — re-confirmed: no G6000/G6020 strings).
TEMPLATE_KEYS = [
    "functions.waste", "commands.set_command", "commands.get_command",
    "commands.set_session", "commands.get_keyword", "commands.get_version",
    "command.index", "command.codes", "command.shift",
    "keyword.index", "keyword.codes", "encoders", "encoded", "decoded",
    "functor", "special", "indexes", "statuses", "action", "prefix",
    "VENDOR", "handler", "label", "model.value", "model.label",
]


def lcg16():
    seed = 0x12345678
    out = []
    for _ in range(16):
        seed = (seed * 0x343FD + 0x269EC3) & 0xFFFFFFFF
        out.append((seed >> 16) & 0xFF)
    return out


def main():
    with open_program(None, project_location=PROJ, project_name=NAME,
                      program_name=PROG, analyze=False) as flat:
        p = flat.getCurrentProgram()
        af = p.getAddressFactory()
        listing = p.getListing()
        fh = open(OUT, "w")

        def w(s=""):
            fh.write(s + "\n")
            print(s)

        # 1. template key census
        w("===== template/config keys present (lookup keys into runtime model tree) =====")
        di = listing.getDefinedData(True)
        found = {}
        while di.hasNext():
            d = di.next()
            v = d.getValue()
            if v is None:
                continue
            s = str(v)
            if not isinstance(s, str):
                continue
            for k in TEMPLATE_KEYS:
                if s == k:
                    found[k] = d.getAddress().toString()
        for k in TEMPLATE_KEYS:
            w("  %-24s %s" % (k, found.get(k, "(exact-string not found)")))

        # 2. envelope disassembly
        w("\n===== functor_encryption_003 envelope build (0x4e8410..0x4e8620) =====")
        start = af.getAddress("004e8410")
        end = af.getAddress("004e8620")
        ins = listing.getInstructions(start, True)
        while ins.hasNext():
            i = ins.next()
            if i.getAddress().getOffset() > end.getOffset():
                break
            w("  %s  %s" % (i.getAddress(), i))

        # 3. deterministic header bytes
        w("\n===== deterministic LCG header (MSVC rand, seed 0x12345678) =====")
        w("  16 bytes after [00 12][01][cmdByte]:  " +
          " ".join("%02x" % b for b in lcg16()))

        fh.close()
        print("CMR_DONE wrote %s" % OUT)


main()
