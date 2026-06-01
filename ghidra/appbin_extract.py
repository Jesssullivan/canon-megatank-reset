#!/usr/bin/env python3
"""
LANE C — APP.BIN container/entropy analysis for printerpotty.exe.

Parses the PE .rsrc directory by hand (no pefile dependency), locates the
DATA / "APP.BIN" resource, carves it, verifies against the documented
file offset 0x66c6e8 / size 571596, and writes APP.BIN to disk for the
downstream structure/entropy/crib analysis.
"""
import os
import struct
import sys

BIN = "/Users/jess/git/canon-megatank-reset/.ghidra-work/bin/printerpotty.exe"
OUT_APPBIN = "/tmp/APP.BIN"

DOC_OFFSET = 0x66c6e8   # 6735592
DOC_SIZE = 571596


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def main():
    data = open(BIN, "rb").read()
    print(f"[*] file size = {len(data)} (0x{len(data):x})")

    # --- DOS header ---
    assert data[:2] == b"MZ", "not MZ"
    e_lfanew = u32(data, 0x3C)
    assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0", "no PE sig"
    coff = e_lfanew + 4
    machine = u16(data, coff + 0)
    num_sections = u16(data, coff + 2)
    size_opt = u16(data, coff + 16)
    opt = coff + 20
    magic = u16(data, opt + 0)
    is_pe32p = (magic == 0x20B)
    print(f"[*] machine=0x{machine:04x} sections={num_sections} "
          f"opt_magic=0x{magic:04x} ({'PE32+' if is_pe32p else 'PE32'})")

    # data directories start
    # PE32: NumberOfRvaAndSizes at opt+92, dirs at opt+96
    # PE32+: at opt+108, dirs at opt+112
    if is_pe32p:
        dd_off = opt + 112
    else:
        dd_off = opt + 96
    # Resource directory is index 2
    rsrc_rva = u32(data, dd_off + 2 * 8 + 0)
    rsrc_size = u32(data, dd_off + 2 * 8 + 4)
    print(f"[*] .rsrc dir RVA=0x{rsrc_rva:x} size=0x{rsrc_size:x}")

    # --- section table: map RVA -> file offset ---
    sect_tbl = opt + size_opt
    sections = []
    for i in range(num_sections):
        so = sect_tbl + i * 40
        name = data[so:so + 8].rstrip(b"\0").decode("latin1", "replace")
        vsize = u32(data, so + 8)
        vaddr = u32(data, so + 12)
        rawsize = u32(data, so + 16)
        rawptr = u32(data, so + 20)
        sections.append((name, vaddr, vsize, rawptr, rawsize))
        print(f"    sect {name:8s} vaddr=0x{vaddr:08x} vsize=0x{vsize:06x} "
              f"raw=0x{rawptr:08x} rawsz=0x{rawsize:06x}")

    def rva_to_off(rva):
        for name, vaddr, vsize, rawptr, rawsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rawptr + (rva - vaddr)
        return None

    rsrc_off = rva_to_off(rsrc_rva)
    print(f"[*] .rsrc file offset = 0x{rsrc_off:x}")

    # --- walk resource directory tree ---
    # IMAGE_RESOURCE_DIRECTORY: 16 bytes header, then entries (8 bytes each)
    found = []

    def walk(dir_rva, level, path):
        base = rva_to_off(dir_rva)
        if base is None:
            return
        n_named = u16(data, base + 12)
        n_id = u16(data, base + 14)
        total = n_named + n_id
        ent = base + 16
        for i in range(total):
            eo = ent + i * 8
            name_field = u32(data, eo + 0)
            off_field = u32(data, eo + 4)
            if name_field & 0x80000000:
                # named entry: name is a IMAGE_RESOURCE_DIR_STRING_U at rsrc_rva+offset
                str_rva = rsrc_rva + (name_field & 0x7FFFFFFF)
                str_off = rva_to_off(str_rva)
                slen = u16(data, str_off)
                name = data[str_off + 2:str_off + 2 + slen * 2].decode(
                    "utf-16-le", "replace")
                key = name
            else:
                key = name_field & 0xFFFF  # numeric ID
            newpath = path + [key]
            if off_field & 0x80000000:
                # subdirectory
                sub_rva = rsrc_rva + (off_field & 0x7FFFFFFF)
                walk(sub_rva, level + 1, newpath)
            else:
                # data entry: IMAGE_RESOURCE_DATA_ENTRY
                de_rva = rsrc_rva + off_field
                de_off = rva_to_off(de_rva)
                data_rva = u32(data, de_off + 0)
                data_size = u32(data, de_off + 4)
                data_off = rva_to_off(data_rva)
                found.append((newpath, data_rva, data_off, data_size))

    walk(rsrc_rva, 0, [])

    print(f"[*] {len(found)} resource data entries; top-level types present:")
    types = {}
    for path, rva, off, size in found:
        types.setdefault(path[0], 0)
        types[path[0]] += 1
    for t, c in sorted(types.items(), key=lambda x: str(x[0])):
        print(f"    type {t!r}: {c} entries")

    # locate APP.BIN (type DATA)
    target = None
    for path, rva, off, size in found:
        if any(isinstance(p, str) and p.upper() == "APP.BIN" for p in path):
            print(f"[+] APP.BIN resource: path={path} data_rva=0x{rva:x} "
                  f"file_off=0x{off:x} size={size} (0x{size:x})")
            target = (off, size)

    if target is None:
        # fall back to the DATA type listing
        print("[!] APP.BIN not found by name; dumping all DATA-type entries:")
        for path, rva, off, size in found:
            if isinstance(path[0], str) and path[0].upper() == "DATA":
                print(f"    {path} off=0x{off:x} size={size}")
        sys.exit(2)

    off, size = target
    print(f"[*] documented offset 0x{DOC_OFFSET:x} size {DOC_SIZE}; "
          f"parsed offset 0x{off:x} size {size} -> "
          f"{'MATCH' if (off == DOC_OFFSET and size == DOC_SIZE) else 'DIFF'}")

    blob = data[off:off + size]
    open(OUT_APPBIN, "wb").write(blob)
    print(f"[+] wrote {OUT_APPBIN} ({len(blob)} bytes)")

    import hashlib
    print(f"[*] APP.BIN sha256 = {hashlib.sha256(blob).hexdigest()}")
    # also carve at documented offset to compare
    carved = data[DOC_OFFSET:DOC_OFFSET + DOC_SIZE]
    print(f"[*] carve@doc sha256= {hashlib.sha256(carved).hexdigest()} "
          f"({'same' if carved == blob else 'DIFFERENT'})")


if __name__ == "__main__":
    main()
