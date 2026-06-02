#!/usr/bin/env python3
"""
LANE C — entropy + structure analysis of /tmp/APP.BIN.

(1) sliding-window Shannon entropy -> uniform cipher vs cleartext header/footer
(2) ECB-tell: repeated fixed-size blocks; byte-value histogram; autocorrelation
(3) header/footer scan: printable runs, small magic, length fields
(4) crib scan: zlib headers, wx signatures, ASCII key strings
"""
import collections
import math
import struct

APPBIN = "/tmp/APP.BIN"


def shannon(buf):
    if not buf:
        return 0.0
    c = collections.Counter(buf)
    n = len(buf)
    h = 0.0
    for v in c.values():
        p = v / n
        h -= p * math.log2(p)
    return h


def hexdump(buf, off, n=64):
    out = []
    for i in range(0, n, 16):
        chunk = buf[off + i:off + i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"  {off+i:08x}  {hexs:<47}  {asci}")
    return "\n".join(out)


def main():
    data = open(APPBIN, "rb").read()
    n = len(data)
    print(f"=== APP.BIN: {n} bytes (0x{n:x}) ===\n")

    # whole-blob entropy
    print(f"[entropy] whole-blob Shannon = {shannon(data):.4f} bits/byte")

    # sliding window 1024, step 512
    W, S = 1024, 512
    lows = []
    minh = (9.9, -1)
    maxh = (0.0, -1)
    series = []
    for start in range(0, n - W + 1, S):
        h = shannon(data[start:start + W])
        series.append((start, h))
        if h < minh[0]:
            minh = (h, start)
        if h > maxh[0]:
            maxh = (h, start)
        if h < 7.0:
            lows.append((start, h))
    print(f"[entropy] window={W} step={S}: "
          f"min={minh[0]:.3f}@0x{minh[1]:x}  max={maxh[0]:.3f}@0x{maxh[1]:x}")
    print(f"[entropy] windows below 7.0 bits/byte: {len(lows)}")
    for st, h in lows[:20]:
        print(f"          low window @0x{st:x}: H={h:.3f}")

    # first / last region fine-grained (64-byte windows) to spot a small header/footer
    print("\n[entropy] head region 64-byte windows (first 16):")
    for start in range(0, min(16 * 64, n), 64):
        h = shannon(data[start:start + 64])
        flag = "  <-- low" if h < 5.5 else ""
        print(f"          @0x{start:04x}: H={h:.3f}{flag}")
    print("[entropy] tail region 64-byte windows (last 16):")
    for start in range(max(0, n - 16 * 64), n, 64):
        h = shannon(data[start:start + 64])
        flag = "  <-- low" if h < 5.5 else ""
        print(f"          @0x{start:04x}: H={h:.3f}{flag}")

    # byte histogram extremes
    hist = collections.Counter(data)
    most = hist.most_common(5)
    least = sorted(hist.items(), key=lambda x: x[1])[:5]
    print(f"\n[hist] 256 distinct? {len(hist)==256}; "
          f"expected/byte={n/256:.1f}")
    print(f"[hist] most common: {[(f'0x{b:02x}', c) for b, c in most]}")
    print(f"[hist] least common: {[(f'0x{b:02x}', c) for b, c in least]}")
    chi2 = sum((c - n / 256) ** 2 / (n / 256) for c in hist.values())
    print(f"[hist] chi-square vs uniform = {chi2:.1f} "
          f"(df=255; ~255 means uniform/random)")

    # ECB-tell: look for repeated aligned blocks at several block sizes
    print("\n[ecb] repeated identical aligned blocks:")
    for bs in (8, 16, 32, 64):
        seen = {}
        dup = 0
        dup_examples = []
        for i in range(0, n - bs + 1, bs):
            blk = bytes(data[i:i + bs])
            if blk in seen:
                dup += 1
                if len(dup_examples) < 3:
                    dup_examples.append((seen[blk], i))
            else:
                seen[blk] = i
        nblk = n // bs
        print(f"      block={bs:2d}B: {nblk} blocks, {dup} duplicates "
              f"(uniq={len(seen)}) ex={dup_examples}")

    # generic repeated-substring (any offset) via simple 16-byte rolling set
    print("\n[repeat] any-offset 16-byte substring repeats (sampled):")
    win = 16
    seen = {}
    rep = 0
    for i in range(0, n - win, 1):
        sub = bytes(data[i:i + win])
        if sub in seen:
            rep += 1
        else:
            seen[sub] = i
    print(f"      16-byte unaligned repeats: {rep} (of {n-win} positions)")

    # length-field guesses in head: read a few u16/u32 LE/BE
    print("\n[header] first 32 bytes as candidate fields:")
    print(hexdump(data, 0, 64))
    for fmt, lab in (("<I", "u32 LE"), (">I", "u32 BE"),
                     ("<H", "u16 LE"), (">H", "u16 BE")):
        sz = struct.calcsize(fmt)
        vals = [struct.unpack_from(fmt, data, o)[0] for o in range(0, 16, sz)]
        print(f"      {lab}: {vals}  (file_size={n}, size-4={n-4}, "
              f"size-8={n-8}, size-16={n-16})")
    print("\n[footer] last 64 bytes:")
    print(hexdump(data, n - 64, 64))

    # crib scan
    print("\n[crib] scan for known plaintext / magic in the RAW (encrypted) blob:")
    cribs = {
        b"\x78\x9c": "zlib default",
        b"\x78\x01": "zlib no/low compression",
        b"\x78\xda": "zlib best",
        b"\x78\x5e": "zlib level2-5",
        b"\x1f\x8b": "gzip",
        b"PK\x03\x04": "zip local file header",
        b"PK\x05\x06": "zip EOCD",
        b"ustar": "tar ustar",
        b"functions": "key:functions",
        b"command": "key:command",
        b"keyword": "key:keyword",
        b"default": "key:default",
        b"userdata": "key:userdata",
        b"functor": "key:functor",
        b"waste": "key:waste",
        b"BZh": "bzip2",
        b"\xfd7zXZ": "xz",
        b"<?xml": "xml",
        b"SQLite": "sqlite",
    }
    any_hit = False
    for pat, lab in cribs.items():
        idx = data.find(pat)
        if idx != -1:
            any_hit = True
            print(f"      HIT {lab!r:30s} '{pat}' @0x{idx:x}")
    if not any_hit:
        print("      (none found in raw blob — consistent with whole-blob cipher)")

    # try the single-byte-XOR sanity (the doc says FALSIFIED — confirm zlib never appears)
    print("\n[xor] single-byte XOR scan for a zlib 0x78 9c/01/da header at offset 0:")
    head2 = data[:2]
    for k in range(256):
        d0 = head2[0] ^ k
        d1 = head2[1] ^ k
        if d0 == 0x78 and d1 in (0x9c, 0x01, 0xda, 0x5e):
            print(f"      key=0x{k:02x} -> {d0:02x}{d1:02x} (zlib) at off0")
    print("      (scan complete)")


if __name__ == "__main__":
    main()
