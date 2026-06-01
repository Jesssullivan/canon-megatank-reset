#!/usr/bin/env python3
"""
appbin_oracle.py — LANE C validation oracle + container model for APP.BIN.

Container (RECOVERED by static RE, see docs/research/wicreset-appbin-container.md):

  printerpotty.exe  PE resource  DATA / "APP.BIN"
    - file offset 0x638ee8 (NOT 0x66c6e8 — that was the RVA), size 571596 (0x8b8cc)
    - whole blob: Shannon 7.9997 b/B, chi^2~239, all 256 byte values, NO ECB
      block repeats, NO cleartext header/footer in the resource itself.

  Mount pipeline (FUN_00530ae0):
    1. copy whole resource into a wxMemoryBuffer (FUN_004d2510)
    2. FUN_004d2a10 strips the LAST 4 BYTES (a trailing 4-byte footer/trailer).
       => body = blob[:-4] = 571592 bytes = 0x8b8c8 = 8 * 71449  (block-aligned!)
    3. build an in-memory wxFileSystem subclass `XFSVirtual` (vtable 0x0098b5a8)
       over a `std::_Tree<unsigned int>`-indexed set of files; the dotted/slash
       VFS paths ("default/userdata", ...) name the entries.
    4. the archive is parsed by the app's own `archive::des` class
       (FUN_00427e70 installs archive::des::vftable @ 0x00970ef8), whose read
       method (slot 1 = FUN_00415070) does:
          DES-decrypt the stream (FUN_00456e20), then
          strip PKCS-style padding:  pad = 8 - (len & 7),
       and hands the plaintext to `archive::zip` (FUN_00427f10 swaps the vtable
       to archive::zip::vftable @ 0x00970f08) for ZIP local-file parsing.

  CIPHER (RECOVERED, HIGH): TRIPLE-DES (DES-EDE3) in CBC mode.
    - FUN_004554b0 = textbook DES block fn (IP delta-swaps 0x0f0f0f0f/0xffff/
      0x33333333/0x00ff00ff/0xaaaaaaaa; 16 Feistel rounds; 8 SP-boxes
      @0x009713b0..0x00971ab0, runtime-initialized).
    - FUN_00455050 = DES key schedule (PC-1/PC-2; rotation 1 at rounds
      {0,1,8,15} else 2 — the standard DES shift schedule).
    - FUN_00456e20 runs the key schedule 3x (=> 3 key blocks = 24-byte 3DES key)
      and chains 8-byte blocks via XOR-with-previous-ciphertext (=> CBC).
    - block size 8; data length always a multiple of 8 (asserted: len & 7 == 0).

  INNER FORMAT after 3DES-CBC decrypt: a ZIP archive (archive::zip), whose member
  files ARE the VFS entries ("default/userdata" etc.). zlib inflate (FUN_00794130)
  is present and used by wxZlibInputStream for the per-member DEFLATE.

  So the full container is:   3DES-CBC( ZIP( deflate(member files) ) )  || 4-byte footer.

This module gives Lanes A/B:
  * load_appbin()        -> the raw 571596-byte blob
  * body()               -> blob with the 4-byte footer stripped (the 3DES input)
  * looks_like_plaintext(buf) -> the validation ORACLE: True iff a candidate
    decrypt looks like the expected ZIP plaintext (PK signature / key strings).
  * try_3des_cbc(key, iv) helper if pycryptodome/pyca is available.
"""
import struct
import sys

APPBIN_DEFAULT = "/tmp/APP.BIN"

# ---- expected cleartext cribs after a CORRECT decrypt ----
# the inner archive is a ZIP, so the very first plaintext bytes should be a ZIP
# local-file-header signature; the member NAMES + the property-tree keys must
# appear as ASCII somewhere in the plaintext.
ZIP_LOCAL = b"PK\x03\x04"          # zip local file header (expected at offset 0)
ZIP_CD = b"PK\x01\x02"             # zip central directory
ZIP_EOCD = b"PK\x05\x06"           # zip end of central directory
ZLIB_HDRS = (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e")

# VFS paths / property-tree keys that MUST be ASCII in the plaintext (filenames
# inside the zip central directory + the userdata tree leaf keys).
KEY_STRINGS = [
    b"default", b"userdata", b"functions", b"command", b"keyword",
    b"functor", b"waste", b"index", b"codes", b"shift",
    b"translations", b"runtime", b"language", b"platform",
    b"app.ini", b"splash.png", b"update",
]


def load_appbin(path=APPBIN_DEFAULT):
    with open(path, "rb") as f:
        return f.read()


def body(blob):
    """The 3DES-CBC ciphertext = resource minus the 4-byte trailing footer."""
    return blob[:-4]


def footer(blob):
    """The 4 trailing bytes stripped by FUN_004d2a10 (role: trailer/length/MAC?)."""
    return blob[-4:]


def looks_like_plaintext(buf):
    """
    VALIDATION ORACLE for Lanes A/B.
    Given a *candidate decrypted* buffer, return (ok: bool, reasons: list[str]).
    A correct 3DES-CBC decrypt of body() should be a ZIP archive.
    """
    reasons = []
    score = 0
    if not buf:
        return False, ["empty"]

    # 1) strongest: ZIP local header at offset 0
    if buf[:4] == ZIP_LOCAL:
        score += 100
        reasons.append("ZIP local-file-header 'PK\\x03\\x04' at offset 0 (STRONG)")
    elif ZIP_LOCAL in buf[:64]:
        score += 60
        reasons.append("ZIP 'PK\\x03\\x04' within first 64 bytes")

    # 2) ZIP central dir / EOCD anywhere
    if ZIP_CD in buf:
        score += 30
        reasons.append("ZIP central-directory 'PK\\x01\\x02' present")
    if ZIP_EOCD in buf:
        score += 30
        reasons.append("ZIP EOCD 'PK\\x05\\x06' present")

    # 3) member filenames / property-tree keys as ASCII
    hits = [k for k in KEY_STRINGS if k in buf]
    if hits:
        score += 5 * len(hits)
        reasons.append("key strings present: %s"
                       % ", ".join(h.decode() for h in hits))

    # 4) zlib stream headers (per-member deflate) — weak on its own
    zl = [h for h in ZLIB_HDRS if h in buf[:4096]]
    if zl:
        score += 5
        reasons.append("zlib header(s) in first 4 KiB: %s"
                       % ", ".join(h.hex() for h in zl))

    # 5) entropy sanity: real plaintext zip has structure (lower than 7.99)
    import collections, math
    c = collections.Counter(buf[:65536])
    n = sum(c.values())
    h = -sum((v / n) * math.log2(v / n) for v in c.values()) if n else 0
    reasons.append("first-64K Shannon=%.3f b/B" % h)
    if h < 7.5:
        score += 10
        reasons.append("entropy < 7.5 (decompressed/structured — good)")

    ok = score >= 60  # require at least a strong ZIP signal
    reasons.insert(0, "SCORE=%d -> %s" % (score, "LOOKS-CORRECT" if ok else "no"))
    return ok, reasons


def try_3des_cbc(key, iv=b"\x00" * 8, path=APPBIN_DEFAULT):
    """
    Convenience: attempt a DES-EDE3-CBC decrypt of body() with the given
    24-byte key + 8-byte IV, then run the oracle. Requires pycryptodome.
    Returns (ok, reasons, plaintext_or_None).
    """
    try:
        from Crypto.Cipher import DES3
    except Exception:
        return None, ["pycryptodome not installed (pip install pycryptodome)"], None
    blob = load_appbin(path)
    ct = body(blob)
    if len(ct) % 8 != 0:
        return False, ["ciphertext not 8-aligned (%d)" % len(ct)], None
    try:
        k = DES3.adjust_key_parity(key) if hasattr(DES3, "adjust_key_parity") else key
    except Exception:
        k = key
    pt = DES3.new(k, DES3.MODE_CBC, iv).decrypt(ct)
    ok, reasons = looks_like_plaintext(pt)
    return ok, reasons, pt


def decrypt_container(blob):
    """
    Decrypt one container layer: strip the 4-byte footer, DES-CBC(zero,zero).
    Returns the plaintext (a ZIP). Works for both APP.BIN and devices.srs.
    """
    from Crypto.Cipher import DES
    ct = blob[:-4]
    if len(ct) % 8 != 0:
        raise ValueError("ciphertext not 8-aligned after footer strip: %d" % len(ct))
    return DES.new(b"\x00" * 8, DES.MODE_CBC, b"\x00" * 8).decrypt(ct)


def extract_devices_xml(path=APPBIN_DEFAULT):
    """
    Full recursive unwrap APP.BIN -> ZIP -> devices.srs -> ZIP -> devices.xml.
    Returns the 2.5 MB plaintext template XML bytes.
    """
    import io
    import zipfile
    outer = zipfile.ZipFile(io.BytesIO(decrypt_container(load_appbin(path))))
    srs = outer.read("devices.srs")
    inner = zipfile.ZipFile(io.BytesIO(decrypt_container(srs)))
    return inner.read("devices.xml")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else APPBIN_DEFAULT
    blob = load_appbin(path)
    print("APP.BIN: %d bytes (0x%x)" % (len(blob), len(blob)))
    b = body(blob)
    print("body (3DES input): %d bytes (0x%x), 8-aligned=%s"
          % (len(b), len(b), len(b) % 8 == 0))
    print("stripped 4-byte footer: %s" % footer(blob).hex(" "))
    print("first 16: %s" % blob[:16].hex(" "))
    # demonstrate the oracle on the RAW (still-encrypted) blob => should say 'no'
    ok, reasons = looks_like_plaintext(blob)
    print("\noracle on RAW (encrypted) blob:")
    for r in reasons:
        print("  - %s" % r)
