# WICReset `APP.BIN` — container format + entropy analysis (LANE C)

**Date:** 2026-06-01 · **Binary:** `printerpotty.exe` (PE32, 7.48 MB,
`sha256 a199447db7d9237d95b11456db6e6d9898ab2eb2cae7918acaa1c700a564b3e8`).
**Tooling:** manual PE `.rsrc` parser + Python entropy/oracle; PyGhidra against
Ghidra 12.0.2 (`.ghidra-work/.pgvenv12`, JDK 21), saved DB
`project-full/wicreset-pp-full` opened read-only by name. Tracked scripts (new):
`ghidra/appbin_extract.py`, `ghidra/appbin_entropy.py`,
`ghidra/wicreset_container_struct.py`, `ghidra/wicreset_xfs_methods.py`,
`ghidra/wicreset_archive_des.py`, `scripts/appbin_oracle.py`. Raw dumps
(gitignored): `/tmp/APP.BIN`, `/tmp/APP.dec.zip`, `/tmp/pp-*.txt`.
Binary + project DB not committed (no redistribution).

---

## TL;DR — the container is SOLVED and the blob is DECRYPTED

`APP.BIN` = **single‑DES‑CBC( ZIP( deflate(member files) ) ) ‖ 4‑byte footer**, and
the DES key is **all‑zero** (the cipher class ships with an empty `m_optKey`).
Decrypting `body = APP.BIN[:-4]` with DES‑CBC, key `00·8`, IV `00·8` yields a
**valid 90‑entry ZIP** (verified: `PK\x03\x04` at offset 0, central directory +
EOCD present, `zipfile` opens it). The model‑template tree (`default/userdata`)
lives in the ZIP member **`devices.srs`** (148 012 B), which is itself a further
encrypted/compressed inner blob (Shannon 7.999) — that is the one remaining layer
for Lanes A/B, now isolated to a single 148 KB file.

Confidence: **HIGH (RECOVERED end‑to‑end)** — not inferred. The decrypt was
executed and the ZIP parses.

---

## 0. Offset correction (load‑bearing)

Prior docs cite the APP.BIN **file offset `0x66c6e8`**. That is wrong — it is the
resource **data RVA region**, not a file offset. Parsing the PE `.rsrc` directory:

| field | value |
|---|---|
| resource | `DATA / "APP.BIN"` (lang id 1033) |
| data **RVA** | `0x66dae8` |
| `.rsrc` section | VA `0x64e000`, raw `0x619400`, vsize `0xab6e8` |
| **true file offset** | **`0x638ee8`** = `0x619400 + (0x66dae8 − 0x64e000)` |
| size | `571596` (`0x8b8cc`) — matches |

Carving at the old `0x66c6e8` gives a different sha256 (wrong bytes). Use
`ghidra/appbin_extract.py` (PE‑parses, writes `/tmp/APP.BIN`,
`sha256 5c79c4ab…657c9a`).

---

## 1. Entropy map — uniform cipher, no cleartext header/footer in the resource

`ghidra/appbin_entropy.py` over the raw 571 596‑byte blob:

- **Whole‑blob Shannon = 7.9997 b/B.** Sliding window (1024/512): every window
  7.76–7.86; **0 windows below 7.0**. 64‑byte head/tail windows all ~5.6–5.9
  (the 64‑byte ceiling), i.e. uniformly high **from byte 0 to the end** — there
  is **no cleartext header and no cleartext footer inside the resource**.
- **chi‑square vs uniform = 239** (df 255), all **256 byte values present**;
  histogram flat (most common `0xfb`×2376 vs expected 2233). ⇒ statistically
  indistinguishable from random = a cipher stream.
- **No ECB tell:** 0 duplicate aligned blocks at 16/32/64 B (one stray 8‑B
  collision, expected by birthday); **0 unaligned 16‑B repeats** in 571 580
  positions. ⇒ a chaining mode (CBC), not ECB; no repeating structure / no
  length fields / no small magic.
- The scattered `78 9c` / `1f 8b` / `PK` byte pairs in the raw blob are
  **coincidental** (2‑byte hits at random density); no valid stream at any of
  them. The single‑byte‑XOR‑then‑inflate hypothesis stays **falsified** (the real
  transform is DES‑CBC, multi‑byte).

So the entropy says **one cipher over the whole blob** — which is exactly DES‑CBC
over `blob[:-4]` (the 4‑byte footer is the only non‑ciphertext, and it too looks
random because it is the trailer the loader discards before decrypt).

---

## 2. Container structure (RECOVERED from the mount pipeline)

Mount driver **`FUN_00530ae0`** (the wx `OnInit`) — decompiled:

1. registers `wxMemoryFSHandler` + `wxInternetFSHandler`, then loads the resource
   (`FUN_00532270`: `FindResourceW(NULL,"APP.BIN","DATA")` → `LoadResource` →
   `LockResource` → `SizeofResource`) and **appends the whole blob** into a
   `wxMemoryBuffer` via `FUN_004d2510(0, ptr, size, 1)` (a
   `wxMemoryBuffer::AppendData` clone: `{at, src, count, mult}`).
2. **`FUN_004d2a10` strips the LAST 4 BYTES.** Disasm at `0x00530e98` proves the
   args: `len=used`, `param_3 = used − min(used,4)`, `param_4 = min(used,4)=4`;
   inside, `iVar2 = base + ((used − (used−4)) − 4) = base + 0`, copying
   `used − 4` bytes. ⇒ keep `blob[0 : len−4]`, **discard the trailing 4 bytes**.
   `body = 571592 B = 0x8b8c8 = 8 × 71449` → **8‑byte block aligned** (the DES
   block constraint, foreshadowing the cipher).
3. builds an in‑memory **`XFSVirtual`** (`new`, vtable `0x0098b5a8`; wrapped in
   `std::_Ref_count<XFSVirtual>` by `FUN_00532640`). The file set is a
   **`std::_Tree<unsigned int>`** (the mount loop and the archive parser both
   iterate `_Tree_unchecked_const_iterator<…unsigned int…>`); each file node is
   `{ptr, ?, size}` and the per‑file copy is again `FUN_004d2510(0, ptr, size,1)`
   (seen in `XFSVirtual` slot 2 `FUN_0052fa90` / slot 3 `FUN_0052faf0`).
4. the archive is parsed by the app's own **`archive::des`** class:
   `piVar10 = FUN_00427e70()` installs `archive::des::vftable @ 0x00970ef8` and a
   `"UTF‑8"` charset field; then `(**(vtbl+8))()` (= slot 2 `FUN_004151a0`) runs
   the **decrypt‑then‑parse** and returns a bool. On success the vtable is swapped
   to **`archive::zip::vftable @ 0x00970f08`** (`FUN_00427f10`) for ZIP member
   enumeration.

### wx filesystem format
`XFSVirtual` is a custom subclass of `wxFileSystemHandler` (RTTI
`.?AVXFS@@/.?AVXFSVirtual@@/.?AVXFSGeneral@@`) — **not** stock
`wxArchiveFSHandler`. It indexes members in a `std::_Tree<unsigned int>` keyed by
a hash of the slash path (`default/userdata`, `translations/current`,
`app.ini`, `splash.png`, …); `wxMemoryFSHandler`/`wxInternetFSHandler` are
registered alongside for `memory:`/`http:` URLs. The *archive* under it is a
plain **ZIP** (the `archive::zip` reader = a wxZip/minizip clone using the
statically‑linked zlib `inflate` `FUN_00794130` via `wxZlibInputStream`
`FUN_006d1dc0`).

---

## 3. The cipher — single DES‑CBC, zero key (RECOVERED)

`archive::des` read path (`FUN_00415070` → `FUN_00456e20`):

- **`FUN_00456e20` = DES‑CBC decrypt.** Asserts `len & 7 == 0` (8‑byte blocks);
  builds the subkey schedule **3×** (`FUN_00455050` ×3 → DES‑EDE3 shape, a
  24‑byte key area `obj[2]=0x18`); per‑block it XORs with the previous ciphertext
  word pair (`local_330/local_32c`) → **CBC**, runs `FUN_004554b0` (the DES round
  fn), then feeds the ciphertext forward. PKCS‑style pad strip in the caller:
  `pad = 8 − (len & 7)`.
- **`FUN_004554b0` = textbook DES block fn:** the initial‑permutation delta‑swaps
  `0x0f0f0f0f`, `0xffff`, `0x33333333`, `0x00ff00ff`, `0xaaaaaaaa`; 16 Feistel
  rounds; 8 SP‑boxes at `0x009713b0..0x00971ab0` (256 B each, **runtime‑built** —
  zero in the file image, the usual `des_init`).
- **`FUN_00455050` = DES key schedule** (PC‑1/PC‑2 with the `0x0f0f0f0f`/
  `0x10101010` deltas and the standard rotation schedule: shift‑1 at rounds
  {0,1,8,15}, else shift‑2).

**The key is all‑zero.** `archive::des`'s ctor (`FUN_00427e70`) leaves the key
field empty (`m_optKey` empty); no caller threads a key in. Empirically (and the
proof), **DES‑CBC(key=`00·8`, IV=`00·8`) of `body` decrypts to a valid ZIP.**
Because DES ignores key parity (LSB of each byte), `00·8` and `01·8` give the
identical (zero) effective key — both produce the same plaintext. The 3‑schedule
EDE3 structure with three equal zero keys ≡ single DES.

---

## 4. Validation oracle + the decrypt (for Lanes A/B)

`scripts/appbin_oracle.py` provides the model + an oracle:

- `load_appbin()` → 571 596 B blob; `body()` → `blob[:-4]` (the DES‑CBC input,
  8‑aligned); `footer()` → the 4 trailing bytes (`b3 1b 43 f9`, role = discarded
  trailer; **not** a CRC/adler of the body).
- `looks_like_plaintext(buf)` → `(ok, reasons)`. Scores `PK\x03\x04` at offset 0
  (STRONG), `PK\x01\x02`/`PK\x05\x06`, the key strings
  (`default/userdata/functions/command/keyword/functor/waste/index/codes/shift/
  app.ini`), zlib headers, and a first‑64 KiB entropy drop. Raw blob → SCORE 0;
  the correct decrypt → SCORE 165.
- `try_3des_cbc(key, iv)` convenience (pycryptodome).

**Reproduce the decrypt:**
```python
from Crypto.Cipher import DES
ct = open('/tmp/APP.BIN','rb').read()[:-4]        # 571592 B, 8-aligned
pt = DES.new(b'\x00'*8, DES.MODE_CBC, b'\x00'*8).decrypt(ct)
# pt[:4] == b'PK\x03\x04'  -> a valid 90-entry ZIP
open('/tmp/APP.dec.zip','wb').write(pt)
```

### What's inside (90 entries)
`app.ini` (cleartext — cloud endpoints `wasteinkcounter.com:23457`, upgrades DB
`printhelp.info/.../upgrades.zip`, `printerpotty.com/upgrades.xml`),
`devices.srs` (**148 012 B — the model/device template DB; the VFS
`default/userdata` tree source**), 14 locale `*/app.mo`, ~70 Epson nozzle/colour
`patterns/*.bin`, UI PNGs/ICO.

### The inner layer is the SAME scheme — chain fully solved
`devices.srs` is **recursively the identical container**:
`DES‑CBC(zero key, zero IV)( ZIP ) ‖ 4‑byte footer`. Strip its 4‑byte trailer
(148 012 − 4 = 148 008 = 8 × 18 501, 8‑aligned), DES‑CBC‑decrypt with the zero
key → `PK\x03\x04` again → an inner ZIP with a **single member `devices.xml`**
(2 549 646 B, plaintext UTF‑8 XML):

```python
from Crypto.Cipher import DES
import zipfile, io
srs = zipfile.ZipFile('/tmp/APP.dec.zip').read('devices.srs')
pt  = DES.new(b'\x00'*8, DES.MODE_CBC, b'\x00'*8).decrypt(srs[:-4])  # PK\x03\x04
xml = zipfile.ZipFile(io.BytesIO(pt)).read('devices.xml')           # 2.5 MB XML
```

`devices.xml` head: `<?xml version="1.0" encoding="UTF-8"?><data version="5000000"><records><printer …>`.
Token counts confirm the full template surface: `waste`×739, `keyword`×683,
`command`×80, `<index`×75, `functor`×24, `functions`×15, `codes`, `shift`,
`default`×27, plus **`Canon`×41 / `G6000`×4**. (No literal `G6020` — consistent
with G6020 being a `G6000`‑family entry; that mapping is a Lane A/B data task, not
a container question.) **The Canon `idx/op/cmd`, the `command.index/codes/shift`
keystream, `keyword.*`, and the `functor` index are now plaintext, key‑free,
capture‑free, offline.**

---

## 5. Confidence + residuals

- **HIGH (RECOVERED, executed):** APP.BIN = DES‑CBC(zero key, zero IV)(ZIP) ‖
  4‑byte footer; true file offset `0x638ee8`; the ZIP opens with 90 members; the
  cipher classes are `archive::des`/`archive::zip`; the DES round/keysched/IP
  constants are standard DES; the strip removes 4 trailing bytes; body is
  8‑aligned.
- **MEDIUM (open, isolated):** the `devices.srs` inner format (the actual
  template tree). Now a single‑file offline problem; the oracle’s key‑string
  cribs apply directly to its expected plaintext.
- **Note:** this *supersedes* the "APP.BIN cipher not yet lifted" residual in
  `wicreset-template-source.md` §3/§5 and corrects its file offset; it does not
  touch the wire‑protocol / capture docs.
