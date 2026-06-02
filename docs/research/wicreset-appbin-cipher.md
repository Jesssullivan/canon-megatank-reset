# WICReset `APP.BIN` container cipher — fully reversed & decrypted (offline)

**Date:** 2026-06-01 · **Binary:** `printerpotty.exe`
(`sha256 a199447db7d9237d95b11456db6e6d9898ab2eb2cae7918acaa1c700a564b3e8`,
7,484,416 B). Static RE on **neo** against the read-only Ghidra 12.0.2 project
`project-full/wicreset-pp-full` (open-by-name pattern). Decryptor:
`scripts/appbin_decrypt.py`. Confidence: **HIGH** — the cipher was recovered from
decompilation *and* the blob was actually decrypted offline to plaintext XML
(`devices.xml`) containing every expected key string.

---

## TL;DR

`APP.BIN` is **3DES (DES-EDE3) in CBC mode, with an all-zero 24-byte key and
all-zero 8-byte IV**, wrapping a **ZIP**. The decrypted ZIP holds the localized
`*.mo` files, nozzle/colour `patterns/`, and a second encrypted blob
`devices.srs`. `devices.srs` is the **same archive::des layer again** (3DES-EDE3-CBC,
zero key/IV) → ZIP → **`devices.xml`** (2,549,646 B plaintext), the model/spec
database. No real secret: the "encryption" is obfuscation only (empty key/IV).

```
APP.BIN (571,596 B, entropy 8.00, DATA/APP.BIN resource @ file 0x638ee8)
  └─ strip last 4 bytes (footer)                       FUN_004d2a10
  └─ 3DES-EDE3-CBC decrypt, key=00*24, iv=00*8         FUN_00457030 + FUN_004554b0
  └─ strip PKCS#5 pad (last byte = count)              FUN_00457250
  = ZIP (90 entries: app.ini, *.mo, patterns/*, devices.srs, ...)
        └─ devices.srs (148,012 B): SAME 3 steps again
           = ZIP (1 entry)
                 └─ devices.xml (2.5 MB plaintext model DB)
```

> NOTE ON THE RESOURCE OFFSET: the prior lane recorded the APP.BIN file offset as
> `0x66c6e8` — that is **wrong** (it is the resource RVA-derived value, and reading
> there yields adjacent `.reloc`/string data). The **true file offset is `0x638ee8`**
> (resource RVA `0x66dae8`, `.rsrc` va `0x64e000`/raw `0x619400`), size 571,596,
> confirmed by walking the PE resource directory. The decryptor uses `0x638ee8`.

---

## 1. The chain LoadResource → mount (what each function actually does)

`FUN_00530ae0` (wx app-init / VFS mount) does, in order:

```c
FindResourceW(NULL,L"APP.BIN",L"DATA"); LoadResource; LockResource; SizeofResource;
FUN_004d2510(...);           // copy locked resource bytes into a wxString/std::string buffer
FUN_004d2a10(buf,out,len-4,4)// **NOT a decryptor** — wxString::Mid; returns buf[0 : len-4]
                             //   (trims the 4-byte footer)
... XFSVirtual::vftable (0x0098b5a8) is wrapped in a std::shared_ptr (FUN_00532640) ...
piVar10 = FUN_00427e70();    // construct an `archive::des` object (vtable 0x00970ef8)
local_29d = (*(piVar10+8))(out_list, appbin_buf);   // vtable[2] = FUN_004151a0 = DESERIALIZE
```

Two earlier-misread functions, now corrected:

| addr | prior guess | **actual** |
|---|---|---|
| `FUN_004d2a10` | "strips header/footer + decrypt" | **`wxString::Mid` substring** — only trims the last 4 bytes; *no* byte loop, *no* XOR |
| `FUN_004d2510` | "copy" | correct — `std::string::append/assign` (memcpy) |
| `FUN_00532640` | "mount driver" | `std::shared_ptr<XFSVirtual>` ctor (refcount only) |
| `FUN_00427e70` | — | **`archive::des` constructor** (sets vtable + `"UTF-8"`, zeroes key/iv wxStrings) |

**The decryption is the `archive::des::deserialize` virtual method, not the strip.**

## 2. archive::des::deserialize = `FUN_004151a0` (vtable[2] @ 0x00970ef8)

```c
FUN_00414fa0(this+8, this+0x14);   // copy this.key (off +8) and this.iv (off +0x14) into a temp
FUN_00457250(buf);                 //   -> 3DES-CBC decrypt + PKCS#5 unpad (writes into temp)
FUN_00415870(out_list, buf);       // parse the now-plaintext bytes (a ZIP) into the tree
```

`this.key` (object +8) and `this.iv` (object +0x14) are the DES key/IV **wxString**
fields. Both construction sites leave them **empty**:

- `FUN_00427e70` (ctor): zeroes them.
- `FUN_00433300` (`Core::StartupTryDatabaseCommon`, the other caller) builds the
  des object on the stack with `local_34=0; uStack_30=0; uStack_2c=0` (24-byte key
  region) and `pvStack_28=0; local_24=0; local_20=0` (IV region) — i.e. **empty**.

So **key = "" and IV = ""** → after the workspace `memset(0)` the effective DES key
is 24 zero bytes and the IV is 8 zero bytes. (RECOVERED: empty key/IV is the
literal program behavior; this is obfuscation, not real key protection.)

## 3. The cipher core — `FUN_00457030` (3DES-EDE3-CBC) + `FUN_004554b0` (DES)

`FUN_00457030(this=des_temp, data=ptr, len)`:

- `if ((len & 7) != 0) return;` → **8-byte block cipher** (DES block = 64 bit).
- Copies **8 bytes** of `this.iv` into `local_330/local_32c` (the CBC feedback seed).
- Copies **0x18 = 24 bytes** of `this.key` into `local_328` → **three 8-byte DES keys**.
- `FUN_00455050(&schedule_k1, key+0); FUN_00455050(&schedule_k2, key+8);
  FUN_00455050(&schedule_k3, key+16);` → **3 DES key schedules** = **EDE3 / Triple-DES**.
- Per 8-byte block: `FUN_004554b0(block)` (DES with the combined 48-round schedule:
  the function indexes subkeys `param_1[0x40 .. 0x5f]` = E-D-E across k1,k2,k3),
  then XOR with the previous **ciphertext** block → **CBC** (`local_330 = saved ct`).

`FUN_004554b0` is verbatim **OpenSSL/libdes `DES_encrypt`**: the IP/FP delta-swap
permutations (`0xaaaaaaaa, 0x33333333, 0x0f0f0f0f, 0x00ff00ff, 0xffff` masks), the
`>>4 | <<0x1c` E-expansion rotate, 6-bit S-box indexing (`& 0x3f`), and the 8
`des_SPtrans` tables:

| S-box (`des_SPtrans[i]`) | .rdata addr | first 4 dwords |
|---|---|---|
| SP0 | `0x009713b0` | `01010400 00000000 00010000 01010404` |
| SP1 | `0x009714b0` | `00000208 08020200 00000000 08020008` |
| SP2 | `0x009715b0` | `00000100 02080100 02080000 42000100` |
| SP3 | `0x009716b0` | `00200000 04200002 04000802 00000000` |
| SP4 | `0x009717b0` | `80108020 80008000 00008000 00108020` |
| SP5 | `0x009718b0` | `00802001 00002081 00002081 00000080` |
| SP6 | `0x009719b0` | `20000010 20400000 00004000 20404010` |
| SP7 | `0x00971ab0` | `10001040 00001000 00040000 10041040` |

`FUN_00455050` is **`DES_set_key`** (PC-1/PC-2 via the `des_skb` tables at
`0x00971330` / `0x00971370`, the `0x0f0f0f0f`/`0x10101010` masks, and the
16-iteration 1/2 left-shift schedule). These tables are bit-identical to stock
OpenSSL DES, so a standard 3DES-EDE-CBC implementation reproduces it exactly — no
custom S-boxes.

## 4. Post-decrypt trimming — `FUN_00457250`

After `FUN_00457030` decrypts in place, `FUN_00457250` reads the **last byte** as a
count and strips that many trailing bytes — i.e. **PKCS#5/CMS padding removal**
(`pad = pt[-1]; pt = pt[:-pad]`). For APP.BIN the pad is `04 04 04 04`; for
`devices.srs` it is `06 06 06 06 06 06`. The plaintext then begins with
`50 4B 03 04` (`PK\x03\x04`) — a **ZIP**, not a bare zlib stream.

> The earlier "expect a `0x78` zlib header / single-byte-XOR-then-inflate"
> hypothesis was correctly FALSIFIED: the container is a **ZIP** (deflate lives
> inside the ZIP's own local file headers), reached **after** the 3DES layer, not a
> raw `inflate()` of the resource. The statically-linked `inflate` (`FUN_00794130`)
> is used by the ZIP reader to decompress individual ZIP members (e.g. the
> deflate-stored `devices.xml`), not on APP.BIN directly.

---

## 5. Key material — RECOVERED

| item | value | source |
|---|---|---|
| cipher | **DES-EDE3-CBC (3DES)**, 8-byte block | `FUN_00457030` (`&7` gate, 3× `FUN_00455050`, CBC feedback) |
| DES impl | **OpenSSL/libdes** (stock S-boxes/skb) | `FUN_004554b0` / `FUN_00455050` + tables `0x009713b0..0x00971ab0`, `0x00971330/70` |
| **key** | **`00 00 … 00` (24 bytes)** | empty `archive::des.key` wxString at both ctor sites (`FUN_00427e70`, `FUN_00433300`) |
| **IV** | **`00 00 … 00` (8 bytes)** | empty `archive::des.iv` wxString |
| footer | **last 4 bytes stripped** before decrypt | `FUN_004d2a10(buf, len-4, 4)` |
| padding | **PKCS#5** (last byte = count) stripped after decrypt | `FUN_00457250` |
| container | **ZIP** (then a nested ZIP for `devices.srs`) | decrypted bytes start `PK\x03\x04` |

No `.rdata` key constants and no `CryptDeriveKey`/`CryptDecrypt` — consistent with
the prior finding. The "key source" is simply **the empty string**.

---

## 6. Runnable decryptor

`scripts/appbin_decrypt.py` (self-contained pure-Python DES; no external deps):

```python
KEY = b"\x00"*24; IV = b"\x00"*8
def decrypt_layer(blob):
    body = blob[:-4]                              # FUN_004d2a10 footer trim
    pt = ede3_cbc_decrypt(body, KEY[0:8], KEY[8:16], KEY[16:24], IV)   # 3DES-EDE3-CBC
    pad = pt[-1]
    if 0 < pad <= 8 and pt[-pad:] == bytes([pad])*pad: pt = pt[:-pad]  # PKCS#5
    return pt                                     # -> a ZIP
# APP.BIN @ file 0x638ee8, len 571596 -> ZIP -> devices.srs -> decrypt_layer again -> devices.xml
```

`python3 scripts/appbin_decrypt.py /path/to/printerpotty.exe` →
`/tmp/appbin_out/devices.xml`. **Verified:** outer ZIP = 90 entries; inner
`devices.xml` = 2,549,646 B and contains `functions`, `command`, `keyword`,
`functor`, `waste`, `default`, `userdata`, `G6000 series`.

---

## 7. G6020 row (RECOVERED from the decrypted `devices.xml`)

There is **no literal `G6020`** — the G6020 is the NA name for the **"Canon G6000
Series"** (`model = "G6000 series"`, `specs = "CANON-SR5"`,
`class = "canon.printer.std.standard"`, `brand = "canon"`).

It sits in the shared **CANON-SR5 / G-MegaTank class** (covers G1000–G7000):

```xml
<device>G6000 series<min>0x00</min><max>9000</max><method>3</method>
        <support>query;waste:common</support></device>
```

Class command framing & template tables for this class:

```xml
<commands>
  <set_session><action>set</action><prefix>0x81 0x00 0x00 0x03</prefix></set_session>
  <get_version><action>get</action><prefix>0x8A 0x0000000 0x00</prefix></get_version>
  <get_keyword><action>get</action><prefix>0x82 0x0000000 0x00</prefix></get_keyword>
  <get_command><action>get</action><prefix>0x86 0x0000000 0x00</prefix></get_command>
  <set_command><action>set</action><prefix>0x85 0x0000000 0x00</prefix></set_command>
</commands>

<functor>0x02</functor>     <!-- matches PrinterCanonSTD::functor_encryption_003 (prior lane) -->

<keyword>
  <codes>0x4D 0x49 0x53 0x00</codes>          <!-- "MIS\0" -->
  <index>0x03 0x01 0x00 0x02</index>
  <value>0x4D 0xB6 0xAB 0x00</value>
</keyword>

<command>
  <index>   <!-- 5 permutation rounds, 20 entries each -->
    <array>0x01 0x0B 0x07 0x0F 0x06 0x0A 0x00 0x11 0x13 0x08 0x03 0x0E 0x12 0x0D 0x04 0x02 0x09 0x10 0x0C 0x05</array>
    <array>0x03 0x07 0x00 0x01 0x08 0x09 0x05 0x0A 0x06 0x0F 0x10 0x12 0x0E 0x02 0x11 0x13 0x04 0x0D 0x0C 0x0B</array>
    <array>0x07 0x10 0x02 0x0B 0x05 0x01 0x0A 0x0C 0x0F 0x06 0x00 0x03 0x0E 0x13 0x12 0x11 0x0D 0x09 0x08 0x04</array>
    <array>0x05 0x09 0x01 0x08 0x04 0x06 0x0F 0x0D 0x13 0x0B 0x03 0x0E 0x11 0x12 0x10 0x0C 0x0A 0x07 0x00 0x02</array>
    <array>0x08 0x0B 0x03 0x12 0x00 0x0D 0x04 0x0A 0x02 0x07 0x09 0x0F 0x10 0x13 0x11 0x01 0x0E 0x06 0x0C 0x05</array>
  </index>
  <codes>   <!-- substitution rows used by the functor (first rows shown) -->
    <array>0x23 0x58 0x0C 0x10 0x5A 0xA8 0x36 0x55 0x60 0x02 0x3E 0x4C 0x60 0x17 0x1B 0x0B 0x63 0xB8 0x2B 0xDC</array>
    ... (7 rows total) ...
  </codes>
</command>

<functions>   <!-- absorber/waste function map: code -> special -> indexes -->
  <function><code>0x00</code><special>0x04 0x66</special><indexes>         </indexes></function>
  <function><code>0x01</code><special>0x05 0x22</special><indexes>0x07     </indexes></function>
  <function><code>0x03</code><special>0x0F 0x01</special><indexes>0x03     </indexes></function>
  <function><code>0x07</code><special>0x04 0x0F</special><indexes>0x01 0x03</indexes></function>
  ... (0x00 .. 0x11+, the per-counter table) ...
</functions>
```

The `functions` table (code→`special`→`indexes`) is the per-counter **waste/absorber**
map the Canon reset (`PrinterCanonSTD::clearCounters`) iterates; the `command`
index/codes permutation + `functor 0x02` + keyword (`MIS`) are the inputs to the
local encryption functor that builds the `[cmd][arg][value]` SEND frame. These were
the "runtime template data" flagged as the only residual unknown in
`wicreset-printerpotty-static-re.md` — now **recovered offline** in full.

Full plaintext DB extracted to `/tmp/appbin_out/devices.xml`
(`scripts/appbin_decrypt.py`). The complete CANON-SR5 class block (statuses,
commands, all device rows G1000–G7000, command/keyword tables, full `functions`
0x00–0x1x table) is in that file around byte offset ~2,429,000–2,448,000.

---

## 8. Confidence / provenance

- **RECOVERED (decompiled + executed):** cipher = 3DES-EDE3-CBC, stock OpenSSL DES;
  key = 24 zero bytes, IV = 8 zero bytes; 4-byte footer strip; PKCS#5 unpad;
  two nested ZIP layers; `devices.xml` plaintext. Proven by actually decrypting
  APP.BIN → ZIP → devices.srs → ZIP → devices.xml containing all expected keys.
- **RECOVERED (from plaintext):** the G6000-series (G6020) maps to CANON-SR5 /
  `canon.printer.std.standard`, method 3, `waste:common`; functor `0x02`; keyword
  `MIS`; the command index/codes/shift and functions tables above.
- **INFERRED:** that the empty key/IV is intentional obfuscation (the program path
  is unambiguous; "why" is interpretation).
