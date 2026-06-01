# CANON-SR5 cipher derivation + G6020 waste:common enciphered clear (Lane A)

**Date:** 2026-06-01 · **Scope:** pure derivation — no WICReset key spent, no
device touched. Builds the tested reference encoder
`scripts/canon_sr5_cipher.py` (+ `tests/test_canon_sr5_cipher.py`) and computes
the enciphered on-wire bytes for the G6020 `waste:common` clear.

This supersedes the "RUNTIME-ONLY / hard wall" claim in
`wicreset-g6020-reset-template.md` §5: the substitution tables and keyword
were recovered on 2026-06-01 from the **decrypted** template DB
`/tmp/appbin_out/devices.xml` (decryptor `scripts/appbin_decrypt.py`). The
cipher *algorithm* was already recovered statically (`ghidra/
wicreset_template_cipher.py`, raw decompiles `/tmp/pp-helpers.txt` FUN_004e76c0
/ FUN_004e72b0, `/tmp/pp-corechain.txt` FUN_004e8410); this lane joins the two.

---

## TL;DR

- **functor for the G6000-series method=3 path = functor 3** (the envelope
  cipher). RECOVERED: `G6000 series ... <method>3</method>`
  (`devices.xml:43549`) selects `<encoders>` method #3, whose block is
  `<handler>0x03</handler><functor>0x03</functor>` (`devices.xml:43690-43691`).
- **The functor-3 envelope self-check passes byte-exact**: the 16 fixed
  MSVC-rand bytes (seed `0x12345678`) =
  `e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f`.
- **The cipher round-trips**: `decrypt(encrypt(x)) == x` for functor 2 and for
  the functor-3 envelope+cipher (proven across synthetic and devices.xml-backed
  inputs in the pytest).
- **Enciphered waste:common (template-default keyword `4D B6 AB 00`)** — the two
  `set_command` frames (prefix `85 00 00`) carrying `10 07 7C` and `0D 00 00`:
  - `10 07 7C` → `f3 0d 61 e7 bb bc 64 31 a7 0b a9 22 95 fb e6 1b a0 00 e1 c9 ce a3`
  - `0D 00 00` → `10 4e 0a 87 71 01 7c 48 06 06 bd a2 a8 c4 df 42 ba 06 08 6e 7c 3d`
  (22 bytes each = 20-byte envelope + 2 tail bytes of the 6-byte app frame.)
- **A live keyword changes every output byte** (device binding). Symbolic live
  keyword `11 22 33 44`:
  - `10 07 7C` → `bd 36 25 94 fa a4 43 39 1e 71 46 39 90 05 42 ab 7c 7b f3 e8 23 ea`
  - `0D 00 00` → `65 78 b7 f9 20 18 0a 8e 70 70 7a d0 6a a5 7c bc f9 81 4d 7e a2 b6`

> **Confidence on the exact ciphertext bytes: MEDIUM.** The envelope, table
> literals, functor selection, keyword binding, and round-trip are HIGH
> (decompiled + parsed verbatim). The *exact* keystream-indexing micro-details
> (the i↔perm[i] position map and the per-position shift fold) are implemented
> faithfully to the FUN_004e76c0 decompile but have **not** been validated
> against a real keyed capture. Until a live/captured frame confirms them, treat
> the literal ciphertext as derivation, not gospel; the **structure, length,
> envelope, and keyword-sensitivity are solid.**

---

## 1. Where the data lives (the "CANON-SR5" naming)

The task calls this spec CANON-SR5. In `devices.xml` the elements
`<CANON-SR5>` and `<CANON-SR6>` (`43439-43495`) carry only localized
service-mode **help text** (press resume/cancel 5× vs 6×). The actual
maintenance spec — `<commands>`, `<printers>`, `<resolution>`, `<encoders>`,
`<functions>/<waste>` — is the **`<CANON-IPL>` block (`43497-43958`)**, which is
exactly the prefix set (`0x81/0x82/0x85`), the G-series printer table, and the
cipher tables the task describes. The encoder parses `<CANON-IPL>`.

### Commands / prefixes (`devices.xml:43503-43509`, RECOVERED)

| command | action | prefix (verbatim) | line |
|---|---|---|---|
| set_session | set | `0x81 0x00 0x00 0x03` | 43504 |
| get_version | get | `0x8A 0x0000000 0x00` | 43505 |
| get_keyword | get | `0x82 0x0000000 0x00` | 43506 |
| get_command | get | `0x86 0x0000000 0x00` | 43507 |
| set_command | set | `0x85 0x0000000 0x00` | 43508 |

The literal `0x0000000` is a 7-nibble zero token; the wire serialises it as one
`0x00` byte (the encoder treats every token as one byte, so set_command ⇒
`85 00 00`). This matches set_session's explicit 4-byte `81 00 00 03`.

### Printer → method (`devices.xml:43549`, RECOVERED)

`<device>G6000 series<min>0x00</min><max>9000</max><method>3</method>
<support>query;waste:common</support></device>` → **method=3**.

---

## 2. The cipher tables (RECOVERED, parsed not hard-coded)

`scripts/canon_sr5_cipher.py` parses these straight from `devices.xml`; nothing
is transcribed by hand. Shapes (asserted in the test):

- `<resolution>` = **one** `<method>`: `handler=0x01 functor=0x02`
  (`43553-43599`). Carries the **default device keyword**:
  - `keyword.codes = 4D 49 53 00` ("MIS") (`43558`)
  - `keyword.index = 03 01 00 02` (`43559`)
  - `keyword.value = 4D B6 AB 00` (`43560`) ← the template-default keyword
- `<encoders>` = **three** `<method>` blocks indexed by the printer's `method`:
  - method 1: `handler=0x01 functor=0x02` (`43601-43644`)
  - method 2: `handler=0x02 functor=0x02` (`43645-43688`)
  - **method 3: `handler=0x03 functor=0x03`** (`43689-43731`) ← **G6000 series**
- Each method's `<command>` holds:
  - `command.index` = **5 arrays × 20 bytes** (permutations) — method-3 first
    array `0F 03 13 0C 01 08 00 12 07 05 10 04 0E 06 02 11 0B 0D 09 0A`
    (`43698`)
  - `command.codes` = **7 arrays × 20 bytes** (keystream material) — method-3
    first array `09 12 DD 1D 41 13 63 6B 44 2A 17 BD AF D2 88 31 3B 71 BB E5`
    (`43705`)
  - `command.shift` = **3 operator-VM arrays** of `<action><sign><data>` steps;
    signs ∈ `{= + - * / % & | ^}` (method-3: `= & = =` / `& = % =` / `& = = =`)

### waste rows (`devices.xml:43805-43810`, RECOVERED)

```
away   : [10 07 7C] [0D 05 00]   (43805)
black  : [10 07 7C] [0D 03 00]   (43806)
common : [10 07 7C] [0D 00 00]   (43807)  <-- THE G6020 clear (support=waste:common)
platen : [10 07 7C] [0D 01 00]   (43808)
color  : [10 07 7C] [0D 04 00]   (43809)
home   : [10 07 7C] [0D 06 00]   (43810)
normal : [10 07 7C] [15]         (43814, functions.query)
```

---

## 3. The algorithm (RECOVERED from the decompiles)

### functor selector

`service_send_buffer` reads `<functor>` and dispatches: **1** = identity copy,
**2** = `functor_implementation` (FUN_004e76c0) directly, **3** =
`functor_encryption_003` (FUN_004e8410) = envelope then functor 2. The G6000
method-3 encoder block carries `<functor>0x03</functor>`, so the **G6020
waste:common path uses functor 3.**

### functor 3 — envelope (FUN_004e8410), HIGH

Prepends a deterministic 20-byte preamble, then runs functor 2 over
(envelope ‖ frame[4:]):

```
[00 12 01 frame[3]] + lcg16()
lcg16() = ESI=ESI*0x343fd+0x269ec3 (seed 0x12345678); emit (ESI>>16)&0xff ×16
        = e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f   (CONSTANT, self-check OK)
```

### functor 2 — functor_implementation (FUN_004e76c0), RECOVERED algorithm

A symmetric, **message-seeded XOR keystream** with an index permutation
(`param_5` swaps the i↔perm[i] roles for encrypt vs decrypt):

```
seed   = big-endian fold of the buffer bytes (local_d4), mixed with the bound keyword
idx    = command.index[ seed % 5 ]      # which permutation array
codes  = command.codes[ seed % 7 ]      # which keystream array
shift  = operator-VM( seed, command.shift[ seed % 3 ] )    # '= + - * / % & | ^'
ks[i]  = (seed >> (shift & 0x1f)) ^ codes[i % 20]
encrypt:  cipher[perm[i]] = msg[i] ^ ks[i]
decrypt:  msg[i]          = cipher[perm[i]] ^ ks[i]
```

The position map `perm` is the recovered index permutation rendered as a true
bijection over the buffer length, which makes encrypt/decrypt exact inverses
(round-trip test). The decompile's `local_d4 = local_d4*0x100 + msg[i]` fold,
the `% len()` array selection (lines 286/290/292), the operator cascade
(`local_ad = 0x3d, 0x2b, 0x2d, …`), the `(local_d4 >> (… & 0x1f)) ^ codes`
keystream byte (lines 522-526), and the `param_5` swap (lines 527-532) are all
reproduced.

### keyword binding — functor_initialization (FUN_004e72b0), RECOVERED

```
for i in 0..4:  bound[i] = keyword.codes[ keyword.index[i] ] ^ device_keyword[ keyword.index[i] ]
```

(verbatim from `/tmp/pp-cipher2.txt:198-252`: the device keyword byte is fetched
at offset `uVar6 = keyword.index[i]`). With the template-default keyword
`4D B6 AB 00`, the bound encoder keyword is `00 FF 00 F8`. A **live** keyword
(read over `get_keyword` in service mode) changes `bound`, which re-seeds the
keystream and changes **every** enciphered byte — this is the device binding the
v5103 plaintext path was missing.

---

## 4. Computed enciphered waste:common (functor 3, method 3)

App frame = `set_command` prefix (`85 00 00`) ‖ command bytes. Cipher input =
`envelope3(frame) ‖ frame[4:]` (22 bytes). Outputs:

### (i) template-default keyword `4D B6 AB 00` → bound `00 FF 00 F8`

```
10 07 7C : f3 0d 61 e7 bb bc 64 31 a7 0b a9 22 95 fb e6 1b a0 00 e1 c9 ce a3
0D 00 00 : 10 4e 0a 87 71 01 7c 48 06 06 bd a2 a8 c4 df 42 ba 06 08 6e 7c 3d
```

### (ii) symbolic live keyword `11 22 33 44` → bound `44 6B 5C 60`

```
10 07 7C : bd 36 25 94 fa a4 43 39 1e 71 46 39 90 05 42 ab 7c 7b f3 e8 23 ea
0D 00 00 : 65 78 b7 f9 20 18 0a 8e 70 70 7a d0 6a a5 7c bc f9 81 4d 7e a2 b6
```

Every byte differs between (i) and (ii): the keystream is fully keyword-bound.
Regenerate with `python3 scripts/canon_sr5_cipher.py [path/to/devices.xml]`.

---

## 5. Reference encoder + tests

- `scripts/canon_sr5_cipher.py` — parser (`parse_devices_xml`,
  `parse_waste_rows`), `lcg16`/`envelope3` (functor 3), `apply_shift_program`
  (operator-VM), `bind_keyword` (functor_initialization), `functor2_transform`,
  `functor3_encrypt/decrypt`, `encode_command`, `encode_waste_common`. Run as a
  script for the self-check + the enciphered bytes above.
- `tests/test_canon_sr5_cipher.py` — 20 tests:
  - envelope == `e9 3f 0d a1 …` and layout `[00 12 01 cmd]`;
  - functor-2 round-trip on synthetic + parametrized inputs;
  - functor-3 envelope+cipher round-trip on the real waste:common frames;
  - parsed-literal assertions (prefixes, keyword codes/index/value, method-3 =
    functor 3, 5×20 index / 7×20 codes / 3 shift arrays, the method-3 first
    index/codes arrays, every waste row's clear bytes);
  - default-vs-live keyword changes every enciphered byte.
  - devices.xml-backed tests `skip` cleanly when the DB is absent (CI
    portability); the pure-algorithm tests always run.

`uv run pytest tests/test_canon_sr5_cipher.py -q` → **20 passed**. Ruff clean;
mypy clean on the script (note: repo CI runs mypy on `src` only, not `scripts`).

---

## 6. Confidence + residual unknowns

- **HIGH (parsed/decompiled verbatim):** functor selection; method-3 ⇒
  functor 3; the envelope and its 16 fixed bytes; all table literals and their
  shapes; the waste row clear bytes; the keyword-binding formula; the
  operator-VM op set; round-trip as an algebraic property.
- **MEDIUM (faithful to the decompile, not yet capture-validated):** the *exact*
  ciphertext bytes — specifically the i↔perm[i] position map rendered as a
  bijection and the precise per-position shift fold. The keystream *shape* and
  keyword sensitivity are solid; the literal bytes need a keyed capture to
  promote to HIGH.
- **NOT in scope here (still runtime/live):** the real device keyword (read via
  `get_keyword` in service mode) — the symbolic `11 22 33 44` is illustrative.

**Gates untouched:** this lane is derivation only. The existing safety gates in
`src/canon_megatank/ops.py` (UUID, `status==verified-captured`, EEPROM dump,
write budget, lockfile) remain intact; the derived sequence stays dry-run/gated
until a live validation promotes it.
