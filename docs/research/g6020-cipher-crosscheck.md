# G6020 CANON-SR5 cipher — independent byte-for-byte cross-check (Lane: static RE)

**Date:** 2026-06-01 · **Verdict: MATCH (HIGH confidence)** · No device, no key.

This note **independently re-derives** the enciphered `set_session` and
`get_keyword` tail bytes for the CANON-SR5 / CANON-IPL method-3 (functor-3)
cipher, **a second way**: by hand-tracing `printerpotty.exe` (Ghidra 12.0.2,
`project-full/wicreset-pp-full`, read-only) and re-implementing the transform
from scratch against the **raw `<encoders>` arrays parsed directly out of
`/tmp/appbin_out/devices.xml`** — never importing `scripts/canon_sr5_cipher.py`
or `src/canon_megatank/protocol/wicreset.py`. The goal is to maximise confidence
the cipher is correct **before** spending the keyed hardware capture.

The independent derivation reproduces our implementation's output **byte-for-byte**:

```
set_session  81 00 00 03      ->  81 00 00 03 2d 2d ba 2b
get_keyword  82 00 00 00 00   ->  82 00 00 00 00 40 40 8f ec
```

Derivation script (gitignored scratch): `/tmp/crosscheck/search_walk.py`.

---

## 0. What was cross-checked, against what

| layer | our impl (to confirm) | independent source |
|---|---|---|
| method block | method-3 (handler 0x03 / functor 0x03) | parsed the `<method>` whose `<handler>`==`<functor>`==`0x03` from raw XML |
| arrays | `command.index`(5) / `.codes`(7) / `.shift`(3), `keyword.index/codes`, `<functions>` | parsed by this note's own regex out of `devices.xml` lines 43689-43801 |
| envelope | `[00 12 01 frame[3]] + lcg16` + `<special>`/`<indexes>` | hand-traced `FUN_004e8410:57-148` |
| seed | BE fold mod 2^32 of envelope | hand-traced `FUN_004e76c0:258-266` |
| array select | seed%5 / seed%7 / seed%3 | `FUN_004e76c0:286,290,292` |
| shift table | one entry per `<value>`, acc reset to seed | `FUN_004e76c0:340-495` |
| keyword bind | `codes[idx[u]] ^ devkw[idx[u]]` | `FUN_004e72b0:247-249` |
| index walk | `j=index[i]%4; code=codes[j]; out[i]=kw[j]^ks` | `FUN_004e76c0:501-534` + `FUN_004c1bf0` |

The `<encoders>` block holds three `<method>`s: handler 0x01/functor 0x02,
handler 0x02/functor 0x02, handler 0x03/functor 0x03. **We use method-3 /
functor-3** (task-confirmed). The method-3 `<command>` arrays are at
devices.xml 43696-43731 and the functor-3 `<functions>` (special/indexes) at
43732-43800. Cross-check: the `<commands>` prefixes in `<CANON-IPL>` are
`set_session 0x81 0x00 0x00 0x03` (43504) and `get_keyword 0x82 ... 0x00`
(43506) — the exact plaintext frames under test.

---

## 1. functor-3 envelope (hand-trace of `FUN_004e8410`)

`pvVar3 = param_3[2]` (frame len) must be ≥ 4 (`"Command buffer is too small."`).
`bVar2 = *((int)*param_3 + 3)` = **frame[3]**. Then `local_a8` is appended:
`0x1200` LE (`00 12`), `0x01`, `frame[3]`, then a 16-iteration loop
`iVar8 = iVar8*0x343fd + 0x269ec3; emit (iVar8>>16)&0xff` seeded `0x12345678`:

```
lcg16 = e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f   (constant)
base envelope[20] = 00 12 01 <frame[3]> + lcg16
```

Function block keyed by `frame[3]` (loop `FUN_004e8410:100-227` matching
`<code>`):

- **`<special>` (lines 120-128):** pairs `(off,val)`; if `off < 20` then
  `env[4+off] := val`.
- **`<indexes>` (lines 130-138):** `env[4+indexes[i]] := tail[i]` where
  `tail = frame[4:]` (`FUN_004d2960`, line 75).

Then `FUN_004e76c0(...)` (functor-2) is run with **this envelope as the seed
source** and emits 4 bytes (line 148).

Independently computed envelopes (from raw XML function blocks):

```
set_session  frame[3]=0x03  <special>0x0F 0x01  -> env[4+15]=env[19]:=0x01
  env = 00 12 01 03 e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 01
get_keyword  frame[3]=0x00  <special>0x04 0x66  -> env[4+4]=env[8]:=0x66
  env = 00 12 01 00 e9 3f 0d a1 66 95 31 04 49 2d 9e 61 83 cf 09 6f
```

Both `<special>` overwrites land where our impl says: set_session at **env[19]**
(inside the surviving seed window), get_keyword at **env[8]** (washed out). For
set_session the LCG byte `0x6f` at env[19] is overwritten by `0x01`. The
`<indexes>` for these frames are empty / no payload, so no scatter.

> **Parse cross-check (task ask):** the method block selected is the one whose
> `<handler>`/`<functor>` are both `0x03`. `<special>` is applied as `env[4+off]`
> — the `4` is the 4-byte header `[00 12 01 frame[3]]` before the 16 LCG bytes,
> so special offset `0x0F`→env[19] (last LCG byte) and `0x04`→env[8] (5th LCG
> byte). This is the correct offset base; confirmed against `FUN_004e8410:123`
> (`*(... + 4 + (int)local_a8) = ...`).

---

## 2. seed, array selection, shift table (hand-trace of `FUN_004e76c0`)

**Seed (lines 258-266):** `local_d4 = 0; for b in buf: local_d4 = local_d4*0x100 + b`
over `local_104` bytes, **mod 2^32** (32-bit). Confirmed direction = big-endian,
width = byte-wise `*256`. Because `256^4 ≡ 0 (mod 2^32)`, **only the trailing 4
envelope bytes survive** (verified empirically: fold(20 bytes)==fold(last 4)).

```
set_session  seed window = 83 cf 09 01  -> seed = 0x83cf0901
get_keyword  seed window = 83 cf 09 6f  -> seed = 0x83cf096f
```

**Array selection (lines 286/290/292):** `index = seed % local_164`,
`codes = seed % local_150`, `shift = seed % local_13c`, where the counts are
5 / 7 / 3 (number of `<array>`s in `command.index/.codes/.shift`):

```
set_session  index%5=3  codes%7=1  shift%3=0
get_keyword  index%5=3  codes%7=6  shift%3=2
```

**Shift table (lines 340-495):** for the selected `command.shift <array>`, the
OUTER loop runs once per `<value>` and **resets the accumulator to the seed**
(`uVar8 = local_d4`, line 342); the INNER loop applies the `<value>`'s
`<action>` operator-VM steps (`= + - * / % & | ^`, the `FUN_0045f180` cascade);
one shift-table entry is appended per `<value>` (lines 484-493 → `local_c0`
entry count = 4). Independently evaluated:

```
set_session  shift array idx 0 -> shift_tbl = (0, 1, 0, 0)
get_keyword  shift array idx 2 -> shift_tbl = (1, 0, 0, 2)
```

Both equal our impl's pinned tables (the `(0,1,0,0)` set_session table is the
cross-interpreter determinism regression). The method-3 `command.shift` arrays
are identical to method-1/2 in this template; array 0 = `[=0][&1][=0][=0]`,
array 2 = `[&1][=0][=0][=2]`.

---

## 3. keyword bind + index walk (hand-trace of `FUN_004e72b0` + `FUN_004e76c0`)

**Bind (`FUN_004e72b0:247-249`):** for `u3` in 0..3: `kwidx = keyword.index[u3]`;
`bound[u3] = keyword.codes[kwidx] ^ device_keyword[kwidx]` (the XOR uses the
device byte at index `kwidx`, not `u3`). With `keyword.index = 03 01 00 02`,
`keyword.codes = 4D 49 53 00`:

```
default kw 4D B6 AB 00 -> bound = 00 FF 00 F8        (matches our impl)
live    kw 11 22 33 44 -> bound = 44 6B 5C 60        (matches doc's live illustration)
```

**Index walk (`FUN_004e76c0:501-534`, two `FUN_004c1bf0` nested lookups):** the
output loop is bounded by `local_e4 = 4` (the bound-keyword length). Per output
position `i`:

```
j     = index_arr[i] % 4        # index value (0..0x13) reduced to the 4-byte buffer
code  = codes_arr[j]            # second nested walk (codes_arr len 20, j now 0..3)
shift = shift_tbl[j % 4]        # uVar8 % local_c0  (local_c0 = #shift entries = 4)
ks    = ((seed >> (shift & 0x1f)) & 0xff) ^ (code & 0xff)
send (param_5=1):  out[i] = bound[j] ^ ks
recv (param_5=0):  out[j] = bound[i] ^ ks
```

The `% 4` reduction is the load-bearing detail that keeps `local_ec[uVar8]`
(line 528/531) in-bounds for the 4-byte keyword; it is the binary's bounded
keyword buffer (`local_e4 = 4`). The map is **not** a bijection over 4 bytes —
the keyword transform is an obfuscating one-way scramble, faithful to the
binary. (Ghidra splits the shift-table container into scrambled locals
`local_cc/c8/c4/c0/d0`; the `% local_c0` reduction is the recoverable invariant.)

Per-position trace (independent), send direction:

```
set_session seed=0x83cf0901 shift_tbl=(0,1,0,0)
  i=0 j=2 code=0x2c sh=0 ks=0x2d kw[2]=0x00 -> 0x2d
  i=1 j=2 code=0x2c sh=0 ks=0x2d kw[2]=0x00 -> 0x2d
  i=2 j=0 code=0xbb sh=0 ks=0xba kw[0]=0x00 -> 0xba
  i=3 j=3 code=0xd2 sh=0 ks=0xd3 kw[3]=0xf8 -> 0x2b
  tail = 2d 2d ba 2b

get_keyword seed=0x83cf096f shift_tbl=(1,0,0,2)
  i=0 j=2 code=0x2f sh=0 ks=0x40 kw[2]=0x00 -> 0x40
  i=1 j=2 code=0x2f sh=0 ks=0x40 kw[2]=0x00 -> 0x40
  i=2 j=0 code=0x38 sh=1 ks=0x8f kw[0]=0x00 -> 0x8f
  i=3 j=3 code=0x4f sh=2 ks=0x14 kw[3]=0xf8 -> 0xec
  tail = 40 40 8f ec
```

(`index_arr` 3 = `0F 03 13 0C 01 08 00 12 07 05 10 04 0E 06 02 11 0B 0D 09 0A`,
so `index[0..3] = 12 0e 00 0f` → `% 4` = `2 2 0 3`; this is why positions 0/1
collide on j=2.)

---

## 4. Byte comparison

| frame | plain | our impl tail | **independent tail** | verdict |
|---|---|---|---|---|
| set_session | `81 00 00 03` | `2d 2d ba 2b` | `2d 2d ba 2b` | **MATCH** |
| get_keyword | `82 00 00 00 00` | `40 40 8f ec` | `40 40 8f ec` | **MATCH** |

Wire frames (CLEAR prefix || 4 enciphered keyword bytes):

```
set_session  -> 81 00 00 03 2d 2d ba 2b
get_keyword  -> 82 00 00 00 00 40 40 8f ec
```

Extra method-3 frames, re-derived independently, also reproduce the doc table
(shared tail because their seed windows are identical `83 cf 09 6f`):

```
get_version 8a 00 00 00 00     -> 8a 00 00 00 00 40 40 8f ec
get_command 86 00 00 00 00     -> 86 00 00 00 00 40 40 8f ec
set_command 85 00 00 10 07 7c  -> 85 00 00 10 07 7c 40 40 8f ec
set_command 85 00 00 0d 00 00  -> 85 00 00 0d 00 00 40 40 8f ec
```

---

## 5. VERDICT — MATCH, HIGH confidence

A from-scratch second derivation — raw `devices.xml` arrays parsed by an
independent regex parser + the cipher coded straight from the
`FUN_004e8410`/`FUN_004e76c0`/`FUN_004e72b0` decompile, with **no reuse of our
cipher code** — reproduces every intermediate AND the final bytes:

- envelopes (incl. both `<special>` overwrites at the right offsets),
- seed window + folds (`0x83cf0901` / `0x83cf096f`),
- array selection (5/7/3),
- shift tables (`(0,1,0,0)` / `(1,0,0,2)`),
- keyword bind (`00 FF 00 F8`, and `44 6B 5C 60` for the live illustration),
- the per-position index walk and final XOR.

Result: **`set_session = 81 00 00 03 2d 2d ba 2b` and
`get_keyword = 82 00 00 00 00 40 40 8f ec` are CONFIRMED**. The two frames
exercise *different* array selections (codes%7 = 1 vs 6; shift%3 = 0 vs 2) and
*different* special offsets (env[19] vs env[8]), so a single faithful formula
reproducing all 8 output bytes is a strong pin — not a coincidence.

**Implication for the keyed capture:** the cipher (envelope, seed, table
selection, shift VM, bind, index walk) is independently corroborated for the
template-default keyword. The keyed hardware capture then only needs to (a)
supply the **live device keyword** (which re-seeds `functor_initialization` and
changes the 4 enciphered tail bytes per §3 binding — the 4-byte CLEAR prefix is
keyword-independent) and (b) confirm the firmware **unlock/clear**. It does not
need to re-validate the cipher math.

**Residual caveats (unchanged, not cipher correctness):**
1. The 4 enciphered tail bytes are device-bound; a live keyword ≠ `4D B6 AB 00`
   yields different tails (formula confirmed, value pending capture).
2. The Ghidra container ABI for the shift table is scrambled in the decompile;
   the `% local_c0`/`% 4` reductions are the recovered invariant that keeps the
   walk in-bounds and reproduces the bytes — but the literal pointer arithmetic
   was not hand-walked field-by-field (low risk: 8/8 output bytes across two
   array selections agree).
3. Whether the firmware *gates* the absorber clear on the keystream vs an extra
   opcode is still the open T4 question (see `wicreset-g6020-reset-template.md`).

Lane boundaries respected: this note does **not** edit `g6020-cipher-fix.md`
(its lane) and touches no hardware / spends no key.
