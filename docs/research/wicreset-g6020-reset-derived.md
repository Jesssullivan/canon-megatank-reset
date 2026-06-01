# WICReset G6020 reset — DERIVED template (APP.BIN cleartext)

**Date:** 2026-06-01 · **Status:** `derived-not-yet-validated`
**Source of truth:** the decrypted WICReset model DB `devices.xml`
(`sha256 6031555f143080038431cf963706191a3108bd7c4fec03eeffeb2c8f60d86db3`,
2 549 646 B), recovered offline from `printerpotty.exe` APP.BIN by
`scripts/appbin_decrypt.py` (3DES-EDE3-CBC, zero key/IV → ZIP → `devices.srs` →
ZIP → `devices.xml`). This closes the "runtime-only template" wall that
`wicreset-g6020-reset-template.md` (the static-RE lane) explicitly left open.

This doc is the **join** of two recovered halves:

1. the **cipher / sequence machinery** — fully reverse-engineered in
   `wicreset-g6020-reset-template.md` (functor selection, the functor-3 LCG
   envelope, the symmetric XOR keystream over `command.index/codes/shift`, the
   `functor_initialization` device-keyword XOR, and the ordered
   `set_session → get_keyword → set_command → get_command` SEND sequence); and
2. the **literal G6020 template rows** — recovered HERE from the cleartext
   `devices.xml`, which the static lane could only describe by shape.

Together they make the reset sequence **computable up to the one live input**
(the device keyword, read in service mode via `get_keyword`).

---

## 1. Model resolution — how a G6020 selects this template

`devices.xml` has **no `G6020` literal**: the G6020 is a member of the
**`G6000 series`** family. The printer entry:

```xml
<printer title="Canon G6000 Series" short="G6000 Series" model="G6000 series"
         specs="CANON-SR5" class="canon.printer.std.standard" brand="canon" shown="true"/>
```

`specs="CANON-SR5"` is **only** the service-mode-entry help text (press ON +
resume×5). The actual command template lives in the **`<CANON-IPL>`** spec block
(the single IPL block in the DB), where the family device row is:

```xml
<device>G6000 series<min>0x00</min><max>9000</max><method>3</method><support>query;waste:common</support></device>
```

Two facts drive everything below:

* **`method = 3`** selects the encoder method keyed `<handler>0x03</handler>`,
  which carries **`<functor>0x03</functor>`** — i.e. the G6020 reset frames use
  the **functor-3 LCG-envelope + XOR-keystream** transform (resolving the
  static lane's open "functor 2 vs 3?" question: **it is 3**).
* **`support = query;waste:common`** → the only waste counter the G6000 family
  clears is the **`common`** absorber (no `platen`/`black`/`color`/`away`/`home`
  for this family). The 5B00 main absorber == the `common` waste row.

---

## 2. `<CANON-IPL>` commands (the session frame prefixes) — RECOVERED literal

```xml
<commands>
  <set_session><action>set</action><prefix>0x81 0x00 0x00 0x03</prefix></set_session>
  <get_version><action>get</action><prefix>0x8A 0x0000000 0x00</prefix></get_version>
  <get_keyword><action>get</action><prefix>0x82 0x0000000 0x00</prefix></get_keyword>
  <get_command><action>get</action><prefix>0x86 0x0000000 0x00</prefix></get_command>
  <set_command><action>set</action><prefix>0x85 0x0000000 0x00</prefix></set_command>
</commands>
```

| command | action | prefix bytes |
|---|---|---|
| `set_session` | set | `81 00 00 03` |
| `get_version` | get | `8A 00 00 00 00` (`0x8A`, zero arg) |
| `get_keyword` | get | `82 00 00 00 00` (`0x82`, zero arg) |
| `get_command` | get | `86 00 00 00 00` (`0x86`, zero arg) |
| `set_command` | set | `85 00 00 00 00` (`0x85`, zero arg) |

These are the literal `cmd`/`arg` headers the SEND sequence uses. They confirm
the v5103-RE values (`0x85` send / `0x86` recv) and add the previously
runtime-only `set_session 0x81 …03` and `get_keyword 0x82 …`.

---

## 3. functions.waste — the reset rows (RECOVERED literal)

```xml
<functions>
  <waste>
    <row><commands><command>0x10 0x07 0x7C</command><command>0x0D 0x05 0x00</command></commands><label>away</label></row>
    <row><commands><command>0x10 0x07 0x7C</command><command>0x0D 0x03 0x00</command></commands><label>black</label></row>
    <row><commands><command>0x10 0x07 0x7C</command><command>0x0D 0x00 0x00</command></commands><label>common</label></row>
    <row><commands><command>0x10 0x07 0x7C</command><command>0x0D 0x01 0x00</command></commands><label>platen</label></row>
    <row><commands><command>0x10 0x07 0x7C</command><command>0x0D 0x04 0x00</command></commands><label>color</label></row>
    <row><commands><command>0x10 0x07 0x7C</command><command>0x0D 0x06 0x00</command></commands><label>home</label></row>
  </waste>
  <query>
    <row><commands><command>0x10 0x07 0x7C</command><command>0x15</command></commands><label>normal</label></row>
  </query>
</functions>
```

Each waste row is a **two-command tuple**: a fixed selector `10 07 7C` followed
by a per-region reset operand `0D <region> 00`:

| label | reset operand | applies to G6000? |
|---|---|---|
| away | `0D 05 00` | no |
| black | `0D 03 00` | no |
| **common** | **`0D 00 00`** | **YES** (`support=…waste:common`) |
| platen | `0D 01 00` | no |
| color | `0D 04 00` | no |
| home | `0D 06 00` | no |

> **G6020 reset operand = `0D 00 00`** (the `common` row), gated by the
> `support=query;waste:common` capability string on the G6000 device row. The
> `query;normal` row (`10 07 7C` + `15`) is the read-back / status query.

This is the **template idx/op** the static lane listed as the one runtime
unknown for `clearCounters`'s `functions.waste` loop. For the G6000 family the
loop has exactly one permitted entry: `common`.

> **Note on the v5103 `idx=0x07` "Main" reading.** The v5103 static-RE lane
> derived a `[00 03 flags 03 idx]` payload with main-absorber `idx=0x07`. That is
> the **Service Tool** family's payload shape. WICReset's G6000 template does
> **not** use that 5-byte payload for the absorber — its waste reset is the
> two-command `10 07 7C` / `0D 00 00` tuple above, fed through the functor-3
> cipher. The two tools reach the same counter by different command encodings;
> the WICReset encoding is the one recovered here and is the path that is known
> to clear on G6000-family units.

---

## 4. functor 3 method (`<handler>0x03</handler>`) — cipher tables (RECOVERED literal)

The G6000 `method 3` resolves to this encoder method. All arrays verbatim.

### 4a. keyword (cipher-seed selector)

```xml
<keyword>
  <codes>0x4D 0x49 0x53 0x00</codes>   <!-- "MIS\0" -->
  <index>0x03 0x01 0x00 0x02</index>
</keyword>
```

(The `<resolution>` method also carries `<value>0x4D 0xB6 0xAB 0x00</value>`,
the keyword **resolution value**; the `<encoders>` methods omit `<value>` and
take the live device keyword instead — see §5.)

### 4b. command.index — 5 permutation arrays (×20 bytes)

```
[0] 0F 03 13 0C 01 08 00 12 07 05 10 04 0E 06 02 11 0B 0D 09 0A
[1] 08 12 00 06 0F 04 0B 0E 01 0A 02 13 03 05 11 07 0D 09 10 0C
[2] 04 0B 13 09 07 11 0F 02 0D 00 01 0E 05 03 06 10 08 0A 0C 12
[3] 12 0E 00 0F 07 08 0B 01 13 03 11 02 10 04 0D 09 0C 06 0A 05
[4] 07 05 08 0A 11 03 00 0E 13 12 04 01 09 06 02 0D 0F 0B 0C 10
```

### 4c. command.codes — 7 keystream arrays (×20 bytes)

```
[0] 09 12 DD 1D 41 13 63 6B 44 2A 17 BD AF D2 88 31 3B 71 BB E5
[1] BB 41 2C D2 18 89 77 45 4F 11 05 67 25 D3 7C 4E D4 4A 88 91
[2] 3F 03 26 3D CA 72 89 44 09 E2 B8 20 A9 4E 2B 04 0C 69 6B 25
[3] 68 12 63 7F 8F DE 70 40 38 2F 09 64 81 BB 31 C5 1A 72 6D 3A
[4] CA CC 1D E4 78 1C 1B 7E 7F 14 D5 18 D1 CF 80 7B 02 D3 19 DE
[5] 14 27 22 08 0A 9D A7 CA E8 3A 4B 47 6B 89 95 90 23 6F B2 C7
[6] 38 42 2F 4F 6D 70 9B DD E6 09 05 07 F0 12 A8 17 62 4C 31 95
```

### 4d. command.shift — 3 arrays of `(sign, data)` operator steps

```
[0]  & 1   = 0   = 0   = 0
[1]  & 1   = 1   % 5   = 0
[2]  & 1   = 0   = 0   = 2
```

(sign ∈ `= + - * / % & | ^`; the operator-VM the static lane recovered —
`FUN_0045f180`. These three programs build the per-position shift table that
shifts the message-seed `local_d4` before XOR.)

### 4e. functor index

```
functor = 0x03   →  functor_encryption_003 (FUN_004e8410): 20-byte LCG envelope
                    + functor_implementation XOR keystream (FUN_004e76c0)
```

### 4f. functions code→special→indexes (the absorber/waste op map, functor-3 method)

The `<functions>` table inside the functor-3 method (44 rows, `code` 0x00–0x43,
some sparse). The rows the static lane wanted (verbatim):

```
0x00 -> special 04 66   indexes (none)
0x01 -> special 05 22   indexes 07
0x02 -> special 00 87   indexes (none)
0x03 -> special 0F 01   indexes 03
0x04 -> special 09 A3   indexes 08
0x07 -> special 04 0F   indexes 01 03
0x08 -> special 0B 91   indexes 06 01
0x09 -> special 02 22   indexes 07 0A
0x0D -> special 05 01   indexes 03 04
0x0F -> special 02 02   indexes 01
0x21 -> special 02 12   indexes 08
0x2E -> special 07 82   indexes 08 09
0x43 -> special 0D 2C   indexes 0A
```

(full 44-row table in `devices.xml` lines ~43712–43803; reproduced under the
`functor3_functions` key in the SSOT). These `special`/`indexes` arrays feed the
`functor_encryption_003` remap step (`indexes`/`special` template arrays) before
the XOR cipher, per the static lane's disassembly of `FUN_004e8410`.

---

## 5. The full enciphered set_session → get_keyword → clear sequence (computable parts)

Joining §2–§4 with the cipher machinery from `wicreset-g6020-reset-template.md`:

| # | step | plaintext app frame (pre-functor) | transform | computable now? |
|---|---|---|---|---|
| 1 | **set_session START** | `81 00 00 03` (`commands.set_session` prefix) | functor-3 envelope+XOR | **YES** (no device keyword needed to *send* the open; the keystream seed for step-1 is the static `keyword.codes[keyword.index]` table, no live keyword yet) |
| 2 | **get_keyword** | `82 00 00 00 00` (`commands.get_keyword` prefix) | functor-3 | **YES to send**; the **RECV returns the 4-byte device keyword** → this is the one live input |
| 3 | **set_command** (clear `common` absorber) | the waste-row tuple `10 07 7C` then `0D 00 00`, carried as a `set_command` (`85 …`) payload | functor-3, keystream now **seeded with the device keyword** (`functor_initialization`: `out[i] = keyword_codes[keyword_index[i]] ^ device_keyword[i]`) | **YES once the step-2 keyword byte-string is known** (everything else is the recovered tables) |
| 4 | **get_command** verify | `86 00 00 00 00` (`commands.get_command`); read-back / `query;normal` `10 07 7C`+`15` | functor-3 | YES to send; RECV = status row (`statuses`: `00`=success, `01`=not-ready, `FF`=unsupported) |

### 5a. The functor-3 envelope (deterministic, no device input) — from the static lane

```
header = 00 12 01 <frame[3]> || LCG16
LCG16  = e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f   (MSVC rand, seed 0x12345678; CONSTANT)
```

So a functor-3 frame's first 20 plaintext bytes (pre-XOR) are fixed except
`frame[3]`. For `set_session` (`81 00 00 03`), `frame[3] == 0x03`, so the
envelope head is `00 12 01 03 e9 3f 0d a1 …`.

### 5b. What is now computable end-to-end

Everything **except the 4 live device-keyword bytes** read at step 2:

* the plaintext frames (set_session / get_keyword / set_command / get_command) —
  **from §2 + §3** (recovered literals);
* the functor selection (**3**) — **from §1/§4e**;
* the 20-byte LCG envelope — **from §5a** (constant);
* the XOR keystream tables (`command.index/codes/shift`) — **from §4b–§4d**;
* the keyword selector (`keyword.index/codes` = `MIS\0` / `03 01 00 02`) —
  **from §4a**;
* the keystream-seed combination rule (`functor_initialization`) — from the
  static lane.

The **only** missing input is `device_keyword[0..3]` (the printer's live keyword,
which `functor_initialization` XORs into the encoder for step-3+). It is read by
**step 2's `get_keyword` RECV** — and step 2 is itself now fully enciphered and
sendable from the recovered tables. So the prior "hard wall" (the keyword was
unreadable because `set_session`/`get_keyword` couldn't be enciphered without the
runtime tables) is **removed**: the tables are recovered, so the session can be
opened and the keyword read natively.

---

## 6. Confidence + residual

* **HIGH (recovered literal, reproduced offline):** model resolution
  (`G6000 series` → CANON-IPL → method 3 → handler/functor 3), the command
  prefixes, the `functions.waste` rows (G6000 = `common` = `0D 00 00`), and the
  full functor-3 `command.index/codes/shift` + `keyword.index/codes` + functions
  tables. Source `devices.xml` sha256 matches across the static and dynamic lanes.
* **HIGH (joined from the static lane):** the functor-3 envelope + XOR cipher +
  `functor_initialization` device-keyword binding + SEND ordering.
* **RESIDUAL (the only remaining input):** the **live 4-byte device keyword**
  (`get_keyword` RECV). This is no longer a *static* wall — step-2 is now
  encipherable from the recovered tables, so the keyword is **readable natively**
  by opening the session and issuing the recovered `get_keyword` frame. After
  that read, steps 3–4 are fully determined.
* **Validation gate:** these values are encoded in
  `printers/canon-g6020/maintenance.yaml` under
  `supported.absorber_reset.derived_template`, marked
  `derived-not-yet-validated`. They do **not** promote `absorber_reset.status`
  off `derived-unvalidated`; no write op will fire on these until a
  pads-installed physical-validation run promotes the status (unchanged gate).
