# WICReset `printerpotty.exe` — G6020 reset frame template + on-wire encryption (static RE)

**Date:** 2026-06-01 · **Binary:** `printerpotty.exe` (PE32, 7.48 MB, the real
extracted app), `sha256 a199447db7d9237d95b11456db6e6d9898ab2eb2cae7918acaa1c700a564b3e8`.
**Tooling:** PyGhidra against **Ghidra 12.0.2** (`/nix/store/a2rxrq8yxw2cahv9j4gbn9d0m8y2d8sq-ghidra-12.0.2/lib/ghidra`),
venv `.ghidra-work/.pgvenv12`, JDK 21 (zulu). Saved DB `project-full/wicreset-pp-full`
(39 096 functions) opened **read-only by name** (`open_program(..., analyze=False)`).
Tracked scripts (new this pass): `ghidra/wicreset_template_extract.py`,
`ghidra/wicreset_template_cipher.py`. Reused: `ghidra/wicreset_decomp.py`.
Raw decompiles (gitignored): `/tmp/pp-corechain.txt`, `/tmp/pp-helpers.txt`,
`/tmp/pp-cipher2.txt`, `/tmp/pp-template-extract.txt`.

This builds on `wicreset-printerpotty-static-re.md` (the call-graph map: reset
button → `ActionCanonDeviceClearCounters` 0x0043fbc0 → `clearCounters` 0x004ecae0
→ `service_perform_command_common` 0x004ec120 → `service_send_buffer` 0x004ea540
→ functor → SEND `FUN_0052ce40` → `DeviceIoControl(0x220038)`) and on the v5103
service-tool docs. **It does not restate those; it extracts the literal frame
construction + the encryption transform that the prior map left as "runtime
template data".**

---

## TL;DR — what was recovered, and the one hard wall

1. **The encryption transform is fully recovered (HIGH).** WICReset's Canon
   "encryption functor" is a **selectable** per-model transform with index 1/2/3,
   dispatched in `service_send_buffer`:
   - **functor 1** → identity / pass-through copy (no transform),
   - **functor 2** → `functor_implementation` (FUN_004e76c0) directly — a
     **symmetric table-driven XOR keystream cipher**,
   - **functor 3** → `functor_encryption_003` (FUN_004e8410) — a **20-byte
     deterministic envelope** prepended, then the same XOR keystream cipher.

   The envelope (functor 3) is byte-exact and **constant** except for one byte:
   `00 12 01 [cmd] <16 fixed LCG bytes>`, the 16 bytes being a fixed
   MSVC-`rand()` sequence seeded at `0x12345678` =
   `e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f`.

2. **The XOR keystream is device-/session-bound — NOT computable from the .exe
   (HARD WALL, by design).** The cipher's substitution tables
   (`command.index` / `command.codes` / `command.shift`) and the per-session
   encoder seed (`keyword.index`/`keyword.codes` XOR a **device keyword** read
   live via `commands.get_keyword`) are **runtime template + device data**.
   There are **no `G6000`/`G6020` strings and no inline command-byte/JSON tables**
   in the image (re-confirmed). So the literal G6020 absorber idx/op/cmd and the
   keystream tables are runtime-resolved; this doc gives their exact *shape* and
   *data-flow*, and the plaintext frame, but the encrypted on-wire bytes can only
   be finalized with the runtime tables (capture or template dump).

3. **The plaintext reset frame for the absorber is recovered by analogy +
   structure (MEDIUM-HIGH for the plaintext, the template idx/op being the one
   runtime unknown).** `clearCounters` loops `functions.waste` and issues a
   `commands.set_command` per waste counter; the app-frame shape is the same
   `[cmd][arg_hi][arg_lo][payload]` the v5103 tool uses, payload
   `00 03 <flags> 03 <idx>` (main absorber idx `0x07`).

4. **The v5103-vs-WICReset delta that explains "WICReset clears, v5103 ACKs but
   doesn't" is identified (MEDIUM):** WICReset runs a **full session sequence**
   (`set_session` START → `get_keyword` → per-counter `set_command` →
   `get_command` verify), and its frames are **encrypted with the device-keyword
   keystream**, whereas the captured v5103 path emitted a **single plaintext
   `0x85` frame** with the runtime preamble bytes left at `00 00`. The firmware
   gate is almost certainly the **session keyword handshake + correct keystream**,
   not a different absorber opcode.

---

## 1. Model → reset-params table — how the frame is built (RECOVERED structure; idx/op is runtime data)

`PrinterCanonSTD::clearCounters` (FUN_004ecae0) is the entry. It does **not**
hold any G6020 constant; it walks a runtime template node and re-dispatches:

```c
// FUN_004ecae0  (verbatim-trimmed)
FUN_004edad0(local_cc, "functions.waste");        // <- template node: list of waste counters
local_b8 = count;                                  // number of waste-counter entries
for (each entry) {
    FUN_00422380("waste");
    piVar7 = FUN_00522ac0("label");                // counter label (e.g. main/platen) - template data
    cVar5  = FUN_004e9d50(..., entry);             // action_is_permitted (local capability gate)
    if (cVar5 == 1) {
        // build a LoggerString "PrinterCanonSTD::clearCounters" with constants 7,7 (group/idx hints)
        ...
        cVar5 = FUN_004ec120(local_ac, entry, 0);  // service_perform_command_common -> the SEND
        if (cVar5 != 1) abort;
    }
}
```

`service_perform_command_common` (FUN_004ec120) then pulls **`"commands"`** and
**`"functions"`** sub-nodes from the template, iterates the matching command list
(`label` == requested), and for each calls down into the set-command path that
ends at `service_send_buffer`. So the absorber **command bytes are template rows**
keyed by dotted paths:

| dotted-path key | role | recovered addr |
|---|---|---|
| `functions.waste` | list of waste counters to clear (main absorber, platen, …) | str @ 0x0097a494 |
| `commands.set_command` | the per-counter WRITE command template (the reset frame) | str @ 0x009869b4 |
| `commands.get_command` | the verify READ template | str @ 0x0098699c |
| `commands.set_session` | open-maintenance-session frame | str @ 0x009868cc |
| `commands.get_keyword` | read device keyword (cipher seed) | str @ 0x0098695c |
| `commands.get_version` | read firmware version (device-cache) | str @ 0x0098691c |
| `command.index` / `command.codes` / `command.shift` | **cipher substitution tables** | 0x0098663c / 0x00986664 / 0x00986654 |
| `keyword.index` / `keyword.codes` | **session-encoder seed tables** | 0x00986534 / 0x0098656c |
| `functor` | the per-command **encryption-functor index (1/2/3)** | str @ 0x00986ae8 |
| `label` / `model.value` / `model.label` | counter/model identity | 0x009870cc / 0x0096efcc / 0x0097dc3c |

> **RECOVERED:** the frame is assembled from these template rows; the WRITE is
> `commands.set_command`, applied once per `functions.waste` entry, encrypted via
> the row's `functor` index. **RUNTIME-ONLY:** the concrete numeric idx/op/cmd
> bytes for the G6020 entry (they are rows in the downloaded/decrypted model
> template tree — `FUN_00522ac0` is a dotted-path lookup into that tree — not
> static `.data`). Per `functions.waste`, WICReset clears **each** waste counter
> the template lists (typically main absorber + platen pad; the strings
> *"Most printers have at least one extra counter that usually represents a
> platen pad."* @ 0x00988108 and the multi-entry loop confirm ≥1, often 2).

**Cross-check vs v5103 (label-confirmed):** v5103's group-7 absorber payload is
`00 03 <flags> 03 <idx>` with Platen `idx=0x00`, Main `idx=0x07`, framed
`85 00 00 00 03 01 03 07`. WICReset's `commands.set_command` row is the **same
app-frame shape** (`[cmd][arg][payload]`); the loop over `functions.waste` is the
analog of clearing each idx. The numeric idx values are not in WICReset's `.exe`
(template), but the v5103 table (Main `0x07`, Platen `0x00`) is the confirmed
reference to test against.

---

## 2. The encryption transform — `functor_encryption_003` (FUN_004e8410) + `functor_implementation` (FUN_004e76c0)

### 2a. Functor selection (in `service_send_buffer`, FUN_004ea540) — RECOVERED, HIGH

```c
iVar4 = FUN_00522ac0("functor");          // read the per-command functor index from template
cVar2 = FUN_004c31a0(...); idx = local_cc; // resolve to int (1/2/3)
if (idx == 1) { ... }                       // -> error path / identity copy
else if (idx == 2) FUN_004e76c0(...)        // functor_implementation directly (cipher only)
else if (idx == 3) FUN_004e8410(...)        // functor_encryption_003 (envelope + cipher)
else  "Could not send printer command. Ecnryption functor call error."
```

So **which** transform applies to the absorber frame is the template's `functor`
field for `commands.set_command`. (Read path mirrors it: functor 2/3 →
`functor_implementation` for decrypt; the cipher is symmetric.)

### 2b. The envelope — `functor_encryption_003` (FUN_004e8410) — RECOVERED, HIGH

Disassembly 0x4e84e5..0x4e85a6 (verbatim, `wicreset_template_extract.py`). It
builds a header buffer `local_a8` via `FUN_004d2510(dst, src, n, 1)` byte
appends, then concatenates the plaintext tail and runs `functor_implementation`:

```text
BL = plaintext[3]                       ; MOV BL,[EAX+3]  (4th byte of the app frame)
append uint16  0x1200   -> bytes 00 12  ; little-endian, MOV [..],0x1200 ; FUN_004d2510(..,2,1)
append uint8   0x01                     ; MOV byte 0x01   ; FUN_004d2510(..,1,1)
append uint8   BL                       ; MOV byte BL     ; FUN_004d2510(..,1,1)
ESI=0x12345678 ; EDI=0x10               ; loop 16 times:
   ESI = ESI*0x343fd + 0x269ec3         ; IMUL ESI,ESI,0x343fd ; ADD ESI,0x269ec3
   append (ESI>>16)&0xff                ; SHR EAX,0x10 ; MOV byte AL ; FUN_004d2510(..,1,1)
tail = plaintext[4:]                    ; FUN_004d2960(buf, len-4, 4)  (FUN_004ed800 "function")
remap via "indexes"/"special" template arrays, then:
FUN_004e76c0(header_buf, tail_buf, ...) ; functor_implementation = the XOR cipher
```

**The first 20 bytes of the functor-3 plaintext (pre-cipher) are DETERMINISTIC:**

```python
LCG_MUL, LCG_ADD, SEED0 = 0x343fd, 0x269ec3, 0x12345678   # MSVC rand()
def lcg16(seed=SEED0):
    out=[]
    for _ in range(16):
        seed=(seed*LCG_MUL+LCG_ADD)&0xffffffff
        out.append((seed>>16)&0xff)
    return bytes(out)
# header = 00 12 01 <plaintext[3]> + lcg16()
# lcg16() == e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f   (CONSTANT)
def encryption_003_header(frame):           # frame = [cmd][arg_hi][arg_lo][payload..]
    assert len(frame) >= 4                   # else "Command buffer is too small."
    return bytes([0x00,0x12,0x01,frame[3]]) + lcg16()
```

`0x1200` is the envelope tag (likely a length/version word, LE → `00 12`);
`0x01` a sub-tag; `frame[3]` echoes the first payload byte (for the absorber
frame `85 00 00 00 03 01 03 07`, `frame[3]==0x00`). These 16 LCG bytes are a
**fixed nonce/pad**, not random per call — the seed is hard-coded.

### 2c. The cipher — `functor_implementation` (FUN_004e76c0) — RECOVERED algorithm, RUNTIME tables

A symmetric, table-driven XOR keystream cipher (`param_5` selects encrypt vs
decrypt direction; tables identical both ways). Verbatim data-flow:

```c
// seed from the message bytes, big-endian fold:
local_d4 = 0;
for (i=0; i<msglen; i++) local_d4 = local_d4*0x100 + msg[i];

ix    = template "command.index"  (array)    // FUN_0045ee10(...,"command.index",...)
codes = template "command.codes"  (array)    // FUN_0045ee10(...,"command.codes",...)
shift = template "command.shift"  (array)    // FUN_0045ee10(...,"command.shift",...)

// build a shift table by evaluating a tiny per-step operator program:
//   for each shift step, op = FUN_00522ac0("...") then FUN_0045f180 matches one of
//   the operator chars and applies it to (acc, val):
//     '=' set   '+' add  '-' sub  '*' mul  '/' div  '%' mod  '&' and  '|' or  '^' xor
//   (chars: 0x3d 0x2b 0x2d 0x2a 0x2f 0x25 0x26 0x7c 0x5e ; FUN_0045f180 cascade)

// final per-byte transform:
for (i=0; i<msglen; i++) {
    j        = codes_index(i)                 // permutation from codes table
    ksbyte   = (local_d4 >> (shifttable[...] & 0x1f)) ^ low_byte(codes[...])
    out[dir? i : j] = in[dir? j : i] ^ ksbyte // XOR; encode/decode swap i<->j
}
```

So: **output = input XOR keystream**, where keystream[i] is derived by indexing
`command.codes` through `command.index`, shifting the message-seed `local_d4` by a
per-position amount computed by the `command.shift` operator-program. It is a
**stream XOR with a data-dependent (message-seeded) keystream** — reversible,
content-aware, but **entirely parameterized by the three template arrays**.

### 2d. The session keystream seed — `functor_initialization` (FUN_004e72b0) — RECOVERED, the device-binding

Before commands run, `service_perform_command_vector`/session setup calls
`functor_initialization`, which builds the per-session encoder from
`keyword.index`/`keyword.codes` XORed with the **device keyword** (the buffer
returned by `commands.get_keyword` = `execute_get_keyword`):

```c
FUN_004ed5e0(.., "keyword.index"); FUN_004ed5e0(.., "keyword.codes");
for (i=0;i<4;i++)
    out[i] = keyword_codes_table[ keyword_index_table[i] ] ^ device_keyword[i];
// "Keyword index/codes table size is lower than expected." guards.
```

**This is why the keystream is device-bound:** the live `device_keyword` (read
from the printer in service mode) is XORed into the encoder. No keyword → no
correct keystream → frames the firmware rejects. The keyword is **not** in the
`.exe`; it is read at runtime via the USB RECV.

---

## 3. The full ordered SEND sequence for a G6020 absorber clear

Reconstructed from `clearCounters` → `service_perform_command_common`/`_vector`
→ `execute_set_session`/`execute_get_keyword`/`execute_set_command`/`execute_get_command`,
each landing at `service_send_buffer` → SEND `FUN_0052ce40`
(`DeviceIoControl(handle, 0x220038, frame, len, NULL,0,…)`).

| # | step | static source | plaintext app frame | on-wire (encrypted) |
|---|---|---|---|---|
| 0 | open USB pipe (`USBPipe::do_open`) | `FUN_0052ce40` lazy-open `CreateFileW(\\?\usb…)` | — (no bytes) | — |
| 1 | **set_session START** | `execute_set_session` 0x004eb430 ← `commands.set_session` | template `set_session` frame | functor-encrypted |
| 2 | **get_keyword** (read device keyword) | `execute_get_keyword` ← `commands.get_keyword`; **seeds the cipher** (`functor_initialization`) | template `get_keyword` frame | functor-encrypted; **RECV returns the keyword** |
| 3 | **set_command** (the WRITE that clears) — once **per `functions.waste` entry** (main absorber idx 0x07, platen idx 0x00, …) | `execute_set_command` 0x004ea540 ← `commands.set_command` | `[cmd][arg_hi][arg_lo] 00 03 <flags> 03 <idx>` (analog of v5103 `85 00 00 00 03 01 03 07`) | **functor-encrypted** with the device-keyword keystream |
| 4 | **get_command** verify READ | `execute_get_command` 0x004ea9c0 ← `commands.get_command` | template `get_command` frame | functor-encrypted; RECV = status |
| 5 | (session close / status sweep `statuses`) | `service_perform_command_vector` tail | template status frame(s) | functor-encrypted |

**Plaintext frame for the main absorber (RECOVERED shape; idx from v5103 table):**

```text
app frame (pre-functor):   85 00 00 00 03 01 03 07     # cmd 0x85, arg 0x0000, payload 00 03 01 03 07, idx 0x07
checkbox-checked variant:  85 00 00 00 03 81 03 07
```

**On-wire (post-functor):** if the template's `functor` for `set_command` is **3**,
the cipher input is `00 12 01 00 e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f`
followed by the frame tail, then XOR-masked by the keystream → the final bytes
DeviceIoControl(0x220038) emits. **The exact encrypted bytes cannot be printed
here** because the XOR keystream needs the runtime `command.index/codes/shift`
tables + the live device keyword. Hook recipe (from the prior map): **Frida-hook
`functor_implementation` (0x004e76c0) entry** to capture the plaintext just before
the XOR, or hook the SEND `FUN_0052ce40` `lpInBuffer` for the post-encryption
wire bytes. The deterministic 20-byte envelope above lets you **recognize a
functor-3 frame on the wire** and recover `frame[3]` and the tag even before the
tables are known.

---

## 4. v5103 vs WICReset — the delta that makes WICReset's path actually clear

| aspect | Service Tool v5103 (ACKs, does NOT clear) | WICReset printerpotty (clears) |
|---|---|---|
| transport | `DeviceIoControl(0x220038)` raw frame, no transform | same IOCTL, **but the frame is functor-encrypted** |
| session | optional 6-byte preamble `12 34 00 00 01 ??` (tail byte runtime, **`00` at rest**) | full **`set_session` START + `get_keyword`** handshake |
| keystream | **none** (payload sent verbatim) | **device-keyword-seeded XOR keystream** (`functor_initialization`) |
| absorber write | single plaintext `85 00 00 00 03 01 03 07` | per-`functions.waste` `set_command`, **encrypted** |
| verify | none in the captured path | `get_command` read-back + `statuses` sweep |

**The DELTA (MEDIUM confidence):** the v5103 capture that ACKed-but-didn't-clear
sent the absorber payload **in the clear** with the runtime preamble byte = `0x00`.
WICReset (a) opens a proper service **session** and (b) reads the **device
keyword**, then (c) sends the same logical absorber write **encrypted with the
keyword-derived keystream**. The G6020 firmware gate is therefore most consistent
with **"reject unless the frame is correctly enveloped/keystreamed for the
current session keyword"** — i.e. the missing ingredient in the v5103 path is the
**session-keyword cipher**, not a different absorber opcode or idx. There is **no
evidence of an extra "commit/flush" opcode** in WICReset's path (no such template
key; the EEPROM commit is implicit in the firmware after `set_command`). The most
likely single reason v5103 ACKs but doesn't clear: it sent the **un-enciphered**
frame (and/or skipped the keyword handshake), which the G-series firmware
silently accepts on the bulk pipe but ignores for the gated absorber counter.

---

## 5. Confidence + the precise residual unknowns

- **HIGH (RECOVERED from instructions/data):**
  - functor selection 1/2/3 in `service_send_buffer`;
  - the `functor_encryption_003` envelope layout `00 12 01 [cmd]` + 16 fixed
    MSVC-rand bytes (seed 0x12345678) = `e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83
    cf 09 6f` (disassembly-exact + reproduced in Python);
  - `functor_implementation` is a symmetric, message-seeded **XOR keystream**
    over `command.index/codes/shift` with the operator-VM
    (`= + - * / % & | ^`);
  - `functor_initialization` XORs the **live device keyword** into the encoder
    (the device-binding), seeded by `keyword.index/codes`;
  - the SEND sequence ordering (session → keyword → per-waste set_command →
    get_command), the dotted-path template keys, and the `0x220038` SEND site.
- **MEDIUM-HIGH:** the plaintext absorber app-frame shape
  `85 00 00 00 03 01 03 07` (cmd/arg inherited from the v5103 read-RE; payload
  `00 03 01 03 07` mode-independent and re-confirmed across both tools).
- **MEDIUM:** the v5103-vs-WICReset delta being the session-keyword cipher (vs an
  extra opcode) — inferred from absence of any commit/flush template key + the
  presence of the keyword handshake; confirm with a keyed capture.
- **RUNTIME-ONLY (genuinely NOT in the .exe — a hard wall by design):**
  1. the numeric **G6020 absorber idx/op/cmd** rows (model-template tree, fetched
     /decrypted at runtime; no `G6000`/`G6020` strings, no inline JSON);
  2. the **`command.index/codes/shift` keystream tables** (template data);
  3. the **device keyword** (`commands.get_keyword`, read live from the printer);
  4. which **`functor` index** the G6020 `set_command` row carries (2 vs 3).

  Items 1–4 are exactly the values the **Frida hook on `functor_implementation`
  (0x004e76c0)** or a **keyed usbmon capture** yields — this doc pre-stages that
  capture by giving the deterministic envelope to anchor on and the full
  data-flow to interpret the bytes.

**Lane boundaries respected:** this file does not touch
`wicreset-printerpotty-static-re.md`, `wicreset-wine-linux-rig.md`,
`wicreset-linux-instrumentation.md`, `wicreset-capture-analysis-pipeline.md`, or
`wicreset-linux-capture-RUNBOOK.md`.
