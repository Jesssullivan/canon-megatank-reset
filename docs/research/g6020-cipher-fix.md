# G6020 WICReset cipher fix (B1–B5): byte-faithful functor-2/3 over the 4-byte keyword

Status: DERIVED, NOT-YET-LIVE-VALIDATED (no device, no key). Lane A static-RE.

This note records the decompile-confirmed correction of the CANON-SR5 /
CANON-IPL functor-2/3 cipher in both `scripts/canon_sr5_cipher.py` (reference)
and `src/canon_megatank/protocol/wicreset.py` (package). The prior model XOR'd
the **whole message** and returned a 20-byte blob; the decompile shows the
transform operates on the **4-byte bound keyword** and the functor-3 envelope is
only the **seed**. The wire frame is `prefix(CLEAR) || 4-byte enciphered
keyword`.

## Ground-truth sources

- `FUN_004e76c0` functor_implementation (functor 2) — `/tmp/pp-helpers.txt:127-549`
- `FUN_004e72b0` functor_initialization (keyword bind) — `/tmp/pp-cipher2.txt:131-325`
- `FUN_004e8410` functor_encryption_003 (functor 3) — `/tmp/pp-corechain.txt:1-228`
- `FUN_004ea540` service_send_buffer (buffer wiring) — `/tmp/pp-corechain.txt:736-950`
- `FUN_00449110` / `FUN_004c1bf0` nested table-walk — `/tmp/pp-cipher2.txt:521-615`
- `FUN_0045f180` operator dispatch — `/tmp/pp-cipher2.txt:1-43`
- Decrypted template DB — `/tmp/appbin_out/devices.xml` (`<CANON-IPL>` block)

## Buffer wiring (the decisive fact)

`service_send_buffer` copies its command frame into `local_e8` (the **seed
source**) and an empty output into `local_d8`. For functor 2 it calls
`FUN_004e76c0(&local_e8, &local_d8, …)`:

- `param_1` → `local_10c` (seed source); `local_d4 = Σ local_10c[i]·256^… ` —
  a big-endian fold of the **command/envelope buffer ONLY** (`:258-266`).
- `param_2` → `local_ec`; `functor_initialization` (`FUN_004e72b0`) writes the
  **4-byte bound keyword** into it and sets `local_e4 = 4` (`:244`).
- The output loop (`:501-534`) is bounded by `local_e4 = 4` and emits 4 bytes.

For functor 3, `FUN_004e8410` builds the 20-byte envelope, applies the
`<special>` / `<indexes>` overwrites, then calls functor 2 with that envelope as
the seed source — emitting the same 4 bytes.

## The five fixes

- **B1 — functor 2 transforms the 4-byte bound keyword, output is 4 bytes.**
  Replaced the whole-message XOR with the bounded `len == 4` keyword transform.

- **B2 — seed = big-endian fold of the COMMAND/ENVELOPE buffer ONLY.**
  Dropped the keyword-XOR that used to be mixed into `_message_seed`. The
  keyword enters via `bind_keyword`, not the seed (`seed_fold`). NB: the fold is
  mod 2^32, so over a 20-byte envelope only the **trailing 4 bytes** survive
  (`256^4 ≡ 0`).

- **B3 — functor 3 = envelope-as-seed + `<special>`/`<indexes>` overwrite, emits
  4 bytes; wire = `prefix(CLEAR) || 4 enciphered keyword bytes`.**
  Envelope `[00 12 01 frame[3]] + lcg16`. The function block keyed by
  `frame[3]` is applied to the envelope: `<special>` pairs `(off,val)` →
  `env[4+off]:=val` (`:120-128`), `<indexes>` scatters `frame[4:][i]` →
  `env[4+indexes[i]]` (`:129-138`). Method-3 `<function><code>0x00</code>` has
  `<special>0x04 0x66</special>` ⇒ `env[8]:=0x66` over the `0x96` LCG byte
  (the `envelopeSpecialApplied` step). It is applied faithfully even though
  `env[8]` is washed out of the surviving seed window; the set_session block
  `<code>0x03</code><special>0x0F 0x01</special>` lands in `env[19]` and **does**
  change the seed.

- **B4 — per-byte SHIFT is a TABLE, not a scalar; ONE entry PER `<value>`.**
  Each `command.shift <array>` holds `N` `<value>` operator-VM sub-programs
  (4 for method-3); each `<value>` is itself a multi-`<action>` program.
  `build_shift_table` evaluates each `<value>` from the seed → one shift-table
  entry per `<value>` (`:340-495`), indexed per output position (`:522-526`).
  The prior code flattened the `<value>`s into one program and returned one
  scalar.

- **B5 — array selection `seed % {5,7,3}` + the real index walk with the
  send/recv swap.**
  Index array `seed % 5`, codes `seed % 7`, shift `seed % 3` (`:286-292`).
  Per output position `i`: `j = index[i] % len`, `code = codes[j%20]`,
  `shift = shift_table[j % len]`, `ks = (seed >> (shift & 0x1f)) ^ code`; then
  send (`param_5=1`) `out[i] = kw[j] ^ ks`, recv (`param_5=0`)
  `out[j] = kw[i] ^ ks` (`FUN_00449110`/`FUN_004c1bf0` nested walk, `:501-534`).
  Replaced the prior rank-sort `_bijection`. For a 4-byte keyword the 20-element
  index reduced mod 4 is NOT a bijection — the keyword transform is an
  obfuscating scramble, not an involution; this is faithful to the binary.

`bind_keyword` (`bound[i] = keyword.codes[index[i]] ^ device_kw[index[i]]`,
`FUN_004e72b0:247-249`) was already faithful and is unchanged.

## Recovered command.shift `<value>` sub-programs (devices.xml ground truth)

```
array[0]: [= 0] [& 1] [= 0] [= 0]
array[1]: [& 1] [= 1] [% 5] [= 0]
array[2]: [& 1] [= 0] [= 0] [= 2]
```

The SSOT `maintenance.yaml` had `array[0]` mis-transcribed as `[& 1] [= 0] …`;
corrected to match devices.xml (this changed only the set_session ciphertext,
since the waste/read frames select `array[2]`).

## The ONE TRUE shift-table semantics (decompile loop structure)

`FUN_004e76c0` builds the shift table with TWO nested loops over the selected
`command.shift <array>` (selected by `local_dc = local_d4 % local_150`,
`:292`, i.e. `seed % 3`):

- **OUTER loop** `:340-495`, `local_128` iterations (= the number of `<value>`
  sub-programs in the array). At the TOP of each iteration `uVar8 = local_d4`
  (`:342`) — the accumulator is **reset to the message seed per `<value>`**.
  After the inner loop, the final `uVar8` is appended to the shift-table
  container `local_cc` (`:484-492`), and `local_c0` (the entry count) is
  incremented by one (`:493`). So **exactly one shift-table entry is produced
  per `<value>`**.
- **INNER loop** `:348-476`, `local_114` iterations (= the number of `<action>`
  steps in that `<value>`). Each step dispatches an operator (`:407-468`,
  `=,+,-,*,/,%,&,|,^`) and carries the accumulator forward (`uVar10 = uVar8`,
  `:475`). So each `<value>` is a **multi-action operator-VM program**.

Answering the RE question precisely: the binary iterates `command.shift` as
**(a) one shift value per `<value>` sub-program** (each a multi-action program),
NOT (b) one per `<action>`. For the method-3 `command.shift` the selected array
has **4 `<value>`s → 4 shift-table entries**, in document order; the per-`<value>`
accumulator **is** reset to the message seed `local_d4` each time (`:342`). The
output keystream then indexes this table per position at `:522-526`.

(In the method-3 data every `<value>` happens to be single-`<action>`, so (a)
and (b) coincide *numerically* — but only if document order is preserved. The
two are genuinely different for any multi-action `<value>`, and the package
mirror previously implemented (b).)

## Determinism root cause + fix (the cross-host `ba` vs `3b` bug)

Probe `wny3i12yy` recorded the enciphered `set_session` frame diverging by
interpreter — neo CPython 3.13 → `81 00 00 03 2d 2d ba 2b`, mbp-13 CPython 3.14
→ `81 00 00 03 2d 2d 3b 2b` (byte i=2, `ba` vs `3b`, differ by `0x81`).
`get_keyword` was unaffected. The two variants trace to **two different shift
tables for the same seed `0x83cf0901`** (array idx 0): neo
`shift_tbl = (0, 1, 0, 0)`, mbp-13 `(1, 0, 0, 0)`.

Root cause (TWO intertwined): (1) the package mirror's SSOT loader used the
WRONG **(b)** semantics — one entry per `<action>` over a FLAT `command.shift`
list; and (2) the SSOT stored `command_shift[0]` in the WRONG ORDER
(`[& 1] [= 0] [= 0] [= 0]`, leading byte first). Under (b) + the mis-ordered
flat list, the four single-action entries were read in an order that was not
pinned to the devices.xml document order, so the leading `(=,0)` vs `(&,1)`
flipped between interpreters → `(0,1,0,0)` (neo, correct) vs `(1,0,0,0)`
(mbp-13). `get_keyword` selects array idx 2 whose leading entry is the same
under either ordering, so it never diverged.

Fix: store `command_shift` in the SSOT as an explicit, document-ordered
`list[array][value][action]` nesting (matching devices.xml), and make **both**
mirrors parse that nesting under the **(a)** semantics (one entry per `<value>`,
acc reset to seed per `<value>`). The keystream path contains no `set`/dict/
`**kwargs` iteration, so with order pinned the table — and therefore the wire
bytes — are now byte-identical across interpreters. Verified under CPython 3.13
and 3.14 (`uv run --python 3.13|3.14`) and pinned by
`tests/test_wicreset_encoder.py::test_handshake_frames_match_across_interpreters`.

## Corrected enciphered wire bytes (default keyword 4D B6 AB 00 → bound 00 FF 00 F8)

```
set_session  81 00 00 03       -> 81 00 00 03 2d 2d ba 2b
get_keyword  82 00 00 00 00    -> 82 00 00 00 00 40 40 8f ec
get_version  8A 00 00 00 00    -> 8a 00 00 00 00 40 40 8f ec
get_command  86 00 00 00 00    -> 86 00 00 00 00 40 40 8f ec
set_command  85 00 00 10 07 7c -> 85 00 00 10 07 7c 40 40 8f ec   (waste selector)
set_command  85 00 00 0d 00 00 -> 85 00 00 0d 00 00 40 40 8f ec   (common = 5B00 clear)
```

Because only the trailing 4 envelope bytes survive the fold, every functor-3
command shares the enciphered keyword `40 40 8f ec` EXCEPT set_session, whose
`<special>` overwrite lands in `env[19]` (→ `2d 2d ba 2b`).

### Live keyword 11 22 33 44 (bound 44 6B 5C 60) illustration

```
set_command  85 00 00 10 07 7c -> 85 00 00 10 07 7c 1c 1c cb 74
set_command  85 00 00 0d 00 00 -> 85 00 00 0d 00 00 1c 1c cb 74
```

On a live run the `get_keyword` RECV reseeds `functor_initialization`; the 4
enciphered tail bytes change (device binding). The 6-byte clear prefix is
keyword-independent.

## Files changed

- `scripts/canon_sr5_cipher.py` — B1–B5; `seed_fold`, `build_shift_table`,
  `FunctionBlock`, `<function>` parsing, 4-byte functor 2, envelope-as-seed
  functor 3, `encode_command` wire = prefix || 4 enciphered bytes.
- `src/canon_megatank/protocol/wicreset.py` — mirror of the above; SSOT loader
  parses `functor3_functions` + nested shift. **Determinism fix:** the loader
  now implements the **(a)** semantics (one shift entry per `<value>`, via the
  new `_parse_shift_value` helper) instead of the prior (b) per-`<action>`
  flatten; `WicResetEncoder.encipher` returns the full wire frame.
- `printers/canon-g6020/maintenance.yaml` — fixed `command_shift[0]` ordering
  (matches devices.xml) AND re-nested `command_shift` as explicit
  `list[array][value][action]` so document order is interpreter-pinned and both
  mirrors agree; rewrote `derived_sequence` golden bytes to the 4-byte-keyword
  wire form.
- `tests/test_canon_sr5_cipher.py`, `tests/test_wicreset_encoder.py` — 4-byte
  semantics; replaced the stale 20-byte golden bytes; added shift-table /
  special / indexes / four-byte-output checks; **added the determinism
  regression**: pinned `set_session`/`get_keyword` bytes, the pinned
  `(0,1,0,0)` set_session shift table, within-process determinism, and the
  cross-interpreter (3.13 vs 3.14) byte-equality check.

## Caveat

Even a byte-perfect cipher over the right pipe may be FIRMWARE-GATED for the
keyed clear (the WICReset unlock). The SESSION-OPEN + get_keyword (a READ) may
work no-key; confirming a changed reply (vs the generic 1284/status) and ideally
a 4-byte keyword would validate cipher + transport without spending a key. The
keyed clear is a separate later step.
