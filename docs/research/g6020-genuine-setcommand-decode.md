# G6020 genuine `set_command` decode — three-lane synthesis

Status: **NEGATIVE for byte-exact reproduction from the live keyword (one pair).**
Date: 2026-06-01.
Inputs: ground-truth capture from a WICReset run (cloud-DRM bypassed) that the
device ACK'd `ret=1`; three independent analysis lanes (A/B/C) run offline
against `scripts/canon_sr5_cipher.py`, `src/canon_megatank/protocol/wicreset.py`,
`scripts/g6020_wire_codec_crack.py`, and `/tmp/appbin_out/devices.xml`.

## 0. Ground truth (this session)

```
set_session  VENDOR_SET 0x220038   81 00 00 03                       (PLAIN, 4 bytes)
get_keyword  VENDOR_GET 0x22003c   prime 82 00 00 -> REPLY e4 7c 5a  (live session keyword, 3 bytes)
set_command  VENDOR_SET 0x220038   23 bytes = 85 00 00 || PAYLOAD(20)
get_command  VENDOR_GET ...0x86    polling for completion
```

`PAYLOAD (20) = db bb 00 67 59 a1 b0 1f 84 2f d5 83 04 4a 3a c3 51 d2 b1 ef`

Transport (confirmed): `VENDOR_SET` = control-OUT `0x41`, `bRequest=inBuf[0]`,
data = whole frame; `VENDOR_GET` = control-IN `0xC1`, `bRequest=inBuf[0]`.

Verified properties of the payload (re-checked this session):
`len 20, distinct 20, exactly one 0x00 (index 2), no 00 12 01 envelope marker.`

## 1. Answer to the two operational questions

### (a) Can we generate the byte-exact 23-byte `set_command` from a live keyword?

**No** — not from the one `(keyword, payload)` pair we hold, and **not with the
cipher we have**. All three lanes are conclusively negative, and the failure is
**structural**, not a parameterization miss.

### (b) Is one pair enough?

**No.** The 0x85 write payload is a full-entropy, operand+keyword-dependent
20-byte ciphertext. A single sample cannot pin a 20-byte plaintext or separate
the keyword keystream from the operand dependence — the same information-theoretic
wall that the cracked 0x84 read codec only got past with ~40 samples.

## 2. What the three lanes proved (convergent)

All three lanes attacked the framing "`PAYLOAD` is a functor-3 envelope
enciphered/keyed by the live keyword `e47c5a`" and all three **refute** it.

| Lane | Hypothesis class | Best score vs GT | Verdict |
|------|------------------|------------------|---------|
| A | `functor3_encrypt` / `envelope3` ± all keyword paddings & operands; 0x84 XOR-keysel; functor2 over 20 bytes; GT XOR {get_version, r84-plaintext}; per-position keyword XOR | 2/20 (below chance ~0.08 expected) | refuted |
| B | `PAYLOAD = envelope3 XOR keyword-keystream`; LCG seeded by keyword (msvc/glibc/nr, all orders/shifts); 0x84-codec decode | 1/20 (chance) | refuted |
| C | functor2 send/recv decrypt to a `00 12 01 cmd` header; XOR every clear envelope to expose keystream; full-20 functor2 both directions | 0/20 header recovery; implied keystream has no keyword structure | refuted |

Empirically re-confirmed this session (`.venv/bin/python`, 69 cipher/wicreset
tests still pass):

```
envelope3(85 00 00 0d 00 00) = 0012010de93f0d0000013104492d9e6183cf096f   match vs GT: 0/20
envelope3(85 00 00 10 07 7c) = 00120110e93f0da196953104492d9e6183cf096f   match vs GT: 0/20
functor3_encrypt(0d 00 00, kw e47c5a00) = e9 e9 8f 1d   substring-of-GT: False
```

### The three independent shape mismatches

1. **Wire length.** Our `WicResetEncoder.encipher` emits
   `prefix(CLEAR) || 4-byte enciphered keyword`. For the live keyword it produces
   e.g. `85 00 00 0d 00 00 e9 e9 8f 1d` (10 bytes) — operand carried **in clear**,
   only **4** cipher bytes appended. The genuine `set_command` is
   `85 00 00 || 20-byte ciphertext` (23 bytes) with **no cleartext operand**. The
   MEMORY/SSOT already flagged this ("our encoder previously emitted
   `prefix||4-enc-keyword-bytes` which is WRONG vs this 23-byte ground truth");
   this run confirms it.

2. **Envelope content.** Our 20-byte functor-3 envelope is mostly the **constant**
   LCG tail `e93f0da1…096f` with a `00 12 01 cmd` header and 2–3 overwrite bytes —
   low entropy, self-similar across operands. GT is 20 distinct high-entropy bytes
   with **no** `00 12 01` marker. No keyword transform we have (0x84 XOR-keysel,
   repeating-keyword XOR, functor2 over 20 bytes) maps `envelope3 -> GT`.

3. **Key independence.** `seed_fold` washes out everything but the trailing 4
   envelope bytes, so our functor-3 output is command-independent under a keyword
   and is structurally **incapable** of being a 20-byte operand-dependent
   ciphertext. The live keyword yields the *same* trailer `e9e98f1d` for both
   `0d 00 00` and `10 07 7c` operands — direct proof of the wash-out.

## 3. The native generator we CAN produce today (validated)

We **cannot** generate the 23-byte cloud blob. We **can**, byte-exact, generate
the functor-3 frames the device already ACK'd on the prior usbprint path, and the
PLAIN clear frames the reset log shows were ACK'd `OK(8)`. Both lanes' positive
findings agree on this as the repo's correct write lane.

```python
# src/canon_megatank/protocol/wicreset.py — validated path
from canon_megatank.protocol import wicreset as w

m   = w.load_method_from_ssot(printer_id="canon-g6020")   # functor=3, handler=3
enc = w.WicResetEncoder(m)                                 # primed default kw 4d b6 ab 00
enc.seed_keyword(bytes.fromhex("e47c5a00"))                # live keyword, padded to 4 bytes

# functor-3 framing (prior usbprint capture, default kw) — reproduced byte-exact:
#   encipher(85 00 00 00 00 0d 00 00) -> 85 00 00 00 00 0d 00 00 40 40 8f ec
#   set_session trailer 2d 2d ba 2b also reproduced (21/21 + 69 suite tests pass)
```

This is the only generator that is currently *byte-true*. It does **not** emit
the 20-byte cloud payload and must not be made to pretend it does.

### Why this matters operationally

The reset log (`docs/research/g6020-wire-codec-crack.md` §5) shows the device
ACK'd the **PLAIN, unkeyed** clear: `85 00 00 00 00 10 07 7c` then
`85 00 00 00 00 0d 00 00` (8-byte frames, `OK(8)`). The WRITE/clear path is **not
keyword-gated** there. The genuine reset therefore does **not** require
reproducing the 20-byte cloud blob; the blob is the WICReset cloud/DRM path's
enciphered command, a different (stronger) codec.

## 4. Corrections our cipher modules need

These are the load-bearing fixes implied by the ground truth. None of them claim
to reproduce the 20-byte blob; they correct the framing model and document the
codec boundary so the encoder stops emitting a wrong wire shape.

1. **Framing: a `set_command` is ONE 23-byte frame `85 00 00 || PAYLOAD(20)`, not
   a `select`+`clear` pair and not `prefix||4-enc-keyword`.** The current
   `encipher` framing (`prefix(CLEAR) || 4-byte trailer`, 10–12 bytes) is the
   functor-3 *usbprint* shape, not the 0x85 cloud shape. Either:
   - keep `encipher` for the functor-3/usbprint lane (it is validated), and add a
     **separate, explicitly cloud** code path that builds `85 00 00 || <20-byte
     ciphertext>` once the 0x85 codec is recovered; or
   - if the operator lane is the PLAIN clear (recommended, per §3), emit the bare
     `85 00 00 00 00 10 07 7c` / `85 00 00 00 00 0d 00 00` operand frames with **no
     enciphered keyword suffix at all** on the write path.

   Do **not** silently route a 0x85 build through `functor3_encrypt`; its 4-byte
   trailer is not the cloud payload (confirmed: `e9 e9 8f 1d != ` any GT
   substring).

2. **Keyword padding.** The live `get_keyword` reply is **3 bytes** (`e4 7c 5a`);
   the cipher keyword word is **4 bytes**. `seed_keyword` already trims to 4 but
   the *source* reply is short, so the 4th byte must be supplied. The
   ground-truth pairing here is the 3-byte live keyword with no observed 4th byte;
   our tested paddings (`…00`, `00…`, `…e4`, `5a7ce400`, `…ff`) **all** fail, so
   the padding rule is **unresolved and cannot be inferred from one pair**.
   Action: document the keyword as the **3-byte live word** and treat the 4th-byte
   padding as an open variable to be fixed by multi-sample capture — do not hardcode
   `||00` as if it were proven.

3. **Keystream / envelope: no fix makes our functor-3 produce the blob.** The
   functor-3 tables model the READ/keyword-handshake path. The 0x85 WRITE payload
   is a different, stronger transform (operand-dependent, full entropy), most
   likely the **same nonlinear-key-schedule family as the still-uncracked 0x8c
   read register** (GF(2)-linear fit 0/160) or a cloud-side cipher keyed by more
   than the 24-bit live keyword. There is no envelope or keystream patch to apply;
   the correct change is a **documentation boundary**: mark functor-3 as
   READ/handshake-only and stop implying it covers 0x85.

4. **Docstring/SSOT note.** Update the `encipher` docstring and ADR-0007 derived
   notes to record that the on-wire `set_command` observed under cloud bypass is
   `85 00 00 || 20-byte ciphertext`, that this is NOT the functor-3 output, and
   that the validated functor-3/PLAIN lanes are the supported write paths.

## 5. Do we need more pairs? (yes — and which)

One pair is insufficient. To crack the 0x85 cloud codec we need either:

- **(preferred, non-destructive) controlled-keyword captures:** ≥2 WICReset
  sessions whose live keywords differ in a **single byte**, each with the **same**
  operand, to isolate the keyword keystream from the operand dependence — the exact
  methodology that cracked 0x84. Then vary the operand at a fixed keyword to map
  the operand path. Realistically want ~10–40 pairs for a keystream/block crack.
- **or the WICReset write-path decompile:** the `FUN_004e8410`-adjacent encryptor
  / the 0x85-specific 20-byte build path in the app binary. The 67 functor-3
  `<function>` blocks (codes 0x00–0x43) are READ-side index/special tables; none is
  keyed to 0x85. Look specifically for a SECOND functor/handler operating on a
  20-byte buffer, and check whether it is the same primitive as the 0x8c nonlinear
  key schedule (the open item in `scripts/g6020_wire_codec_crack.py`).

## 6. Next step

1. Land the framing + boundary corrections in §4 (encoder docstring + a guard that
   refuses to present a functor-3 trailer as a 0x85 cloud payload). Keep the
   validated functor-3/PLAIN lanes intact (69 tests green).
2. Drive the operator reset via the **PLAIN clear** (`85 00 00 00 00 10 07 7c`
   then `85 00 00 00 00 0d 00 00`), which the device already ACK'd `OK(8)` and is
   not keyword-gated — this is the genuine reset path and needs no blob.
3. To actually decode the cloud blob, schedule the controlled-keyword capture
   campaign (§5) or the 0x85 decompile. Until then, treat the 20-byte payload as a
   cloud/DRM artifact, not a reproducible target.

## References

- `scripts/canon_sr5_cipher.py`, `src/canon_megatank/protocol/wicreset.py` — cipher under test (functor-3, validated 69 tests)
- `scripts/g6020_wire_codec_crack.py` — cracked 0x84 XOR-keysel codec; open 0x8c nonlinear schedule
- `docs/research/g6020-wire-codec-crack.md` §2/§5 — 0x84 codec, PLAIN write path ACK'd `OK(8)`
- `docs/research/g6020-recv-transport-re.md` — functor output = 4 bytes (decompiled)
- `docs/research/usbprint-vendor-urb-mapping.md` — prior 12-byte `set_command` (default kw, `40 40 8f ec`)
- `printers/canon-g6020/maintenance.yaml` — `supported.absorber_reset.derived_template` (recovered tables)
- `/tmp/appbin_out/devices.xml` — decrypted WICReset model DB (ephemeral; not vendored)

## 7. Adversarial verification (independent re-run)

This section is an independent check of the §1–§6 claims, run against the live
cipher (`src/canon_megatank/protocol/wicreset.py`) rather than trusting the prior
analysis. Every number below was reproduced this session.

**Q1 — Is the payload reproduction byte-EXACT from `e47c5a`, or overfit?**
NEITHER: there is NO reproduction at all. `encipher()` for the live keyword emits a
**12-byte** frame (clear prefix + 4-byte trailer), not the 23-byte ground-truth
`85 00 00 || PAYLOAD(20)`. Best match across all 5 keyword paddings × both operands
was **2/20** (kw `00e47c5a`, trailer `0d0dd53b`) — below the ~0.08 chance floor and
in the trailer region only. The functor-3 envelope `envelope3()` matches GT **0/20**;
`GT[4:] XOR fixed16 = b09ebdbe12bae4874d67a4a2d21db880` has **0/16** keyword-byte
structure. GT has no `00 12 01` marker, all 20 bytes distinct, one zero (idx 2). So
the claim is correctly stated as **non-reproduction**, not an overfit fit.

**Q2 — Does the generator depend ONLY on live keyword + fixed template?**
For the VALIDATED lane, YES and it is NOT overfit to this payload: with the
template-DEFAULT keyword `4db6ab00`, `encipher("85 00 00 00 00 0d 00 00")` →
`...40408fec` (prior `set_command`) and `encipher("81 00 00 03 ...")` → `2d2dba2b`
(prior `set_session`), both byte-exact against the PRIOR usbprint capture (a
DIFFERENT keyword than `e47c5a`). That cross-keyword reproduction is the proof the
generator is keyword+template-parametric, not curve-fit to one sample. The generator
was NOT secretly tuned to the 20-byte payload — it CANNOT emit 20 bytes at all
(structural), so there was nothing to overfit. 69 tests pass.

**Q3 — Can ONE pair generalize, or do we need more?**
We need more, and the §5 count is right. One `(keyword, payload)` pair cannot pin a
20-byte plaintext under any keyed codec; and the payload is NOT GF(2)-linear-recoverable
from a single sample (`GT ^ get_version` and every envelope residual are full-entropy,
0/20 keyword bytes). Minimum: **2 sessions with single-byte-different live keywords at a
fixed operand** to separate keystream from operand; then **vary operand at fixed keyword**.
Plan for **~10–40 captured pairs** for a keystream/block crack (same scale that cracked
0x84 with 40). A decompile of the 0x85/20-byte write encryptor is the alternative and
would need zero live captures.

**GO / NO-GO for the native tool generating the genuine clear:**
**GO** — but only for the genuine *reset clear*, which is the PLAIN, NON-keyword-gated
operand sequence `85 00 00 00 00 10 07 7c` then `85 00 00 00 00 0d 00 00` (device
already ACK'd `OK(8)`). The native tool can emit these today. **NO-GO** for reproducing
the 23-byte cloud `set_command` blob — that is a separate WICReset cloud/DRM codec
(0x8c nonlinear-schedule family, not functor-3) and is blocked on §5 captures/decompile.
Do NOT route a 0x85 build through `functor3_encrypt`; its `e9e98f1d` trailer is not any
GT substring. The blob is not on the critical path for the reset.

**What would falsify this conclusion:** if a future capture showed the device REJECTING
the PLAIN clear and requiring the 23-byte blob (then the blob IS load-bearing and the
GO downgrades); or if `GT XOR envelope3` over a controlled second keyword revealed a
clean per-position keyword XOR (then it IS the same family as 0x84 and crackable in
~2–4 pairs, not 10–40). Neither is observable from the single pair in hand.
