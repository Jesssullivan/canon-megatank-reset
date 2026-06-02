# G6020 service-mode readback WIRE CODEC — empirical crack

**Date:** 2026-06-01 · **Lane:** cipher-crack (pure offline analysis). **No device
write was ever issued.** All results below are math on the collected dataset
`/tmp/codec-dataset.json` (mirror `mbp-13:~/canon-tool-staging/codec-dataset.json`):
40 fresh service-mode sessions, constant device state, per-session 3-byte keyword.
Cross-validated against the out-of-sample baseline session in
`mbp-13:~/canon-tool-staging/reset-attempt-20260601-182441.log`.

Reproducer (untracked, for review): `scripts/g6020_wire_codec_crack.py`.

> The repo's WICReset functor-3 cipher (`scripts/canon_sr5_cipher.py`,
> `src/canon_megatank/protocol/wicreset.py`) is **devices.xml template
> obfuscation**, NOT this wire codec — it does not reproduce these replies and is
> not used here. The wire codec below was reversed empirically from the dataset.

---

## TL;DR

| item | result |
|---|---|
| **0x84 codec** | **SOLVED.** Additive (XOR) stream cipher over a CONSTANT 20-byte plaintext; each output byte XORs one raw keyword byte (or nothing) per a fixed position-selection table. Reconstructs **40/40** dataset rows **and** the out-of-sample log session byte-exact. |
| **0x84 plaintext** | `06 47 1a 0e 1b 01 02 54 07 59 12 07 1f 0b 08 52 12 01 01 4e` (constant). This is a **device descriptor / status register, NOT the live waste counter** — it is byte-identical before and after the in-session CLEAR. |
| **0x8c codec** | **NOT solved.** Substitution cipher with a key schedule that is **nonlinear in all three keyword bytes** (GF(2)-linear fit = 0/160 output bits; no single/double keyword-byte XOR/add/sub, no GF(256) multiply, no keyed permutation, no tried LCG). 0x8c is the more likely counter register but its codec needs the firmware/tool read-path source or controlled-keyword data to finish. |
| **get_version (0x8a)** | Stable `e790c1848ba047873c2d4741b0d8d6d4b357beeb`. Does NOT share the 0x84 codec (does not fit it under any single keyword). It is keyed/encoded differently (and unchanging across sessions, so unkeyed-by-session or fixed-key). Not decoded. The plaintext model string is independently known from the live `GET_1284_ID`: `MFG:Canon;CMD:BJL,BJRaster3,BSCCe,IVEC,IVECPLI;MDL:Device;CLS:PRINTER;DES:Canon Device;VER:1.070;STA:10;PSE:KMDA10021;` (from the reset log). |
| **plain clear** | The operator already sent the PLAIN clear `85 00 00 00 00 0d 00 00` (preceded by selector `85 00 00 00 00 10 07 7c`) and the device **ACK'd it (OK(8))**. The wire SET path does **not** require a session-keyword-keyed payload — see §5. Effect on 5B00 commits only on the power-button cycle. |

---

## 1. Dataset / transport recap

`VENDOR_GET` = USB control-IN `bmRequestType=0xC1`, `bRequest=<cmd>`, `wValue=0`,
`wIndex=0` (authoritative: `docs/research/usbprint-vendor-urb-mapping.md`). Each
session: `set_session 81 00 00 03` → read `0x82` (3-byte keyword `kw`) → read
`0x84` (20 bytes) → read `0x8c` (20 bytes). `kw` is the only per-session variable;
device state is constant, so the 0x84/0x8c **plaintexts are constant** and only the
encoding varies with `kw`.

## 2. 0x84 codec — SOLVED (additive XOR stream, raw-keyword keystream)

For every byte position `p ∈ [0,20)`:

```
r84[p] = plaintext84[p]  XOR  keystream[p]
keystream[p] = 0                     if KEYSEL[p] == 'C'
             = kw[ KEYSEL[p] ]       otherwise         (kw = the 3 raw keyword bytes)
```

Recovered tables:

```
KEYSEL    = [1,'C', 2, 0, 2, 1, 0,'C', 1,'C', 2, 2, 0, 0, 1,'C', 2, 1, 0,'C']
plaintext84 (hex) = 06 47 1a 0e 1b 01 02 54 07 59 12 07 1f 0b 08 52 12 01 01 4e
```

i.e. positions **1, 7, 9, 15, 19 are un-keyed** (always emit the raw plaintext byte
`0x47 0x54 0x59 0x52 0x4e`), the other 15 positions XOR one of the three keyword
bytes per `KEYSEL`.

### Evidence

* **Constancy:** for each non-keyed position `r84[p]` is identical across all 40
  rows; for each keyed position `r84[p] XOR kw[KEYSEL[p]]` is identical across all
  40 rows (= the plaintext byte). Derived independently per position, no fitting.
* **GF(2) linearity:** all **160/160** output bits of 0x84 are GF(2)-linear in the
  24 keyword bits with zero inconsistent equations — exactly what a per-byte
  keyword XOR predicts.
* **Full reconstruction:** encoding `plaintext84` under each session's `kw`
  reproduces all **40/40** `r84` values byte-exact.
* **Out-of-sample validation (decisive):** the reset log captured a *different*
  session (`kw = 8b12d7`) with `0x84 = 1447cd85cc1389541559c5d094801a52c5138a4e`.
  The recovered codec **predicts that ciphertext byte-exact** — a session that was
  never part of the crack set. Codec is correct, not over-fit.

### Why the row-0 "TGM4LS8TUYEP%1ZRES;N" crib was a red herring

That ASCII-looking string was the *ciphertext* of one session; it looked textlike
by chance because the keystream of that particular `kw` mapped the binary
plaintext into printable bytes. The true plaintext is binary register data, not the
1284-ID string. The 1284-ID lives on the separate `GET_1284_ID` (class) request.

## 3. What 0x84 actually holds — a CONSTANT descriptor, NOT the counter

Decoded `plaintext84 = 06 47 1a 0e 1b 01 02 54 07 59 12 07 1f 0b 08 52 12 01 01 4e`
(decimal `[6,71,26,14,27,1,2,84,7,89,18,7,31,11,8,82,18,1,1,78]`).

The reset log read `0x84` **before** and **after** issuing the CLEAR (steps:
baseline `1447cd85…` under `kw=8b12d7`; post-clear `dc47f0c2…` under the reset
session's `kw=ccdaea`). Decoding **both** with the §2 codec yields the **identical**
plaintext `06471a0e1b010254075912071f0b08521201014e`. So **0x84 does not change with
the clear** → 0x84 is a device/model status descriptor (the `0x47 'G'`, `0x54 'T'`,
`0x59 'Y'`, `0x52 'R'`, `0x4e 'N'` un-keyed bytes are stable record markers), **not
the live waste-ink counter**. The waste counter is therefore in `0x8c` (which does
vary independently) and/or the `0x86` status frame.

## 4. 0x8c codec — NOT solved (nonlinear key schedule)

0x8c is the more probable waste-counter register, but its encoding is materially
harder than 0x84. Confirmed it is a **substitution cipher** (39/40 distinct sorted
byte-multisets → not a permutation of a fixed multiset) with a **nonlinear** key
schedule. The following were all tested against the 40 rows (+ the log baseline) and
**all FAILED**:

* per-position single keyword-byte XOR / modular ADD / modular SUB;
* per-position XOR/ADD/SUB of any *pair* of keyword bytes;
* full GF(2)-linearity in the 24 keyword bits → **0/160** output bits linear
  (vs 160/160 for 0x84) — proves the schedule is genuinely nonlinear;
* GF(256) multiply of a single keyword byte by a per-position constant; GF(256)
  `xtime`-shifts; a square-then-high-byte hash of a keyword-byte pair;
* additive-keystream + standard LCGs (MSVC `0x343FD/0x269EC3`, glibc, Numerical
  Recipes, Borland, MMIX, Java, etc.) over all 6 keyword byte-orderings, output
  shifts {0,8,16,24}, advance-before/after, several increments — assuming plaintext
  = zero, = the 0x84 plaintext, or a per-position constant recovered from row 0;
* a byte-permutation of a constant plaintext; a per-position link to any single
  `0x84` ciphertext byte; a `0x8c = 0x84 XOR const` link.

Conclusion: 0x8c mixes all three keyword bytes through a nonlinear function (integer
multiply / hash / S-box keyed by the 24-bit session keyword). Finishing it needs one
of:

1. the firmware or Service-Tool **read-path** decompile of the 0x8c reply parser
   (Ghidra) to read the generator directly; or
2. **controlled-keyword** captures (sessions chosen so two keywords differ in only
   one byte) to isolate per-byte dependence — not obtainable from this random-keyword
   dataset.

The log's baseline `0x8c = c0f98d21b5c539ca50559f61995133ef9068bf2b` (kw `8b12d7`)
and post-clear `0x8c = 933167ce20c409c5f8bc95ffbc30f32b6aa808f9` (kw `ccdaea`)
cannot be compared in plaintext without this codec; they differ at the cipher level
as expected because the keywords differ.

## 5. The clear / SET direction — is it keyed?

The reset log is the authority here: in one live session the operator sent, as
**plain** control-OUT frames (`bmRequestType=0x41`, the §-usbprint mapping):

```
1 set_session   81 00 00 03                 -> OK(4)
2 get_keyword   0x82                         -> ccdaea
3 set_command   85 00 00 00 00 10 07 7c      -> OK(8)   (waste-row selector)
4 set_command   85 00 00 00 00 0d 00 00      -> OK(8)   (G6000-family 'common' 5B00 clear operand)
```

Both `0x85` set_commands were **accepted (OK(8)) with the operand bytes sent
verbatim and unkeyed** — no session-keyword-derived suffix was appended, and the
device did not stall. So, on the evidence:

* The **read** replies (0x84/0x8c) are keystream-encoded with the session keyword,
  but the **write/clear** path accepts the plain operand frame. There is no sign the
  5B00 clear requires a keyword-keyed payload; the keyword gates the *read* obfuscation,
  not the *write*.
* **Exact clear bytes** (already sent, accepted): selector
  `85 00 00 00 00 10 07 7c`, then clear `85 00 00 00 00 0d 00 00`, each as a control-OUT
  `0x41 / bRequest=0x85 / wValue=0x0000 / wIndex=0x0000` with the whole frame as the
  data stage (per `usbprint-vendor-urb-mapping.md`).

**Plain clear should suffice** — it was ACK'd. The 5B00 state only commits on the
power-button cycle, so confirmation must come from a post-power-cycle read (the
in-session `0x86` verify in the log returned empty, and `0x84` is not the counter).
A keyed clear is **not** indicated by any evidence collected.

## 6. Device state during analysis

The G6020 was power-cycled by the operator mid-analysis: it briefly enumerated as
`04a9:1865` (normal mode) and then returned to `04a9:12fe` (service mode). All
results above are from the dataset + the existing reset log; no fresh reads were
taken (the pyusb reader that produced the dataset was not resident on `mbp-13`, and
the constraint is read-only / no writes). The 0x84 codec is fully validated without
any new capture; 0x8c remains the open item.

## 7. Next steps to close 0x8c (no device write)

* Ghidra the 0x8c reply parser in ServiceTool / WICReset (read path,
  `FUN_0040f500`-adjacent, cf. `docs/research/servicetool-v5103-read-re.md`) to read
  the keystream generator.
* OR collect ~10 sessions with **controlled** keywords (keywords differing in a
  single byte) — non-destructive reads only — to linearize the per-byte dependence.
* Then decode 0x8c before/after a power-cycle to read the waste-counter value and
  confirm 5B00 cleared.
