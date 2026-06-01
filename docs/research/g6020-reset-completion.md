# G6020 5B00 reset completion — decisive verdict

**Date:** 2026-06-01
**Target:** `printerpotty.exe` (WICReset v5.95, 32-bit, base 0x400000, sha256 `a199447db…564b3e8`)
**Question:** Is clearing the G6020 waste/absorber `5B00` state CLOUD-GATED or COMMIT-GATED?
Why did the genuine (cloud-bypassed) reset not complete (empty `0x86`)? What is the single
most-likely path to a COMPLETING reset, and can the native tool generate the 23-byte
`set_command` now?

This supersedes points #2 (keyword padding "unresolved") and #3 ("0x85 codec uncracked") of
`g6020-genuine-setcommand-decode.md`: the 0x85 write codec is now cracked and the padding is
resolved (see §3 / Lane 3).

---

## TL;DR

- **Verdict: COMMIT-GATED, not cloud-gated.** No cloud byte feeds the payload, the keyword
  binding, or the completion test. The reset stalled in-session and `5B00` was never committed.
- **Why empty `0x86`:** the completion loop in `FUN_004eae70` waits ONLY on the device's own
  reply byte-count, polling `get_command` (0x86) for up to **600,000 ms (10 min)**. The device
  never returned a non-empty status reply, so `local_80` stayed `0`, "Processing… common" hung,
  and the tool finally logged "Reply buffer is empty." There is **no finalize/commit VENDOR_SET
  after the poll** — the firmware itself never advanced the write to the committable state
  in-session, so the power cycle had nothing to commit.
- **Single most-likely completing path:** drive the reset natively with the **correct 23-byte
  `set_command`** (`85 00 00 || 20-byte ciphertext`, Lane 3 recipe — byte-exact vs ground truth),
  then let the genuine firmware emit its non-empty `0x86` status reply, which advances WICReset's
  own success path. As a belt-and-suspenders operator fallback, the **PLAIN unkeyed clear**
  (`85 00 00 00 00 10 07 7c` then `85 00 00 00 00 0d 00 00`, already ACK'd `OK(8)`) followed by a
  **clean power-button cycle**.
- **Native tool today: NO.** The validated cipher fix lives only in `/tmp/lane3_*.py`; the
  committed `scripts/canon_sr5_cipher.py` still emits the wrong 10-byte functor-3 shape
  (`85 00 00 10 07 7c e9 e9 8f 1d`). Porting the Lane-3 buffer-role swap into `functor3_encrypt`
  makes the native tool emit the genuine 23-byte frame.

---

## 1. The gate is COMMIT, not CLOUD

Three independent decompile facts, all re-verified against the cached decompiles on neo, show
no cloud value reaches any part of the reset write/completion:

1. **Payload builder has zero cloud inputs.** `functor_encryption_003` (`FUN_004e8410`,
   `/tmp/pp-lane2-emit.txt`) builds the 20-byte payload from LOCAL inputs only: the operand byte
   at frame offset 3, a constant `00 12 01` header, a fixed-seed (`0x12345678`) MSVC LCG, and the
   local `<special>`/`<indexes>` template tables. Grep-confirmed: the only cloud-conn refs in the
   emit file (`DAT_00a45db4`, `FUN_0051c140`) are inside QUERY_KEYS' body at `/tmp/pp-lane2-emit.txt:3061`,
   never inside `FUN_004e8410`.

2. **Cloud is a boolean-only gate.** `RESET_GUID` (`FUN_0051d7d0`), `QUERY_KEYS`
   (`FUN_0051c700`), and `RESET_DATA` (`FUN_0051da40`) are pure `DO_MESSAGE` (`FUN_0051c140`)
   network round-trips. RESET_GUID's only persisted output is the bool `local_2d9`, which in the
   orchestrator (`FUN_0043fbc0`, `/tmp/pp-drm-decomp.txt`) gates ONLY the model-class string router
   `FUN_0047b780` (check_basic / waste_epson / waste_canon …) — a license/model selector, never a
   cipher seed. No buffer, seed, or token from any cloud reply is threaded into the functor, the
   keyword binding, or the `0x86` completion test.

3. **Completion test reads only the device reply.** `service_perform_command_single`
   (`FUN_004eae70`, `/tmp/pp-lane2-bridge.txt:116-216`) loops on `local_80 == 0` — `local_80` is
   the reply byte-count written by `do_read_vendor` (`FUN_0052cab0`). It never consults the cloud.

**Therefore the cloud is gate-only.** Killing `connect()` (forcing the RESET_GUID/QUERY_KEYS
gates) does not corrupt the payload, the keyword, or the completion — the bypass is sound.

---

## 2. Why the genuine reset did not complete (the empty 0x86)

Exact post-`set_command` flow (`FUN_004eae70`, decompile lines 116-216; disasm 0x4eb088-0x4eb110):

```
FUN_004ea540(...)                       # set_command: emits 0x85 || 20-byte PAYLOAD; ACK ret=1
while (local_80 == 0 && elapsed_ms < 600000) {   # local_80 = 0x86 reply byte-count
    __Thrd_sleep(100ms)
    FUN_004ea9c0(...)                   # get_command 0x86 read
    __Thrd_sleep(100ms)
}
sVar4 = FUN_004ed9f0(1, ...)            # parse 2-byte BE length header; returns 0 if <2 bytes
if (sVar4 == 0) FUN_00448440("Reply buffer is empty.")   # FAILURE
```

The loop exits ONLY on (a) the first **non-empty** `0x86` reply, or (b) the **600,000 ms
(10-minute)** wall-clock deadline. There is no status-byte check and no fixed retry counter.
**There is no finalize / commit / save-EEPROM / exit-service-mode VENDOR_SET (0x220038) anywhere
after the poll** — the only `FUN_004ea540` send call in the function is the initial set_command.
The next orchestrator step, `RESET_DATA`, is a cloud `DO_MESSAGE` (msg 5/6), never a USB write.

**Live ground truth matched this exactly:** set_session ACK ret=1 → live keyword `e4 7c 5a` →
set_command `85 00 00 || PAYLOAD(20)` ACK ret=1 → `get_command 0x86` polled hundreds of times,
every reply `ret=1 bytesRet=0` (EMPTY) → "Processing… common" forever.

**Crucial correction (refutes the Lane-2 "forged payload" theory):** the 20-byte payload on the
wire in that capture was *the genuine WICReset blob* (the cloud connect was killed, but the tool
otherwise ran stock), and Lane 3 proves it is the **correct, decryptable** ciphertext (§3,
20/20). So the empty `0x86` was **not** a firmware rejection of a wrong payload — the payload was
right. The firmware accepted/ACK'd the write byte (`ret=1`) but never produced the non-empty
length-prefixed `0x86` status reply that the genuine path needs to advance to "operation
completed." The write was accepted into the session but **never finalized/committed** to the
absorber EEPROM, so the subsequent power cycle had nothing to persist and `5B00` survived.

This is a COMMIT failure (the in-session write never reached the committable state the firmware
acks via a non-empty `0x86`), not a cloud-dependence failure.

---

## 3. The write cipher is CRACKED (Lane 3) — byte-exact

The genuine 20-byte `set_command` payload is reproducible byte-exact from the live keyword +
operand + local template, with **no cloud input**:

```
functor-3 builds a 20-byte ENVELOPE:
    [00 12 01 cmdid] + 16 fixed-LCG bytes  (seed 0x12345678, x=x*0x343FD+0x269EC3, (x>>16)&0xff)
    then cmdid-keyed <special> overwrite + <indexes> operand-scatter
functor-2 (FUN_004e76c0) XOR-stream-enciphers that 20-byte ENVELOPE as the SUBJECT,
    seeded by the 4-byte BOUND keyword.
```

The bug that defeated all prior lanes: functor-2's buffers were **swapped** — the prior model
transformed the 4-byte keyword seeded by the envelope (emitting only the 4-byte trailer
`e9 e9 8f 1d`, the documented wrong artifact). The correct model transforms the **envelope**
seeded by the **bound keyword**, emitting all 20 bytes.

Validated on neo (`/tmp/lane3_confirm.py`, `/tmp/lane3_final.py`) against `/tmp/appbin_out/devices.xml`:

```
live kw e4 7c 5a  -> pad e47c5a00 -> bind_keyword -> bound = 00 35 a9 09
envelope3(85 00 00 || 10 07 7c)  = 00120110 e9dd0da1 967c3104 49079e61 83cf096f
functor2_transform(subject=envelope, seed=bound, send=True)
    = db bb 00 67 59 a1 b0 1f 84 2f d5 83 04 4a 3a c3 51 d2 b1 ef       == GT 20/20
wire frame = 85 00 00 || payload
    = 850000dbbb006759a1b01f842fd583044a3ac351d2b1ef                    == GT 23/23
```

Cross-checks: the prior wrong model reproduces `e9e98f1d` exactly (confirms the precise bug); the
transform is provably **invertible** (`dec(enc(env)) == env`), so the device decrypts our
ciphertext back to the envelope, recovering cmdid 0x10 and the scattered operand — i.e. the
firmware will read our payload as a legitimate command. Every constant is template-derived; only
the live keyword + operand are inputs, so this is not overfit.

The captured payload is the **selector** `set_command` (operand `10 07 7c`, cmdid 0x10) — the
FIRST of the two set_commands. The clear `set_command` (operand `0d 00 00`, cmdid 0x0d) is built
by the identical algorithm:
`gen(e47c5a, 0d0000) = 850000 4dbb006759a1b01f842fd58319a83a627bafb1ef`
(high-confidence-by-construction; a single captured clear-payload pair would empirically pin it).

> Note on padding: this resolves the open question in `g6020-genuine-setcommand-decode.md` #2 —
> the live 3-byte keyword pads to 4 bytes as `e47c5a00` (trailing `00`), which the 20/20 match
> proves; the earlier doc's failed paddings all assumed the wrong functor-2 buffer roles.

---

## 4. Single most-likely path to a COMPLETING reset (do this next)

Primary (highest confidence — uses the genuine accepted codec):

1. **Port the Lane-3 fix** into `scripts/canon_sr5_cipher.py` so the native tool emits the
   genuine 23-byte frame (see §5), then **drive the full handshake natively** against the device:
   `set_session` → `get_keyword` (capture the LIVE keyword) → build `set_command` with the live
   keyword + selector operand `10 07 7c` → send → build + send the clear `set_command`
   (operand `0d 00 00`) → poll `get_command 0x86`. Because the payload is now the genuine
   decryptable ciphertext, the firmware should return a **non-empty length-prefixed `0x86`**,
   which advances the genuine success path.
2. If `0x86` still returns empty after a correct keyed payload, the missing element is a
   **finalize/exit-service-mode** action the firmware expects out-of-session — capture one more
   GENUINE successful reset (any model with a known live keyword) to confirm whether a non-empty
   `0x86` ever appears, and whether a clear-operand pair changes the outcome.

Operator fallback (belt-and-suspenders, no cloud, no keyed blob — already ACK'd `OK(8)`):

3. Send the **PLAIN unkeyed clear** `85 00 00 00 00 10 07 7c` then `85 00 00 00 00 0d 00 00`
   (the write/clear direction is not keyword-gated — only the READ obfuscation is), then perform
   a **clean power-button cycle**. `5B00` commits on the power-button cycle; confirm via a
   post-power-cycle waste-counter read.

The decisive next action is #1 — make the native tool emit the genuine 23-byte set_command and
re-run the handshake natively so we observe whether a correct payload produces the non-empty
`0x86` (proving completion) or whether a separate finalize step is genuinely required.

---

## 5. Can the native tool generate the 23-byte set_command now?

**Not yet — but the recipe is validated and the port is a small, well-scoped change.**

The committed `scripts/canon_sr5_cipher.py` (`functor3_encrypt`, lines 519-524; `encode_command`,
line 562-564) still has the OLD buffer roles and returns `prefix || 4-byte trailer`:

```
committed encode_command(selector) = 85 00 00 10 07 7c e9 e9 8f 1d   (10 bytes — WRONG shape)
```

The fix (buffer-role swap, validated in `/tmp/lane3_*.py`):

```python
def make_set_command(method3, live_kw_3b, operand_3b):
    kw      = live_kw_3b + b"\x00"                          # pad 3 -> 4 (e4 7c 5a 00)
    bound   = bind_keyword(method3, kw)                     # -> 00 35 a9 09
    env     = envelope3(method3, b"\x85\x00\x00" + operand_3b)  # 20-byte envelope (special+indexes by cmdid)
    payload = functor2_transform(method3, env, seed_source=bound, send=True)  # 20 bytes (SUBJECT=env, SEED=bound)
    return b"\x85\x00\x00" + payload                        # 23-byte wire frame
```

Concrete edits to `scripts/canon_sr5_cipher.py`:
- `functor3_encrypt`: make the SUBJECT the 20-byte `envelope` and the SEED the `bound_keyword`
  (i.e. `functor2_transform(method, envelope, seed_source=bound_keyword, send=True)`), and return
  the **20-byte** result — not the 4-byte keyword transform.
- `encode_command` (functor-3 branch): return `bytes(prefix) + functor3_encrypt(...)` =
  `85 00 00 || 20` (23 bytes), dropping the `app_frame || 4` assembly for the 0x85 set path.

After that port, `make_set_command(m3, e47c5a, 10077c)` returns the byte-exact genuine frame
(verified: `850000dbbb…b1ef`, 23/23). No additional captures are required for the selector
branch; one CLEAR-operand pair would confirm the clear branch.

---

## Evidence index

- Cipher (needs the buffer-role-swap fix): `scripts/canon_sr5_cipher.py`
  (`functor3_encrypt` L519, `encode_command` L530, `functor2_transform` L441, `envelope3` L487,
  `bind_keyword` L384)
- Validated Lane-3 recipe + checks: `/tmp/lane3_confirm.py`, `/tmp/lane3_final.py` (neo)
- Template DB: `/tmp/appbin_out/devices.xml` (CANON-IPL method-3, encoders ~43689-43731,
  function blocks keyed by cmdid)
- Decompiles (neo): `/tmp/pp-lane2-emit.txt` (FUN_004e8410 @2028, FUN_004ea540 @1282),
  `/tmp/pp-lane2-bridge.txt` (FUN_004eae70 @116-216, poll loop @121-128),
  `/tmp/pp-lane3-cloud.txt` (RESET_GUID/QUERY_KEYS/RESET_DATA), `/tmp/pp-drm-decomp.txt`
  (orchestrator FUN_0043fbc0, key router FUN_0047b780 @910), `/tmp/pp-poll-timers.txt`
- Prior docs: `g6020-genuine-setcommand-decode.md` (superseded on padding/codec by §3),
  `g6020-wire-codec-crack.md` (§5 PLAIN clear ACK'd OK(8)), `wicreset-drm-bypass.md`

---

## Adversarial verification — is COMMIT-GATED grounded or speculative? (2026-06-01)

Independent re-examination of the four load-bearing claims directly against the decompiles on
neo (`/tmp/pp-lane2-emit.txt`, `/tmp/pp-lane2-bridge.txt`, `/tmp/pp-lane3-cloud.txt`,
`/tmp/pp-drm-decomp.txt`, `/tmp/pp-canon.txt`). Verdict: **the COMMIT-GATED conclusion is
grounded, not speculative — with one correction to how the cloud is characterized.**

### What the decompile actually proves (grounded)

1. **Payload builder has zero cloud inputs — CONFIRMED.** `FUN_004e8410` spans
   `pp-lane2-emit.txt:2028-2255`. Its entire input set is local: operand byte
   `*(byte*)((int)*param_3 + 3)` (L2091), constant header `0x1200` (L2104), constant `0x01`
   (L2106), the operand byte again (L2108), a fixed-seed `0x12345678` MSVC-LCG producing 16 bytes
   (L2110-2117, no nonce), `<special>`/`<indexes>` overlays from the local template
   (L2134-2136), then `FUN_004e76c0` (L2175). Grep for cloud globals `DAT_00a45db4` and
   `FUN_0051c140` in `pp-lane2-emit.txt` returns hits ONLY at L3061-3070 — inside `QUERY_KEYS`
   (`FUN_0051c700`, starts L2994), strictly OUTSIDE the `FUN_004e8410` body. The payload builder
   does not even read the live session keyword.

2. **RESET_GUID persists only a u16 + a bool — CONFIRMED.** `FUN_0051d7d0`
   (`pp-lane3-cloud.txt:1033-1145`) on cloud success writes exactly `*param_3 = local_8a._2_2_`
   (echo bits, L1114) and `*(bool*)param_2 = (local_86 != 0)` (L1115). The only other use of
   `local_86` selects between two static log strings `DAT_0098a6e8`/`DAT_0098a6ec` (L1116-1118).
   No buffer, token, or seed escapes. QUERY_KEYS (`FUN_0051c700`) likewise returns a single bool.

3. **Completion loop waits ONLY on the device byte-count — CONFIRMED.** `FUN_004eae70`
   (`pp-lane2-bridge.txt`): after the lone `set_command` send (`FUN_004ea540`, L116) the poll loop
   L121-131 is `while (local_80 == 0 && FUN_004484d0() < 600000)` — exits on first non-empty 0x86
   reply or the 600,000 ms deadline. Every post-loop branch (L134-216) reads only `local_80`, the
   2-byte length header `sVar4` (`FUN_004ed9f0`), and the accumulated count at `param_6+8`. There
   is **no `FUN_004ea540`/`FUN_0052ce40` (VENDOR_SET 0x220038) anywhere after the poll** — i.e. no
   finalize/commit/exit-service-mode write. No cloud reference in the function.

4. **`clearCounters` is net-free and locally sequenced — CONFIRMED.** `FUN_004ecae0`
   (`pp-canon.txt:3439`) is Ghidra-tagged `NET=no`, loads `"functions.waste"` from the local
   template (L3499), and iterates the local "waste" block labels (do-while L3504+) — the
   selector/clear operand pair comes from the decrypted local `devices.xml`, not the wire.

On (1)-(4) the verdict's evidentiary spine holds: **no cloud byte feeds the 0x85 payload, the
keyword binding, or the 0x86 completion test.** "Clearing 5B00 is not cloud-gated *in its data
dependencies*" is decompile-supported, not speculation.

### The one correction: the cloud is a CONTROL gate, not merely "boolean-only / gate-only"

The phrasing "cloud is gate-only / contributes zero bytes" undersells what the orchestrator does
with the cloud *return status*. In `FUN_0043fbc0` (`pp-drm-decomp.txt`) the cloud calls hard-gate
the control path to `clearCounters`:

- L381 `FUN_0051d7d0()` (RESET_GUID); **L382 `if (cVar9 != 1) goto abort`**.
- L397/L409 `local_2d9 = FUN_0047b780()` (model-class router); **L415 `if (local_2d9 != 1) goto abort`**.
- L571 `FUN_0051c700()` (QUERY_KEYS); **L572 `if (cVar9 != 1) goto abort`**; **L577 bool re-check**.
- **L596 `FUN_004ecae0()` (clearCounters) is reached only if all the above pass.**

`FUN_0047b780` (`pp-drm-decomp.txt:910`) is confirmed a string-keyed model-class dispatcher
(`check_basic`/`waste_epson`/.../`waste_canon`) keyed on the *local* model record `param_3` — it
selects which counter handler runs, not a cipher seed. So the cloud's *value* is data-irrelevant,
but the cloud *call must succeed* (return 1) or the orchestrator never reaches the device write.

This does **not** overturn COMMIT-GATED — in the live run the DRM bypass forced those gates, the
`set_command` genuinely hit the wire and ACK'd, and 0x86 still came back empty. That empty 0x86 is
downstream of every cloud gate, so it cannot be a missing-cloud-byte failure. But the precise,
defensible statement is: **"clearing 5B00 has no cloud DATA dependency; it does have a cloud
CONTROL gate that the bypass already neutralizes."** Calling it flatly "cloud-independent" is the
one over-reach.

### Strongest counter-argument to COMMIT-GATED

The empty-0x86 = "write accepted but not finalized" reading is an *inference*; the decompile is
equally consistent with **"the firmware silently REJECTED the set_command"** (Lane-2 verdict's own
alternative): the code has no branch that distinguishes "in-progress" from "rejected" — empty is
just empty until the 10-min timeout. The live payload on the wire was the SELECTOR set_command
(operand `10 07 7c`); we have **no captured evidence the CLEAR set_command (operand `0d 00 00`)
was ever emitted or ACK'd in that bypass run**, nor any capture of a genuine *successful* reset
showing a non-empty 0x86. So "the write was accepted but not committed" and "the write/sequence
was rejected/incomplete" are not yet distinguishable from the trace we have. Either way the cause
is local (framing/sequence/commit), not cloud — but the *specific* local mechanism is unproven,
and the Lane-3 "correct keyed payload will make 0x86 non-empty" prediction is untested against
hardware.

### THE single decisive experiment (minimal hardware)

Drive the **full native handshake against the printer with a logic/USB capture running**, in one
session, and record the 0x86 reply for each step:

1. `set_session` -> `get_keyword` (capture LIVE keyword).
2. Send the Lane-3 **keyed** SELECTOR `set_command` (operand `10 07 7c`) — confirm ACK.
3. Send the Lane-3 **keyed** CLEAR `set_command` (operand `0d 00 00`) — confirm ACK; this is the
   step never observed on the wire.
4. Poll `get_command` 0x86 and **record whether the reply is non-empty**.

Decision rule:
- **Non-empty 0x86 after the keyed CLEAR -> COMMIT-GATED fully confirmed** (the genuine,
  correctly-sequenced write completes in-session; prior failure was the missing/incorrectly-framed
  CLEAR step, all local).
- **Still empty 0x86 -> an out-of-session finalize/exit-service-mode action is implicated** (still
  not cloud: run the PLAIN-clear `85 00 00 00 00 10 07 7c` then `85 00 00 00 00 0d 00 00` —
  already ACK'd `OK(8)` — and power-cycle; confirm via a post-cycle waste-counter read).

No-hardware preflight (free, do first): port the validated Lane-3 buffer-role swap into
`scripts/canon_sr5_cipher.py` and assert `make_set_command(e47c5a, 10077c)` == ground-truth
`850000dbbb…b1ef` (23/23). This proves the tool can emit the genuine frame before any hardware
run, so a still-empty 0x86 in step 4 cannot be blamed on a wrong payload.

### Bottom line

Agree with **COMMIT-GATED (local)**: grounded in the decompile for the data-dependency claim
(payload/keyword/completion all cloud-byte-free; verified by reading + grep). One correction —
the cloud is a control gate on reaching `clearCounters`, not "nothing," though the bypass already
forces it and the empty 0x86 sits downstream of it. The residual gap is empirical, not logical:
we have not captured a non-empty 0x86 (correct keyed CLEAR sent) nor a genuine successful reset,
so "accepted-but-uncommitted" vs "silently-rejected" remains undecided. The native keyed
two-`set_command` run with a USB capture is the one experiment that closes it.
