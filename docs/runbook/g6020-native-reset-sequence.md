# G6020 native reset — WICReset-derived enciphered session sequence (Lane B)

**Date:** 2026-06-01 · **Status:** `derived-not-yet-validated` (dry-run / gated)
**Lane:** B — USB transport + ordered ops sequence wiring.
**Scope:** wire the full enciphered `set_session → get_keyword → set_command →
verify` sequence into the gated native reset path. **No key spent, no device
touched** — pure derivation, dry-run by default, behind every existing gate.

This is the transport+sequence join of:

- the **literal G6000-family template** recovered from the decrypted WICReset
  `devices.xml` (RECOVERED 2026-06-01 — `docs/research/wicreset-g6020-reset-derived.md`),
- the **functor-3 cipher** (RECOVERED — `docs/research/wicreset-g6020-reset-template.md`
  + `ghidra/wicreset_template_cipher.py`; Lane A owns the runnable encoder),
- the **existing gate stack** (`src/canon_megatank/ops.py` — UUID, status,
  EEPROM, write budget, lockfile).

---

## 1. What changed (code)

### `src/canon_megatank/usb.py` — `ClaimedDevice.send_and_receive`

The existing helpers already cover the two primitive directions:

- `read_response(header)` — write a bare 3-byte `[cmd][arg_hi][arg_lo]` header to
  bulk-OUT (EP `0x03`, the `0x220038` SEND equiv), read the reply on bulk-IN
  (EP `0x86`, the `0x22003c` RECV equiv).
- `send_command(frame)` — write a full frame to bulk-OUT, no read (the
  `0x220038` SEND equiv, write-only — GATED).

The WICReset session needs a **send-primed RECV with a *full enciphered frame***
(not a bare 3-byte header): `set_session` and `get_keyword` write the
functor-enciphered `0x81…`/`0x82…` prefix and then read the reply. Added one thin
method mirroring `read_response`'s style:

- **`send_and_receive(frame, *, timeout_ms, length)`** — write the full
  (enciphered) `frame` to bulk-OUT EP `0x03`, read the reply on bulk-IN EP `0x86`.
  This is the `get_keyword` shape: send the enciphered `0x82 …` prefix, read the
  keyword reply. It does NOT mutate state by itself (session-open + keyword-read
  are handshakes); the state-changing `set_command` still goes through
  `send_command`, and the whole sequence stays behind the gate stack in
  `ops.reset_absorber_wicreset`.

So the transport map is:

| WICReset step | direction | `ClaimedDevice` method | wire (iface 4) |
|---|---|---|---|
| `set_session` | send-primed RECV | `send_and_receive` | OUT `0x03` → IN `0x86` |
| `get_keyword` | send-primed RECV | `send_and_receive` | OUT `0x03` → IN `0x86` |
| `set_command` (×2) | SEND | `send_command` | OUT `0x03` |
| `get_command` verify | send-primed RECV | `send_and_receive` | OUT `0x03` → IN `0x86` |

### `src/canon_megatank/ops.py` — `reset_absorber_wicreset` (+ helpers)

New, alongside the existing `reset_absorber` (bulk `[00 03 01 03 07]`) and
`replay_control_sequence` (EP0 control) paths:

- **`WicSessionDevice` / `WicResetEncoder` Protocols** — the minimal surfaces the
  op needs. `usb.ClaimedDevice` satisfies the device Protocol; Lane A's encoder
  satisfies `WicResetEncoder` (`.encipher(plaintext) -> wire`,
  `.seed_keyword(device_keyword)`). Defining them as Protocols lets the tests
  drive recording fakes without hardware or Lane A's runtime tables.
- **`load_wicreset_frames(...)`** — builds the plaintext app frames by SOURCING
  every literal from the SSOT `derived_template` (the `commands` prefixes and the
  `functions_waste` rows). **No template byte is hardcoded in the module.** The
  `set_command` frames are `prefix(85 …) + selector(10 07 7C)` and
  `prefix + operand(0D 00 00)`.
- **`reset_absorber_wicreset(...)`** — drives the ORDERED sequence, DRY-RUN by
  default, behind the SAME gate stack, in order.

---

## 2. The ordered sequence (every frame functor-3 enciphered)

Over the bulk maintenance lane (iface 4, OUT `0x03` / IN `0x86`):

```
1. set_session   81 00 00 03            send_and_receive   opens the session
2. get_keyword   82 00 00 00 00         send_and_receive   RECV → 4-byte device keyword
                                                            → encoder.seed_keyword(reply)
3. set_command   85 00 00 00 00 | 10 07 7C   send_command  waste-row selector
4. set_command   85 00 00 00 00 | 0D 00 00   send_command  'common' reset operand  ← THE 5B00 WRITE
5. get_command   86 00 00 00 00         send_and_receive   (optional) verify read-back
```

Every frame is passed through `encoder.encipher(...)` before the transfer. The
device keyword read at step 2 is fed back into the encoder
(`functor_initialization` XOR) so the step-3/4 `set_command` frames are keyed to
the live session — this is why the keyword read must precede the writes.

### Literal bytes — RECOVERED vs INFERRED

All literals below are **RECOVERED** from the cleartext
`/tmp/appbin_out/devices.xml` (sha256
`6031555f143080038431cf963706191a3108bd7c4fec03eeffeb2c8f60d86db3`), with the
exact source line cited:

| token | bytes | source | status |
|---|---|---|---|
| `set_session` prefix | `81 00 00 03` | `devices.xml:43504` | RECOVERED |
| `get_keyword` prefix | `82 00 00 00 00` | `devices.xml:43506` | RECOVERED |
| `get_command` prefix | `86 00 00 00 00` | `devices.xml:43507` | RECOVERED |
| `set_command` prefix | `85 00 00 00 00` | `devices.xml:43508` | RECOVERED |
| waste selector | `10 07 7C` | `devices.xml:43807` (`common` row) | RECOVERED |
| `common` operand (5B00) | `0D 00 00` | `devices.xml:43807` | RECOVERED |
| model row | `G6000 series … method=3 support="query;waste:common"` | `devices.xml:43549` | RECOVERED |
| functor for method 3 | `0x03` | `<CANON-IPL>` handler 0x03 block | RECOVERED |
| functor-3 LCG16 envelope | `e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f` | `ghidra/wicreset_template_cipher.py` (MSVC rand, seed `0x12345678`) | RECOVERED |

> **Note on the devices.xml prefix literal width.** The raw XML writes
> `get_keyword`/`set_command` prefixes as `0x82 0x0000000 0x00` — a `0x82` cmd, a
> zero arg, and a trailing `0x00`. The SSOT normalizes this to the 5-byte
> `0x82 0x00 0x00 0x00 0x00` (cmd + 4 zero bytes), matching `set_session`'s 4-byte
> `81 00 00 03` cmd+arg width plus the trailing action byte. The exact on-wire
> arg width is **INFERRED** from the normalized form and is irrelevant to Lane B
> (the encoder consumes whatever the SSOT carries verbatim); it is pinned at
> physical-validation time.

- The G6020 itself has **no `devices.xml` literal** — it is a member of
  `G6000 series` (RECOVERED at `devices.xml:43549`). G6020-applicability is the
  documented family hypothesis (INFERRED), not a direct literal.
- `support="query;waste:common"` (RECOVERED) → the G6000 family clears ONLY the
  `common` absorber. `common` == the 5B00 main absorber is the cross-tool mapping
  (INFERRED from the v5103 "Main" reading + the WICReset capability string).

---

## 3. How it stays gated (the safety contract — unchanged)

`reset_absorber_wicreset` is **DRY-RUN by default**. `execute=True` runs the
existing gate ladder, IN ORDER, before ANY transfer touches the device:

1. **UUID isolation** — `verify` (fingerprint vs the locked `test_unit` UUID).
   Wrong unit → `UnknownPrinterError`.
2. **Validation status** — `maintenance.yaml::supported.absorber_reset.status`
   must be `verified-captured`. It is currently `derived-unvalidated`, so
   `execute=True` HARD STOPS with `ResetNotValidatedError`. The derived template
   is EVIDENCE ONLY (`derived_template.validation: derived-not-yet-validated`) and
   does **not** promote `status` — no op reads/writes the absorber off it until a
   pads-installed physical-validation run.
3. **EEPROM baseline** — `eeprom_dump_done` must be True (rollback evidence).
4. **Write budget** — `charge` raises `WriteBudgetExhaustedError` at the cap,
   **before** any transfer.
5. **Lockfile** — held by the caller (CLI), unchanged.

Two extra refusals specific to this path:

- **literals are SSOT-sourced** — `load_wicreset_frames` refuses
  (`ResetNotValidatedError`) if `derived_template` / its `commands` prefixes are
  absent; it raises (`CanonToolError`) for a waste region the template doesn't
  list (the G6000 family lists only `common`).
- **encoder required** — with no injected `encoder=` and Lane A's
  `canon_megatank.protocol.wicreset.build_encoder` not yet importable, the op
  refuses cleanly (`ResetNotValidatedError`) rather than crashing.

Dry-run is pure: it enciphers the frames for the operator preview but consults
NO gate and touches NO device (verified by tests).

---

## 4. Lane A integration

The cipher is **not** reimplemented here. Lane B owns the ordered transport + the
gate stack; the functor-3 enciphering is Lane A's `WicResetEncoder`:

- **Primary path:** inject `encoder=` (any object with `.encipher(bytes) -> bytes`
  and `.seed_keyword(bytes) -> None`). This is the contract the tests exercise.
- **Convenience fallback:** when `encoder=` is omitted the op dynamically imports
  `canon_megatank.protocol.wicreset.build_encoder(printer_id=...)`. Lane A's
  current cipher lives in `scripts/canon_sr5_cipher.py`; promoting it to
  `src/canon_megatank/protocol/wicreset.py` with a `build_encoder` factory is the
  one wiring step that lights up the fallback. Until then the injected-encoder
  path is fully functional and tested.

---

## 5. Tests

- `tests/test_usb.py::test_send_and_receive_*` — the full-frame send-primed RECV
  writes the whole frame to OUT `0x03`, reads the reply on IN `0x86`, and maps
  USB errors to `UsbAccessError`.
- `tests/test_wicreset_sequence.py` — SSOT sourcing (incl. against the real
  shipped `maintenance.yaml`), dry-run drives nothing / consults no gate,
  `execute=True` blocked at each gate in order (UUID → status → EEPROM → budget)
  with the device proven untouched, and the happy path drives EXACTLY the ordered
  sequence (`recv, recv, send, send, recv`), seeds the encoder with the step-2
  keyword, and carries the `0D 00 00` 'common' operand in the state-changing
  write.

`uv run pytest -q` for the Lane B surface (`tests/test_usb.py`
`tests/test_wicreset_sequence.py`): **29 passed**. Full suite excluding Lane A's
in-progress `tests/test_canon_sr5_cipher.py`: **104 passed, 11 skipped**.
`ruff` + `mypy` clean on the changed files.

> The 7 failures in `tests/test_canon_sr5_cipher.py` are Lane A's brand-new
> cipher round-trip tests (landed in parallel at 2026-06-01 08:40); they are not
> part of the Lane B baseline and are not touched by this change.
