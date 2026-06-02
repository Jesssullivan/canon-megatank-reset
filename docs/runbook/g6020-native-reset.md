# G6020 native 5B00 reset — VALIDATED end-to-end procedure

**Date:** 2026-06-01 · **Status:** `hardware-validated` (native libusb clear, real
debug unit) · SSOT status deliberately kept `derived-unvalidated` (see §7).
**Scope:** the complete, hardware-proven native reset of the Canon G6020 ink
absorber (5B00 / `markerWasteInkReceptacleFull`) — no WICReset, no VM, no Wine, no
cloud, no purchased key. Pure libusb EP0 control transfers from our own tool.

> **VALIDATED ON REAL HARDWARE (2026-06-01).** The sequence below cleared 5B00 on
> the dedicated debug G6020. The printer rebooted out of service mode to normal
> mode (re-enumerated `04a9:1865`) after a clean power-button shutdown. This is the
> reference procedure. The dangerous prior dead-ends (bulk group-7 SEND, cloud
> nonce gamble) are NOT this — see §6 for why this one works.

---

## 0. Before you touch the printer

1. Confirm you are on **mbp-13** with the debug unit attached (this is the only
   unit the SSOT UUID gate accepts — `00000000-0000-1000-8000-00186501807c`).
2. This is a **write-eeprom** operation. The full gate ladder (§5) runs on every
   `--execute`. Do not bypass it.
3. **Dry-run first.** `canon-megatank reset-native` (no `--execute`) prints every
   wire frame and the commit step without touching USB. Always preview.

---

## 1. Service-mode entry (device enumeration)

The native reset talks to the printer **in service mode**, where it enumerates as
a different USB product:

| mode | USB id | how to enter |
|---|---|---|
| normal | `04a9:1865` | default power-on |
| **service** | **`04a9:12fe`** | service-mode key sequence on the panel |

Service-mode entry is the standard Canon panel combo (power + resume taps); the
G6020 then enumerates as `04a9:12fe` on interface 0, alt 0. The CLI opens this
product by default on `reset-native --execute` (`--product-id 0x12fe`,
`interface=None` — EP0 control needs no bulk-interface claim). Confirm with
`lsusb` that `04a9:12fe` is present before running.

---

## 2. The transport — usbprint VENDOR control, NOT bulk

Every frame is an **EP0 vendor control transfer** to the device, exactly
reproducing what Windows' `usbprint.sys` emits for its `VENDOR_SET_COMMAND`
(IOCTL `0x220038`) and `VENDOR_GET_COMMAND` (`0x22003c`) IOCTLs. This is the
decisive correction over the earlier bulk path (which ACKed but never cleared).

Mapping (RECOVERED from the `usbprint.sys` decompile,
`docs/research/usbprint-vendor-urb-mapping.md` §7, CONFIRMED live):

| step | dir | bmRequestType | bRequest | wValue | wIndex | data stage |
|---|---|---|---|---|---|---|
| `set_session` | OUT | `0x41` | `0x81` | `0x0000` | `0x0000` | whole enciphered frame |
| `get_keyword` | IN | `0xC1` | `0x82` | `0x0000` | `0x0000` | reads device keyword |
| `set_command` ×2 | OUT | `0x41` | `0x85` | `0x0000` | `0x0000` | **whole 23-byte frame, verbatim** |
| `get_command` | IN | `0xC1` | `0x86` | `0x0000` | `0x0000` | reads back (empty — see §4) |

`bRequest = frame[0]`; `wValue = (frame[1] << 8) | frame[2]` (both 0 here). The
`set_command` 23-byte frame is the WHOLE control-OUT data stage — **never split**
the `85 00 00` header from the payload. `ServiceModeTransport.send_and_receive`
routes by frame shape: a bare 3-byte read header (`82 00 00` / `86 00 00`) goes
VENDOR_GET IN; anything longer is a write-shaped frame and goes VENDOR_SET OUT and
returns `b''`.

---

## 3. The four commands (the ordered session)

```
1. set_session   81 00 00 03            OUT 0x41/0x81   opens the service session
2. get_keyword   82 00 00               IN  0xC1/0x82   -> live 3-byte device keyword
                                                         (pad to 4, then seed encoder)
3. set_command   85 00 00 | 10 07 7c    OUT 0x41/0x85   waste-row SELECTOR (23 bytes)
4. set_command   85 00 00 | 0d 00 00    OUT 0x41/0x85   'common' CLEAR  ← THE 5B00 WRITE
   get_command   86 00 00               IN  0xC1/0x86   read-back (EMPTY by design — §4)
```

- Step 2 returns the printer's **live 3-byte keyword** (e.g. `e4 7c 5a`). The
  functor-2 cipher SEED is 4 bytes, so the reply is right-padded with `0x00` to
  `e4 7c 5a 00` (`keyword_pad_to=4`) before `encoder.seed_keyword`. The keyword is
  the ONLY runtime input; everything else is statically derived. The keyword read
  MUST precede the writes — it keys them to the live session.
- Steps 3 and 4 are the two enciphered `set_command` writes. The SELECTOR
  (`10 07 7c`) addresses the `common` waste row; the CLEAR (`0d 00 00`) is the
  operand that zeroes the absorber counter.

### The cracked write cipher (why these are 23 bytes)

The genuine `set_command` is functor-2 with the buffer roles **swapped** vs the
naive reading: SUBJECT = the 20-byte functor-3 ENVELOPE, SEED = the 4-byte BOUND
keyword. The wire frame is the 3-byte set_command header followed by the 20-byte
enciphered payload:

```
app      = 85 00 00 || operand            (e.g. 85 00 00 10 07 7c)
envelope = envelope3(method=3, app)       (20 bytes)
payload  = functor2_transform(method, envelope, seed=bound_keyword, send=True)   (20 bytes)
wire     = 85 00 00 || payload            (23 bytes)
```

`bound_keyword = bind_keyword(method, live_keyword_padded)`. For the captured live
keyword `e4 7c 5a 00`, bind yields `00 35 a9 09`.

---

## 4. The empty-0x86 caveat — DO NOT gate on it

`get_command` (`86 00 00`, IN `0xC1/0x86`) returns an **EMPTY reply** on this
device, and **there is NO finalize command**. This is by design.

- The op never asserts on the `get_command` reply; an empty read is expected and
  correct.
- The clear is committed by the two `set_command` writes plus the power-off (§4½),
  NOT by `0x86`.
- **Do not block, retry, or fail the reset because `0x86` came back empty.** Code
  that gates on a non-empty `0x86` will wrongly mark a successful reset as failed.

---

## 4½. CRITICAL — the clean power-button commit (and why unplug fails)

The two `set_command` writes do **not** persist the cleared counter by themselves.
The reset is COMMITTED by a **clean power-button shutdown**, in this exact order:

1. **Release the USB handle first** (close the libusb device). The CLI does this
   when the `--execute` op returns.
2. **Press the printer's power button** for a normal shutdown.

The clean shutdown lets the **printhead park** and the firmware **flush the cleared
EEPROM page**. This is the verbatim commit instruction the op surfaces
(`COMMIT_INSTRUCTION` in `ops.py`, echoed as `commit_step` in both the dry-run and
execute CLI logs):

> NEXT STEP TO COMMIT: release the USB handle, then perform a CLEAN POWER-BUTTON
> shutdown so the printhead parks and the cleared counter is flushed to EEPROM. An
> abrupt UNPLUG does NOT commit the reset.

**Why an abrupt unplug fails:** pulling power (or yanking USB power) skips the park
+ flush — the printhead never parks and the EEPROM page is not written back, so the
counter is not persisted and 5B00 returns on next boot. **Always use the power
button.** This was the single most important hardware lesson of the validated run.

---

## 5. Running it (CLI)

### Dry-run (default, no USB touched)

```
canon-megatank reset-native
```

Loads the real SSOT `derived_template`, builds the Lane A encoder, enciphers the
validated frames, and logs `reset_native.dry_run` with the per-step wire bytes (the
two `set_command` wires are the 23-byte `85 00 00 || payload(20)` form), the
status, and `commit_step`. Consults no gate, opens no device.

### Execute (GATED — real write)

```
canon-megatank reset-native --execute --accept-derived
```

Opens `04a9:12fe`, wraps `dev.control_transfer` in `ServiceModeTransport`, and
drives `reset_absorber_wicreset(execute=True, keyword_min_len=3, keyword_pad_to=4)`
inside `write_lock(serial)` + a write-budget charge. Useful flags: `--region`
(default `common`), `--no-verify-readback`, `--timeout-ms`, `--product-id`.

On success it logs `reset_native.ok` with the (padded) keyword, the executed steps,
the summary, and `commit_step`. **Then perform §4½.**

### The gate ladder (runs IN ORDER on every `--execute`; no device touch if any refuses)

1. **UUID isolation** — runtime fingerprint vs the locked `test_unit` UUID. Wrong
   unit → refuse, touch nothing.
2. **Validation status** — `absorber_reset.status` must be `verified-captured`. The
   shipped SSOT is `derived-unvalidated` (§7), so `--execute` HARD-STOPS with
   `ResetNotValidatedError` unless `--accept-derived` is passed (one-run override,
   logged loudly as `[accept_derived OVERRIDE]`; does NOT mutate the SSOT).
3. **EEPROM dump** — `eeprom_dump_done` must be True (rollback baseline);
   `accept_derived` does NOT bypass this.
4. **Write budget** — `charge()` at the cap before any transfer.
5. **Lockfile** — the CLI wraps the op in `write_lock(serial)`.
6. **Live-keyword guard (R1)** — a `get_keyword` reply shorter than
   `keyword_min_len` HARD-STOPS before any `set_command` write. `keyword_pad_to`
   only pads a valid `>=`min-len short read; it does NOT relax this guard.

---

## 6. WHY it works (cloud-independence)

The reset bytes are built **entirely locally**. The earlier "fetched from cloud"
belief was a misread of WICReset's architecture
(`docs/research/wicreset-cloud-vs-local-template.md`):

- The per-model command template lives in a **bundled, PE-embedded device
  database** (`APP.BIN`/`DATA` resource → decompresses to `devices.xml`), loaded at
  startup. **No internet is required to obtain it** — the embedded resource is the
  guaranteed-present floor.
- The cloud has only three roles, **none of which supplies the device-bound
  bytes**: a key-validation **boolean** gate (`QUERY_KEYS` — authorizes, carries no
  bytes), an **optional** device-list refresh (`network/enabled`-gated superset),
  and a post-reset accounting report. None sources the reset template at reset time.
- We recovered the template from the decrypted `devices.xml`
  (`/tmp/appbin_out/devices.xml`), cracked the functor-2 write cipher (the buffer
  role swap, §3), and reproduce WICReset's exact frames ourselves. The only runtime
  input is the live device keyword read over USB in service mode (§3 step 2).

So the native tool needs **no key, no cloud call, no Windows tool, no VM** — just
the embedded-derived template + the local cipher + one live keyword read.

---

## 7. Verification — the 1865 re-enumeration

The proof the reset took:

1. After step 4 + the clean power-button shutdown (§4½), the printer **reboots out
   of service mode**.
2. It **re-enumerates as `04a9:1865`** (normal mode) instead of `04a9:12fe`
   (service mode). Confirm with `lsusb`.
3. The 5B00 / `marker-waste-full-error` is gone — IPP `get-printer-attributes`
   reports `printer-state = idle` (not `stopped`), no `markerWasteInkReceptacleFull`
   alert.

The `04a9:1865` re-enumeration is the at-a-glance signal that the printer left
service mode in a healthy state. Contrast the earlier failed bulk write, which
ACKed but left the printer in `marker-waste-full-error` across a power-cycle
(`docs/runbook/live-reset-write-2026-05-31.md`).

> **SSOT status stays `derived-unvalidated`.** Per repo convention, the
> `verified-captured` promotion is a manual, per-physical-unit decision gated on a
> pads-installed validation run with a fresh EEPROM baseline — not an automatic flip
> from one debug-unit success. `--execute` therefore still requires `--accept-derived`
> on the shipped SSOT. Promote by hand after a clean, pads-installed run.

---

## 8. Ground-truth frame (the anchor — assert these byte-exact)

For the real captured live keyword `e4 7c 5a` → padded `e4 7c 5a 00` → bound
`00 35 a9 09`, both code paths (`build_encoder('canon-g6020')` /
`load_method_from_ssot`, and `scripts/canon_sr5_cipher.encode_command(method_no=3)`)
reproduce the WICReset captured frames **byte-exact (23/23)**:

```
SELECTOR  set_command 10 07 7c
  850000dbbb006759a1b01f842fd583044a3ac351d2b1ef       (23 bytes)

CLEAR     set_command 0d 00 00   ← the 5B00 write
  8500004dbb006759a1b01f842fd58319a83a627bafb1ef       (23 bytes)
```

These match `printers/canon-g6020/maintenance.yaml`
`supported.absorber_reset.derived_sequence.hardware_validated_frames`
(`set_command_select` / `set_command_reset`) and WICReset's real captured wire
frames. They were re-confirmed against `/tmp/appbin_out/devices.xml` while writing
this runbook.

> The frames change with the live keyword (device binding): the bytes above are the
> `e4 7c 5a 00` form. On any run, `seed_keyword(live)` reseeds the functor-2 SEED so
> the 20-byte payload re-derives for that printer. The template-default-keyword form
> (`4d b6 ab 00`) is the key-free derivation, NOT what goes on the wire live.

---

## 9. Reference (validated artifacts)

- **CLI:** `canon-megatank reset-native` (`src/canon_megatank/main.py::cmd_reset_native`).
- **Op + commit:** `src/canon_megatank/ops.py::reset_absorber_wicreset`,
  `COMMIT_INSTRUCTION`.
- **Transport:** `src/canon_megatank/protocol/servicemode_transport.py`
  (VENDOR_SET 0x41 OUT / VENDOR_GET 0xC1 IN, frame-shape routing).
- **Cipher:** `src/canon_megatank/protocol/wicreset.py`
  (`functor3_encrypt`, `envelope3`, `functor2_transform`, `bind_keyword`,
  `build_encoder`), mirrored in `scripts/canon_sr5_cipher.py`.
- **SSOT:** `printers/canon-g6020/maintenance.yaml`
  (`supported.absorber_reset.derived_sequence.hardware_validated_frames`).
- **Transport RE:** `docs/research/usbprint-vendor-urb-mapping.md` §7.
- **Cloud reconciliation:** `docs/research/wicreset-cloud-vs-local-template.md`.
- **Native reference run:** `native_reset.py` on mbp-13 (the validated sequence).
- **Failed bulk dead-end (contrast):** `docs/runbook/live-reset-write-2026-05-31.md`.
