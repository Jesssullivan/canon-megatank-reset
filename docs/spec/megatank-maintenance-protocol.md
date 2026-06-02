# Canon MegaTank maintenance protocol — validated formal spec

**Validated reference code:** `src/canon_megatank/protocol/wicreset.py`
(cipher), `scripts/canon_sr5_cipher.py` (mirror encoder),
`src/canon_megatank/protocol/servicemode_transport.py` (transport),
`src/canon_megatank/ops.py` (gated session). **Proofs:**
`tests/test_cipher_groundtruth_regression.py`,
`tests/test_canon_sr5_cipher.py`, `tests/test_servicemode_transport.py`,
`tests/test_protocol_model.py` (Hypothesis). **SSOT:**
`printers/canon-g6020/maintenance.yaml`.

This document specifies the **hardware-validated** Canon G6020 service-mode
absorber-reset protocol. It agrees factually with the
[field guide](../research/canon-service-mode-field-guide.md) (the model-agnostic
RE method) and the [reference runbook](../runbook/g6020-native-reset.md) (the
end-to-end operator procedure); all three describe the same protocol.

## 1. Status

**Validated, hardware-confirmed (2026-06-01).** A pure-libusb native clear built
from the protocol below cleared 5B00 (`markerWasteInkReceptacleFull`) on the
dedicated debug G6020 — no WICReset, no VM, no Wine, no cloud call, no purchased
key. The printer rebooted out of service mode and **re-enumerated as the normal
PID `04a9:1865`** after a clean power-button shutdown, and IPP reported
`printer-state = idle`.

The write cipher reproduces WICReset's real captured frames **byte-exact (23/23)**
through both code mirrors (§4), and the property tests pass offline with no key
or device. The transport (§2) and reset payload (§4) were confirmed on the wire
and supersede the earlier normal-mode `usbscan`/bulk hypothesis (which ACK'd but
never cleared 5B00).

> The shipped SSOT keeps `absorber_reset.status: derived-unvalidated` by repo
> convention: the `verified-captured` promotion is a manual, per-physical-unit
> decision gated on a pads-installed validation run with a fresh EEPROM baseline,
> not an automatic flip from one debug-unit success. `--execute` therefore still
> requires the logged one-run `--accept-derived` override on the shipped SSOT.

## 2. Transport — EP0 vendor control transfers

Service mode is a device-side firmware state entered by a front-panel button
combo (power + resume taps); it cannot be driven over USB. On entry the printer
**re-enumerates with a different USB identity**: normal `04a9:1865` (6
interfaces) → **service `04a9:12fe`** (single printer-class interface). The
native tool opens the service PID on interface 0, alt 0; EP0 control needs no
bulk-interface claim.

Every maintenance frame is an **EP0 VENDOR control transfer**, reproducing what
Windows `usbprint.sys` emits for its `VENDOR_SET_COMMAND` (IOCTL `0x220038`) and
`VENDOR_GET_COMMAND` (`0x22003c`) IOCTLs:

| direction | bmRequestType | bRequest | wValue | wIndex | data stage |
|---|---|---|---|---|---|
| **SET** (host→device) | `0x41` (vendor, interface, OUT) | `frame[0]` | `(frame[1]<<8)\|frame[2]` | `0x0000` | **the entire frame, verbatim** |
| **GET** (device→host) | `0xC1` (vendor, interface, IN) | `frame[0]` | `(frame[1]<<8)\|frame[2]` | `0x0000` | reply of the requested length |

The first three bytes seed `bRequest`/`wValue` **and remain the first three bytes
of the data stage** — the whole `InputBuffer` is the OUT data with
`wLength = len(frame)`. **Never split the header from the payload**; earlier
native attempts STALLed (libusb "Pipe error") precisely because they stripped the
prefix. `usbprint.sys` also caps a control buffer at one page (4096 bytes), so a
large read must be clamped to ≤4096.

`ServiceModeTransport.send_and_receive` (`servicemode_transport.py`) routes by
**frame shape**: a bare 3-byte read header (`82 00 00` / `86 00 00`) goes
VENDOR_GET IN; any longer (write-shaped) frame goes VENDOR_SET OUT and returns
`b''`. Reads are **SEND-primed, not free-running** — a cold bare RECV with nothing
armed times out (errno 110).

Setup builders: `vendor_set_setup`, `vendor_get_setup`, `get_1284_id_setup`.

## 3. Session — the four-step ordered handshake

```
1. set_session   81 00 00 03            OUT 0x41/0x81   open the service session (enciphered, §4)
2. get_keyword   82 00 00               IN  0xC1/0x82   -> live 3-byte device keyword
3. set_command   85 00 00 | 10 07 7c    OUT 0x41/0x85   waste-row SELECTOR (23-byte enciphered frame)
4. set_command   85 00 00 | 0d 00 00    OUT 0x41/0x85   'common' CLEAR  ← THE 5B00 WRITE
   get_command   86 00 00               IN  0xC1/0x86   read-back (EMPTY by design)
```

State machine:

```
   ┌──────────────┐ set_session(0x81)   ┌─────────┐ get_keyword(0x82) ┌────────┐
   │ DISCONNECTED │ ──────────────────▶ │ SESSION │ ────────────────▶ │ KEYED  │
   └──────────────┘                     └─────────┘  live keyword →   └────────┘
          ▲                                          seed encoder         │
   close  │                                                               │ set_command SELECTOR (0x85, 10 07 7c)
   + clean│ power-button                                                  ▼
   shutdown (commit)                     ┌──────────┐ set_command       ┌──────────┐
   ┌──────────────┐  get_command(0x86)   │ COMMITTED │ CLEAR(0x85, 0d00) │ SELECTED │
   │  RE-ENUM 1865 │◀── (empty read) ─── │  (in-RAM) │◀───────────────── │          │
   └──────────────┘                      └──────────┘                    └──────────┘
```

- **Step 2 keyword is the ONLY runtime input.** Everything else is statically
  derived. The reply is a fresh per-session 3-byte value (e.g. `e4 7c 5a`),
  right-padded to 4 (`e4 7c 5a 00`) and fed to `encoder.seed_keyword`. The
  keyword read MUST precede the writes — it keys them to the live session.
- **Step 3 SELECTOR** (`10 07 7c`) addresses the `common` waste row; **step 4
  CLEAR** (`0d 00 00`) is the operand that zeroes the absorber counter (the 5B00
  write).
- **`get_command` (0x86) returns EMPTY, and there is no finalize command.** This
  is by design — an ACK is acceptance, not a commit. Do **not** block, retry, or
  fail on an empty `0x86`. Proven by
  `test_native_reset_empty_get_command_does_not_gate_the_clear` and
  `test_empty_get_command_readback_does_not_fail_the_clear`.
- **Commit is a clean power-button shutdown** (not the writes alone, not an
  unplug): release the USB handle, then power off with the button so the
  printhead parks and the firmware flushes the cleared EEPROM page. An abrupt
  unplug skips the flush and 5B00 returns. The op surfaces this verbatim as
  `COMMIT_INSTRUCTION` in `ops.py`.

## 4. Write cipher — functor-3 envelope + functor-2 role-swap (23/23 byte-exact)

The genuine `set_command` is enciphered. The decisive correction over earlier
attempts is a **buffer-role swap**: the functor-2 transform's SUBJECT is the
20-byte functor-3 **envelope** and its SEED is the 4-byte **bound keyword** —
*not* the keyword seeded by the envelope. With that fix the encoder emits all 20
payload bytes and reproduces the captured frames exactly.

```
app      = 85 00 00 || operand                  (e.g. 85 00 00 10 07 7c)
envelope = envelope3(method=3, app)              (20 bytes)
payload  = functor2_transform(method, envelope, seed_source=bound_keyword)   (20 bytes)
wire     = 85 00 00 || payload                   (23 bytes)
```

- **`envelope3`** (`wicreset.py`) is the deterministic 20-byte functor-3 envelope:
  `[00 12 01 frame[3]]` + 16 fixed MSVC-LCG bytes (seed `0x12345678`), then the
  function-block `<special>` overwrite (`env[4+off]:=val`) and the `<indexes>`
  payload scatter for the block keyed by `frame[3]`. The operand therefore rides
  the envelope, so SELECTOR ≠ CLEAR on the wire.
- **`functor2_transform`** walks the index/codes/shift permutation tables per
  output position with a keystream byte `(seed >> shift) ^ code`, where
  `seed = seed_fold(envelope)`. It is provably invertible (send vs recv differ
  only by which buffer indexes the XOR), so the firmware decrypts our ciphertext
  back to a legitimate command. Keystream derives from a CANON-SR5 schedule.
- **`bind_keyword`** maps the live padded keyword to the bound SEED. For the
  captured keyword `e4 7c 5a 00` it yields `00 35 a9 09`.
- **set_session** is enciphered the same way; **get_keyword/get_command** are
  bare 3-byte READ headers that go on the wire verbatim (the RECV reply is what
  matters).

Ground-truth anchor — for live keyword `e4 7c 5a 00` → bound `00 35 a9 09`, both
`build_encoder('canon-g6020')`/`load_method_from_ssot` and
`scripts/canon_sr5_cipher.encode_command(method_no=3)` emit, byte-exact (23/23):

```
SELECTOR  85 00 00 db bb 00 67 59 a1 b0 1f 84 2f d5 83 04 4a 3a c3 51 d2 b1 ef
CLEAR     85 00 00 4d bb 00 67 59 a1 b0 1f 84 2f d5 83 19 a8 3a 62 7b af b1 ef   ← 5B00 write
```

These equal `maintenance.yaml`
`supported.absorber_reset.derived_sequence.hardware_validated_frames` and
WICReset's real captured wire frames. The frames change with the live keyword
(device binding); a fresh `seed_keyword(live)` re-derives the 20-byte payload per
printer. Pinned by `test_cipher_groundtruth_regression.py` (both mirrors agree
byte-for-byte) and `test_canon_sr5_cipher.py`.

## 5. Template provenance — APP.BIN → devices.xml

The per-model command template is **bundled, PE-embedded, cloud-independent**.
WICReset ships its model DB inside an encrypted `APP.BIN` container; the offline
decrypt path is: strip footer → **3DES-EDE3-CBC** (zero key/IV from empty-string
construction) → strip pad → zlib inflate → `devices.xml`
(`scripts/appbin_decrypt.py`). From the decrypted `devices.xml`
(sha256 `6031555f…d86db3`) we resolve the G6000-series row (no G6020 literal;
G6020 ∈ G6000 series): `<method>3</method>`, functor-3, `support=query;waste:common`
(the family clears only the `common` absorber, i.e. the 5B00 main). The session
headers, the functor-3 keystream/permutation/shift tables, and the per-code
function blocks all come straight from that decrypted DB and are mirrored into
the SSOT `derived_template`. The reference encoder builds its `SR5Method` from the
SSOT (`load_method_from_ssot`), never from `devices.xml` at runtime.

## 6. DRM — licensing-only, off the repair data path

By decompile, **zero cloud bytes feed the reset payload, the keyword binding, or
the completion test**. The vendor cloud has only three roles, none of which
sources device-bound bytes: a key-validation **boolean** gate (`QUERY_KEYS` —
authorizes, carries no bytes), an **optional** device-list refresh (a
`network/enabled`-gated superset of the always-present embedded DB), and a
post-reset accounting report. The Service Tool's license/anti-tamper checks
likewise gate **whether** a command runs, not **what** bytes it sends. The native
tool needs no key and no network: embedded-derived template + local cipher + one
live keyword read.

## 7. Implementation + tests (validated)

| Concern | Code | Tests |
|---|---|---|
| Transport (0x41 OUT / 0xC1 IN, frame-shape routing, 1284-id) | `protocol/servicemode_transport.py` | `tests/test_servicemode_transport.py` |
| Write cipher (`envelope3`, `functor2_transform`, `functor3_encrypt`, `bind_keyword`, `build_encoder`) | `protocol/wicreset.py` | `tests/test_canon_sr5_cipher.py`, `tests/test_cipher_groundtruth_regression.py` |
| Cipher mirror / `devices.xml` reference encoder | `scripts/canon_sr5_cipher.py` | `tests/test_cipher_groundtruth_regression.py` (both paths agree 23/23) |
| Gated 4-step session + commit | `ops.py::reset_absorber_wicreset`, `COMMIT_INSTRUCTION` | `tests/test_cipher_groundtruth_regression.py` (native-sequence frames), `tests/test_reset.py` |
| CLI | `main.py::cmd_reset_native` (`canon-megatank reset-native [--execute --accept-derived]`) | `tests/test_cli_reset_native.py` |

The `--execute` gate ladder (UUID isolation → validation status → EEPROM dump →
write budget → lockfile → live-keyword guard) is detailed in the runbook §5.

## 8. Generic invariants (offline, no key)

These are protocol-shape invariants that hold independent of the specific cipher.
They are encoded by `src/canon_megatank/protocol/model.py` and asserted by
`tests/test_protocol_model.py` (Hypothesis):

- **Round-trip:** `decode_frame(encode_send(c,a,p)) == (c,a,p)`.
- **Determinism:** `encode_send` and `derive_reset_frame` are pure functions.
- **Byte order / length:** `arg` serializes big-endian; the header is exactly 3
  bytes; a SEND frame is `3 + len(payload)`.
- **Idempotency:** `apply_reset` zeroes the counter from any state and is
  re-applicable (`apply_reset(apply_reset(s)) == apply_reset(s)`) — re-issuing
  the clear is safe.
- **Write-budget monotonicity:** `consumed` only grows, `remaining` only shrinks,
  `exhausted` latches at the cap (lockfile gate).
- **UUID gate:** only the locked `test_unit` UUID permits a write
  (`uuid_permits_write`).
- **No SSOT drift:** model transport constants `==` `maintenance.yaml`.

These remain a useful methodology record and a guard rail; the runnable native
reset is the cipher + transport + session of §2–§4, validated on hardware.
