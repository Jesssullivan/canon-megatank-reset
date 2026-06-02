# G6020 absorber-reset — cross-validation + live-run risk (Lane C)

**Date:** 2026-06-01 · **Status:** `cross-validated-derivation` (still
`derived-unvalidated` at the SSOT gate; no live write fired)
**Inputs joined here:**

- the derived sequence — `docs/research/wicreset-g6020-reset-derived.md`
- the cipher machinery — `docs/research/wicreset-g6020-reset-template.md`,
  `ghidra/wicreset_template_cipher.py`
- the v5103 static RE — `docs/research/servicetool-v5103-servicemode-reset-re.md`
- the cleartext template DB — `/tmp/appbin_out/devices.xml`
  (`sha256 6031555f…d86db3`)
- every prior on-wire capture under `captures/` (decoded here as usbmon /
  DLT 220, since `tshark` is absent on neo — see §2 method note)

This doc does three things: (1) explains **definitively** why the v5103
`0x85`-only plaintext attempt failed and the WICReset path clears; (2)
**cross-checks** the derived opcodes/prefixes/envelope against the bytes we
actually captured; (3) reconciles the **two different waste-addressing
schemes** and lists the **concrete live-run risks** with in-session
detection/handling. RECOVERED = read verbatim from `devices.xml` or a capture;
INFERRED = reasoned from RE.

---

## 1. Why v5103 `0x85 [00 03 01 03 07]` FAILED and WICReset clears — DEFINITIVE

Three independent gates each, on their own, doom the v5103 frame. WICReset
satisfies all three.

### 1a. Opcode / payload-shape mismatch (the *command set* is different)

The v5103 frame carries the **Service Tool** absorber payload
`00 03 01 03 07` (RECOVERED: `servicetool-v5103-servicemode-reset-re.md:184,207`
— `payload[5] = {0x00,0x03,flags,0x03,idx}`, `flags 0x01`, main absorber
`idx=0x07`). That is the *Service Tool* group-7 dispatcher's payload shape.

WICReset's G6000 template does **not** use a 5-byte `[00 03 …]` payload for the
absorber at all. Its waste reset is a **two-command tuple** (RECOVERED,
`devices.xml:43807`):

```
set_command(85 …) carrying  10 07 7C      <- waste selector
set_command(85 …) carrying  0D 00 00      <- 'common' reset operand (the 5B00 clear)
```

So even though both frames share the literal opcode byte `0x85`, the *operand
grammar after the prefix* is from two unrelated tools. Sending the Service
Tool's `[00 03 01 03 07]` under a WICReset-style transport (or vice-versa) is
sending a payload the receiving command interpreter does not parse. **Opcode set:
DIFFERENT.** (INFERRED that the firmware rejects the foreign operand grammar;
RECOVERED that the two grammars are distinct.)

### 1b. No session — the device was never in a command-accepting state

WICReset's clear is an **ordered four-step session**:

```
set_session  81 00 00 03    (RECOVERED devices.xml:43504)  -> open
get_keyword  82 00 00 00 00 (RECOVERED devices.xml:43506)  -> read live keyword
set_command  85 …(10 07 7C) (RECOVERED devices.xml:43508 + :43807) -> select
set_command  85 …(0D 00 00) (the write)
[get_command 86 … verify]
```

The v5103 attempt (RECOVERED on-wire, see §2: `ctrl-reset-sample-20260601`
pkt#12) sent a **single** `0x85` frame with **no preceding `set_session`
(`81 00 00 03`) and no `get_keyword`**. The `0x81` session byte never appears in
that capture. A G6000-family unit only accepts maintenance writes inside an
opened session; an unsolicited `0x85` lands with no session context.
**Session requirement: UNMET by v5103, MET by WICReset.**

### 1c. The cipher gate — frames must be functor-3 enciphered

This is the decisive one. The G6000 family device row is
`method=3` (RECOVERED `devices.xml:43549`), which selects the encoder
`<handler>0x03</handler>` / `<functor>0x03</functor>` block (RECOVERED
`devices.xml:43690-43691`). Every frame on the wire must therefore be passed
through **functor-3**: the 20-byte deterministic LCG envelope
(`00 12 01 <cmd>` + 16 fixed MSVC-rand bytes seeded `0x12345678`) prepended by
`functor_encryption_003`, then the symmetric XOR keystream of
`functor_implementation` (over `command.index/codes/shift`), with the keystream
seeded by `functor_initialization` XOR-ing in the **live device keyword** read at
`get_keyword`.

The v5103 frame is **raw plaintext** — `00 03 01 03 07`, "verbatim, no
transform" (RECOVERED `servicetool-v5103-servicemode-reset-re.md:41,207`). It is
neither enveloped (`00 12 01 …` absent) nor XOR-keystreamed nor keyed to the
session keyword. A firmware that expects functor-3 ciphertext sees noise.
**Cipher gate: UNMET by v5103, MET by WICReset.**

> **Bottom line.** v5103 failed on **all three** axes at once — wrong operand
> grammar under `0x85`, no `0x81` session, and zero enciphering. WICReset clears
> because it opens the `81 00 00 03` session, reads the keyword via `82 …`,
> seeds the functor-3 keystream with it, and sends the `10 07 7C` + `0D 00 00`
> tuple as functor-3 **ciphertext**. The opcode byte being `0x85` in both is a
> coincidence of the shared command byte, not evidence the v5103 frame was
> "close."

---

## 2. Cross-check against the captured pcaps on neo

**Method note.** `tshark` is **not installed on neo** (so `src/canon_megatank/pcap.py`,
a tshark wrapper, cannot run). All `captures/*.pcapng[.gz]` are
`DLT_USB_LINUX_MMAPPED` (linktype 220, usbmon mmapped — confirmed by reading
each IDB), **not** the USBPcap format the prefix-scan first assumed. They were
re-decoded with a 64-byte-usbmon-header parser (`/tmp/usbmon.py`, transient).
Endpoints, transfer types and payloads below are RECOVERED from that decode.

### 2a. Do the derived prefixes / opcodes appear on the wire?

Yes — the **WICReset session prefixes appear in a prior experimental capture**,
and the **v5103 plaintext frame appears in two captures**:

| capture | what it shows | bearing |
|---|---|---|
| `captures/live/handshake-exp-20260531-062747.pcapng` | BULK on **iface-4 EP 0x03 OUT / 0x86 IN** (the SSOT-pinned maintenance lane): `81000000` → `820000` → read `86 IN` → `850000123400000100` → `8500000003010307` → read `86 IN` | the closest prior experiment to the WICReset path |
| `captures/ctrl-reset-sample-20260601.pcapng` | pkt#12 a **control** transfer `bmRequest 40 85 0000 0000 0005` data `00 03 01 03 07` | the v5103-style plaintext absorber frame on the wire |
| `captures/live/reset-derived-20260531-052948.pcapng` | pkt#8 BULK `0x03 OUT` `8500000003010307`; pkt#7/#9 carry `…0D00…` fragments inside the **config descriptor**, not command frames | a derived-frame dry attempt; still plaintext |
| `captures/v5103-wine-launch-no-clicks-20260528-222034.pcapng` | enumeration only (descriptors of 4 devices); no maintenance frames | baseline |

Key reads from `handshake-exp` (RECOVERED):

- The session byte `0x81` **does** appear — but as `81 00 00 00`, **not** the
  template's `81 00 00 03` (RECOVERED `devices.xml:43504`). The `0x03` session
  argument is **missing**. (INFERRED: an incomplete/guessed session open.)
- `get_keyword` was sent as `820000` and the follow-up `86 IN` read returned
  **0 bytes** (pkt#16/#17). **The keyword read returned nothing.**
- The `0x85` frames (`850000123400000100`, `8500000003010307`) were sent as
  **plaintext** — no `00 12 01 …` envelope, no XOR. Every `86 IN` read-back
  returned **0 bytes** (pkt#22/#23, #28/#29).

So the prior live experiment used the **right endpoint** (iface-4 0x03/0x86,
matching `maintenance.yaml::usb_interface_layout`) but **plaintext frames with a
malformed session** — and the device answered **nothing** on every read. This is
direct on-wire corroboration of §1: without the `81 00 00 03` session arg and
functor-3 enciphering, the G6020 does not respond.

### 2b. Does the deterministic envelope `00 12 01 …` appear?

**No — and a prefix scan falsely suggests "yes," so this is called out
explicitly.** A naive byte search for `00 12 01` matches **every** capture, but
in **all** cases the match is the tail of the standard USB **device descriptor**
GET_DESCRIPTOR reply, e.g.
`1201 0002 0000 0040 a904 6518 …` (RECOVERED `handshake-exp` pkt#1) — that is
`bLength=0x12`, `bDescriptorType=0x01`, with the preceding `bcdUSB` low byte
`0x00` producing the spurious `00 12 01`. **The functor-3 LCG envelope head
`00 12 01 <cmd>` followed by the constant `e9 3f 0d a1 …` keystream is NOT
present in any capture** (the `e9 3f 0d a1` LCG signature never appears). i.e.
**we have never captured a real WICReset functor-3 frame** — every maintenance
frame we ever put on the wire was plaintext. The envelope remains RECOVERED from
static RE only (`ghidra/wicreset_template_cipher.py`), un-witnessed on-wire.

> Cross-val verdict: the captures **confirm** the opcodes (`0x81`, `0x82`,
> `0x85`, `0x86` all observed) and the maintenance endpoint (0x03/0x86), and they
> **confirm by negative result** that plaintext frames get zero response —
> exactly what the cipher-gate theory predicts. They do **not** independently
> witness the functor-3 envelope; that is the one piece resting purely on static
> RE, and is the thing the live validation run will witness for the first time.

---

## 3. Two waste-addressing schemes — which the G6020 honors

There are **two different addressing schemes** for the same physical absorber,
one per tool. They are NOT interchangeable.

| scheme | source | "main / single absorber" code | other codes |
|---|---|---|---|
| **WICReset** (`0D <nn> 00`, the 2nd byte of cmd2) | RECOVERED `devices.xml:43805-43810` | **`common = 0x00`** | platen `0x01`, black `0x03`, color `0x04`, away `0x05`, home `0x06` |
| **Service Tool v5103** (`idx` = byte 5 of `00 03 01 03 idx`) | RECOVERED `servicetool-v5103-…re.md:184,207` | **`Main = 0x07`** | Platen `0x00` |

Note the schemes **collide on the value `0x00`**: it means **`common` (the
absorber)** in WICReset but **`Platen`** in the Service Tool table. And `0x07`
means **Main** in Service Tool but is **out of range** for the WICReset waste
table (only 0x00,0x01,0x03,0x04,0x05,0x06 exist). They are **unrelated
encodings**; one cannot be substituted into the other's frame.

**Which does the G6020 firmware honor for our path?** The **WICReset scheme**,
because we are sending the **WICReset functor-3 command grammar** — and within
that grammar the G6000-family capability string is `support=query;waste:common`
(RECOVERED `devices.xml:43549`). The family exposes exactly **one** waste
counter, `common`, whose operand is **`0D 00 00`** (RECOVERED
`devices.xml:43807`). The G6020 is a single-absorber MegaTank; `common` is its
only (and therefore the correct) waste row. The other WICReset rows
(platen/black/color/away/home) are multi-absorber rows that the G6000 family
does not support and that `load_wicreset_frames(region=…)` will refuse
(`ops.py:757`).

> **Decision (RECOVERED + INFERRED):** for the G6020 send the WICReset
> **`common`** row → operand **`0D 00 00`**. Do **not** import the Service Tool
> `idx=0x07` value into the WICReset frame, and do **not** read the shared
> `0x00` as "Platen" — that cross-scheme reading is the trap. `common = 0x00`
> here is the single-absorber 5B00 clear.

---

## 4. Concrete risks for the one live validation run

Ordered by likelihood × blast radius. Each lists how to **detect in-session**
and how the encoder/ops path already handles (or must handle) it.

### R1 — keyword is the template default, not the live read (HIGH likelihood)

The functor-3 keystream is keyed by the **live device keyword** read at step 2
(`functor_initialization` XORs it in). The `<encoders>` method carries **no
`<value>`** (RECOVERED `devices.xml:43692-43694`) — only the `<resolution>`
method has the default `0x4D 0xB6 0xAB 0x00` (`devices.xml:43560`). If the
encoder ever falls back to that resolution default instead of the live keyword,
**every `set_command` ciphertext is wrong** and the clear silently no-ops (or
worse).

- **Detect:** assert `get_keyword` RECV is non-empty and the expected width
  before seeding. **The prior `handshake-exp` capture shows `86 IN` returning 0
  bytes** — a zero-length keyword is a real, observed failure mode.
- **Handle / GAP:** `ops.py:972-975` does
  `gk_reply = device.send_and_receive(…); encoder.seed_keyword(gk_reply)` with
  **no length/empty check** — `seed_keyword(b"")` would seed a degenerate key.
  **Add a guard:** refuse to proceed to step 3 unless `len(gk_reply) >= 4` (the
  keyword is 4 bytes per `keyword.codes`/`index` width). This is the single most
  important pre-write assertion to add before the live run.

### R2 — no EEPROM commit / flush after the two writes (MEDIUM)

Many Canon maintenance ops require a commit/flush (or a power-cycle) for the
EEPROM write to stick; the recovered template gives only the
`set_command(10 07 7C)` + `set_command(0D 00 00)` tuple and a `get_command`
read-back — **no explicit flush opcode**.

- **Detect:** after the two writes, issue `get_command` (`86 …`) and read the
  `statuses` row (`00`=success, `01`=not-ready, `FF`=unsupported — RECOVERED
  per the derived doc §5). Then re-read the waste counter (the `query;normal`
  row, §R3) and/or re-dump EEPROM and diff against the mandatory pre-flight dump
  (`ops.py:945` already requires `eeprom_dump_done`).
- **Handle:** `verify_readback=True` (default, `ops.py:991`) issues the
  `get_command`. If status ≠ `00` or the counter is unchanged, **treat as
  not-committed**: do a controlled power-cycle and re-read before declaring
  failure. Do not re-issue the write blindly (write-budget, `ops.py:954`).

### R3 — the `normal` row (`10 07 7C` + `15`) may be needed to read/exit (MEDIUM)

The `<query>` `normal` row `10 07 7C` + `0x15` (RECOVERED `devices.xml:43813`)
is the **status/read-back** query for the counter. It is **not** in the current
executed sequence (steps 1-5 use only `set_session`/`get_keyword`/two
`set_command`/`get_command`). If verification needs the counter value (to prove
0), the `normal` query is how to read it; it may also be the intended way to
leave the counter subsystem in a clean state.

- **Detect:** if `get_command` returns success but we cannot confirm the counter
  is zero, the `normal` query gives the live value.
- **Handle:** add an optional post-write `normal` read (functor-3 enciphered,
  same as the others) to confirm `common == 0`. It is a READ (`query`), not a
  write, so it does not touch the write budget. Note: `0x15` is a single-byte
  operand (no trailing `00`), unlike the `0D nn 00` waste operands — encode it
  exactly as `10 07 7C` then `15`.

### R4 — endpoint / transfer nuance (MEDIUM, partly de-risked)

The captures settle the endpoint question: the maintenance lane is **iface-4
BULK 0x03 OUT / 0x86 IN** (RECOVERED from `handshake-exp`, matching
`maintenance.yaml:66-67`), **not** the `iface0 EP 0x01/0x82` mentioned in some
older transport notes, and **not** a control transfer (the v5103 control-frame
in `ctrl-reset-sample` pkt#12 used `bmRequest 0x40` class-vendor OUT and got no
clear). Remaining nuances:

- **Detect:** confirm the claimed interface/EP at session open; verify each
  BULK write returns its full byte count and each read returns a sane length
  (not 0 — see R1).
- **Handle:** `ClaimedDevice` (`src/canon_megatank/usb.py`) must claim
  **interface 4** and use 0x03/0x86. If the printer-class interface (1) or
  ipp-usb interfaces (2,3) are bound by CUPS/ipp-usbd, detach/claim must target
  iface 4 only. A short read on `86 IN` is the canary that the wrong EP or an
  unentered service mode is in play.

### R5 — service mode not actually entered (MEDIUM)

The recovered USB path assumes the printer is in **service mode** (the SR5
entry: power + resume×5). If the unit is in normal mode, the maintenance
interface may enumerate differently or reject `set_session`.

- **Detect:** `set_session` (`81 00 00 03`) RECV should return a non-error
  status; a 0-byte or error reply means service mode is not active.
- **Handle:** gate step 3+ on a successful session open; abort cleanly (no
  writes) if `set_session` does not ACK. The `handshake-exp` zero-replies are
  consistent with *either* plaintext frames *or* not-in-service-mode — the live
  run must distinguish by sending the **correct enciphered** `81 00 00 03` after
  confirmed service-mode entry.

### R6 — single-shot keyword binding / session expiry (LOW)

The keyword is read once and seeds the encoder for the rest of the session. If
the session times out between `get_keyword` and the `set_command` writes, the
seeded keystream may desync.

- **Detect:** a `get_command` status of `01` (not-ready) after a previously
  successful open.
- **Handle:** run steps 2-5 back-to-back with a generous `timeout_ms`
  (`ops.py:820` default 5000); do not pause for operator input mid-session.

### R7 — first-ever real functor-3 frame on the wire (inherent)

Per §2b, **no capture has ever witnessed a real functor-3 enciphered frame** —
the envelope/keystream is RECOVERED from static RE only. The live run is the
first on-wire test of the cipher implementation itself (Lane A's
`encipher`/`seed_keyword`).

- **Detect:** in DRY-RUN (`execute=False`, `ops.py:883`), the enciphered wire
  bytes are printed without touching the device — eyeball that the first 4 bytes
  of each frame are `00 12 01 <cmd>` and bytes 4-19 are the constant LCG block
  `e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f`. A mismatch means the
  envelope is wrong **before** any device contact.
- **Handle:** require a clean DRY-RUN review (envelope + a known-keyword XOR
  round-trip self-test in the encoder) as a pre-condition of the `execute=True`
  run. Capture the live session (usbmon) so the first real functor-3 frame is
  recorded for the SSOT.

---

## 5. Gate posture (unchanged)

All findings here are **cross-validation of a derivation**; nothing promotes the
SSOT. `absorber_reset.status` stays `derived-unvalidated`
(`maintenance.yaml:98`); `reset_absorber_wicreset(execute=True)` HARD-STOPS until
status is `verified-captured` (`ops.py:934`), after the EEPROM-dump
(`ops.py:945`), write-budget (`ops.py:954`), UUID-isolation (`ops.py:924`) and
lockfile gates. No WICReset key was spent (pure derivation + capture re-decode).
The **one** code change this lane recommends before the live run is the **R1
keyword-length guard** in `reset_absorber_wicreset` (refuse to seed/clear on a
short/empty `get_keyword` reply) — the prior `handshake-exp` zero-length read
proves that failure mode is real.
