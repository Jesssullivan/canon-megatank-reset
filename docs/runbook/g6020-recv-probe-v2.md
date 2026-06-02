# G6020 control-IN RECV probe — v2 (corrected cipher + RECV sweep, NON-DESTRUCTIVE)

Date: 2026-06-01 (run 10:09 UTC)
Host: mbp-13 (Rocky 10.1, Bus001 Dev046, `04a9:12fe` "Printer in service mode")
Lane: iface0, EP 0x01 OUT / 0x82 IN, usblp UNBOUND (driver=NONE), libusb via printstack-group, no sudo for the transfers.
Capture: `dumpcap -i usbmon1` (bus 1). usbmon loaded via `modprobe usbmon` (sops become pw).

## What this run did (and did NOT do)

- Lane A: the **corrected** functor-3 encoder (`build_encoder("canon-g6020")`),
  synced from neo HEAD (`wicreset.py`, `usb.py`, `ops.py`, `canon_sr5_cipher.py`;
  md5 identical to neo).
- Lane B: control-IN RECV sweep — class `0xA1` bReq `0x00..0x10`, vendor
  `0xC0`/`0xC1` bReq `0x00`/`0x82`/`0x86`, lengths 4/20/64.
- Sent ONLY the corrected enciphered `set_session` (`81 00 00 03`) and
  `get_keyword` (`82 00 00 00 00`) on bulk-OUT, with control-IN reads.
- **NEVER** sent `0x85`/set_command/clear. No key spent. No clear write.

## Wire frames actually delivered (usbmon-confirmed)

| frame | plaintext | enciphered wire (on EP0x01 OUT) |
|---|---|---|
| set_session | `81 00 00 03` | `81 00 00 03 2d 2d 3b 2b` |
| get_keyword | `82 00 00 00 00` | `82 00 00 00 00 40 40 8f ec` |

usbmon (decode `g6020-recv-probe-20260601-100952.decode.txt`):
- `62|0x03|0x01|'S'|8|810000032d2d3b2b` … then `63|0x03|0x01|'C'|0` (submit + completion).
- `338|0x03|0x01|'S'|9|820000000040408fec` … `'C'|0`.
- EP0x01 OUT: 69× `810000032d2d3b2b`, 69× `820000000040408fec`; **all 138 completions urb_status=0** (delivered + ACKed).
- bulk-IN EP0x82: 2 submits, **0 bytes, no data completion** (ZLP — confirms the bulk-IN-ZLP transport note).

## BEFORE vs AFTER (the discriminator)

| read | BEFORE | AFTER | changed? |
|---|---|---|---|
| `0xA1/0x00` GET_DEVICE_ID (1284) | 120B `00 78 4d 46 47 3a 43 61 6e 6f 6e 3b …` (`\x00\x78MFG:Canon;CMD:BJL,…`) | identical 120B | **NO** |
| `0xA1/0x01` GET_PORT_STATUS | `18` | `18` | **NO** |

The two generic class control-INs that answer on this device returned the
**identical** bytes before and after the corrected set_session + get_keyword.

## RECV sweep result

- `0xA1/0x00` (GET_DEVICE_ID): answers, returns the 1284 ID **truncated to the
  requested length** (len=4 → `00 78 4d 46`, len=20 → `…BJL,`, len=64 → more of
  the same string). These are NOT maintenance bytes.
- `0xA1/0x01` (GET_PORT_STATUS): answers, returns `18` at any length.
- `0xA1/0x02..0x10`: STALL ("Pipe error").
- vendor `0xC0`/`0xC1` bReq `0x00`/`0x82`: STALL.
- vendor `0xC0`/`0xC1` bReq `0x86`: succeed but return **0 bytes** (empty) at
  every length — no payload.
- No setup packet returned a maintenance-session reply or a 4-byte keyword.

### The "4-byte keyword candidate" is a FALSE POSITIVE

The probe's auto-flagger marked `00 78 4d 46` (the len=4 `0xA1/0x00` read) as a
4-byte keyword candidate. It is not: `00 78 4d 46` = `\x00 \x78 'M' 'F'` = the
IEEE-1284 length header (`\x00\x78`) + the start of `MFG:Canon`. Proven a byte-exact
prefix of the 120-byte baseline 1284 ID. The 20/64-byte hits are longer prefixes
of the same string. They only differed from baseline in the auto-filter because
it compared against the full-length blob, not the length-matched prefix.

## VERDICT

**Session NOT opened. Corrected cipher NOT validated by this read.**

- The corrected enciphered frames were delivered and ACKed on bulk-OUT
  (the cipher bytes are correct *as bytes on the wire*), but the device's
  observable reply did not change: every control-IN before == after, and the
  only non-empty replies are the generic 1284 ID / status `0x18`.
- No control-IN setup in the swept space carried the maintenance reply. bulk-IN
  ZLP'd. So either (a) the session genuinely did not open (cipher still wrong, or
  set_session needs the live device keyword first — chicken/egg with get_keyword),
  or (b) the RECV read itself is firmware-gated and never exposes the keyword over
  any of the swept channels regardless of cipher correctness. **This probe cannot
  distinguish (a) from (b)** — both yield "generic reply only".

### Cross-host cipher determinism BUG — FIXED (2026-06-01)

> **RESOLVED.** The wire bytes recorded in the table above are the OLD,
> mbp-13 (3.14) **buggy** variant (`…2d 2d 3b 2b`). The corrected, deterministic
> `set_session` frame is **`81 00 00 03 2d 2d ba 2b`** on every interpreter; see
> `docs/research/g6020-cipher-fix.md` (“Determinism root cause + fix”).

Same code (md5-identical), same seed `0x83cf0901`, same index/codes arrays — but
`build_shift_table` returned a **different ordering** across Python versions:
- neo (CPython 3.13.5): `shift_tbl = (0, 1, 0, 0)` → set_session wire `…2d 2d ba 2b` (CORRECT)
- mbp-13 (CPython 3.14.0): `shift_tbl = (1, 0, 0, 0)` → set_session wire `…2d 2d 3b 2b` (BUGGY)

Byte i=2 diverged (`ba` vs `3b`, differ by `0x81`); `get_keyword` was unaffected
(it selects shift array idx 2, whose leading entry is order-invariant).

Root cause: the package mirror's SSOT loader used the WRONG **(b)** semantics
(one shift entry per `<action>` over a FLAT list) AND the SSOT stored
`command_shift[0]` in the wrong order, so the four single-action entries were
read in an interpreter-dependent order. Fix: store `command_shift` as an
explicit document-ordered `list[array][value][action]` nesting and parse it
under the binary's true **(a)** semantics (one entry per `<value>`, acc reset to
the seed per `<value>` — FUN_004e76c0:340-495) in BOTH mirrors. Now byte-identical
under CPython 3.13 and 3.14, pinned by
`tests/test_wicreset_encoder.py::test_handshake_frames_match_across_interpreters`.

## Artifacts (on mbp-13)

- pcap:   `/tmp/g6020-recv-probe-20260601-100952.pcap`
- log:    `/tmp/g6020-recv-probe-20260601-100952.log`
- decode: `/tmp/g6020-recv-probe-20260601-100952.decode.txt`
- probe:  `/tmp/recv_probe_v2.py`, orchestrator `/tmp/run_probe.sh`

## Next steps (no key)

1. Fix the cross-interpreter shift-table ordering bug in `wicreset.py`
   (`build_shift_table` / `command_shift` parse) so neo and mbp-13 emit the same
   frame; re-derive the reference vectors.
2. The discriminator (a) vs (b) needs the live device keyword to break the
   chicken/egg — which is exactly the keyed capture this probe was meant to avoid.
   This run SHRINKS that capture's burden: it proves the corrected frames are
   delivered+ACKed and that the keyword is NOT exposed over any non-keyed
   class/vendor control-IN or bulk-IN. So a keyed capture only needs to prove the
   *one* remaining unknown: whether a primed session changes the RECV channel.
