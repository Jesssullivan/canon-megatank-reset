# G6020 transport fix — RECV over control-IN, not bulk-IN (Lane B)

**Date:** 2026-06-01 · **Scope:** `src/canon_megatank/usb.py` (RECV half only) ·
**Device:** `04a9:12fe` (G6020 service mode) · **No device / no key needed for
this change** — it is a transport correction validated by unit tests; the live
confirmation is a separate probe step.

---

## TL;DR

The maintenance RECV used to read the reply from the **bulk-IN endpoint
(EP 0x82 / 0x86)**, which **always returns a zero-length packet (ZLP)** on the
live 12fe device — so every read came back empty and no session could ever be
confirmed. The decompile shows the WICReset RECV (`do_read_vendor`
`FUN_0052cab0` ⇒ `DeviceIoControl(0x22003c)`) is the **IN half of one combined
`DeviceIoControl`** whose `lpInBuffer` is the primed enciphered prefix and
`lpOutBuffer` is the 5000-byte reply — and on the live device that reply is
delivered over a **CONTROL-IN transfer on EP0**, not bulk-IN.

This change makes the RECV read over **control-IN** (`ctrl_transfer`) instead of
bulk-IN. The **SEND half is unchanged**: the enciphered prefix / request header
is still written (primed) on **bulk-OUT** first. Because the exact setup packet
is **not in the `.exe`**, it is **parameterized and sweepable**.

---

## What changed

`src/canon_megatank/usb.py`:

1. **New `RecvControlSetup` dataclass** (frozen, slots) — the parameterized
   control-IN setup packet: `bm_request_type` / `b_request` / `w_value` /
   `w_index` / `length`. `__post_init__` **rejects any non-IN `bm_request_type`**
   (direction bit `0x80` must be set) — RECV is always a read, so a probe can
   never accidentally point it at a control-OUT.
2. **`DEFAULT_RECV_CONTROL_SETUP`** — the best-guess default:
   `bmRequestType=0xA1, bRequest=0x01` (printer-**class** GET_PORT_STATUS). This
   is the most likely RECV channel because, on the live device, only the two
   standard printer-class control-INs ever **answered** (`0xA1/0x00`
   GET_DEVICE_ID ~120 B; `0xA1/0x01` GET_PORT_STATUS `0x18`); every **vendor**
   control-IN (`0xC0`/`0xC1`, bReq `0x00..0x11`) **STALLed**, and bulk-IN ZLP'd.
3. **`RECV_CONTROL_CANDIDATES` + `sweep_recv_control_setups()`** — the ranked
   sweep set the probe iterates: the two answered class reads first
   (`0xA1/0x01`, then `0xA1/0x00`), then the vendor `0xC0`/`0xC1` × bReq
   `0x00..0x11` scan (STALLed bare, but the natural `DeviceIoControl`-style
   channel — may answer once a session is primed). `include_vendor=False`
   restricts to just the two class reads.
4. **`ClaimedDevice`** now takes `recv_control_setup=` (defaults to the class
   GET_PORT_STATUS read) and exposes a `recv_control_setup` **property + setter**
   so a probe can swap candidates against an already-open device without
   re-claiming the interface.
5. **`read_response` and `send_and_receive`** now: write the header / enciphered
   frame on **bulk-OUT** (unchanged), then read the reply via the shared
   `_control_recv()` helper over **control-IN** using the configured setup.
   `read()` on bulk-IN is **no longer issued at all**.
6. **`open_g6020`** forwards `recv_control_setup=` so callers/probes can pick a
   candidate per open.

**Unchanged / preserved:**

- **SEND half** — `send_command` (write-only) and the bulk-OUT prime in both
  RECV methods are untouched (EP 0x03 OUT on the maintenance lane).
- **All safety gates** — vendor allowlist, pinned-interface verification
  (iface 4 / OUT 0x03 / IN 0x86), kernel-driver detach/reattach, the
  `ClaimedDevice` context contract, and the `ops.py` gate stack
  (UUID isolation, write budget, EEPROM dump, validated-status, lockfile,
  dry-run) are all intact. Nothing was loosened.
- **Public API shape** — `read_response(request_header, *, timeout_ms, length)`
  and `send_and_receive(frame, *, timeout_ms, length)` keep their exact
  signatures, so the `ops.ReadableDevice` / `ops.WicSessionDevice` protocols and
  every existing caller still type-check and run unchanged.

---

## On-wire shape now

```
SEND (unchanged):   dev.write(bulk_out_ep=0x03, <enciphered prefix / header>)
RECV (the fix):     dev.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, length)   # control-IN on EP0
```

- `read_response` primes the 3-byte `[cmd][arg_hi][arg_lo]` RECV header.
- `send_and_receive` primes the full functor-enciphered frame (the
  `set_session` / `get_keyword` / verify shape).
- Both then read over the configured control-IN setup. The read **length** comes
  from the method's `length=` kwarg (the `ops.py` callers pass `keyword_len` /
  `STATUS_READ_LEN`); the setup's own `.length` field is the probe-facing default
  used when constructing a candidate directly.

---

## How the probe sweeps candidates (no device assumed here)

```python
from canon_megatank.usb import open_g6020, sweep_recv_control_setups

with open_g6020() as cd:
    # prime + read with each candidate, watching for a CHANGED/new reply vs the
    # generic 1284-id / status baseline (and ideally a 4-byte keyword)
    for setup in sweep_recv_control_setups():
        cd.recv_control_setup = setup
        reply = cd.send_and_receive(get_keyword_wire, length=0x14)
        # record (setup.describe(), reply) — a non-baseline reply == session opened
```

A probe may also pass `recv_control_setup=` straight to `open_g6020(...)` to pin
one candidate per open.

---

## What this validates (and what it does NOT)

- **Validates:** the RECV now reads over the pipe the live device actually
  answers on (control-IN), and the candidate set / sweep mechanism is in place.
  Combined with Lane A's corrected functor cipher, the **goal** of the probe is
  to confirm the cipher **opens a session** — a changed/new reply vs the generic
  1284-id / status baseline, and ideally a 4-byte keyword from `get_keyword`
  (a READ that may well work no-key).
- **Does NOT (yet):** the **keyed WICReset clear** (`set_command`) may still be
  **firmware-gated** even over the correct pipe with a byte-perfect cipher. The
  session-open + keyword **read** is the thing this enables confirming without
  the key; the keyed clear is a separate later step, still behind the full gate
  stack and `verified-captured` status.

---

## Verification (no hardware)

```
uv run pytest -q          # 159 passed, 11 skipped
uv run ruff check src tests
uv run ruff format --check src/canon_megatank/usb.py tests/test_usb.py
uv run mypy src           # Success: no issues found in 13 source files
```

`tests/test_usb.py` now asserts the RECV path issues **no** bulk-IN `read()` and
exactly one `ctrl_transfer` with the configured setup fields + caller length;
covers the `RecvControlSetup` non-IN rejection, the default channel, the sweep
ordering/contents, candidate swapping via the setter, and STALL/prime-failure
error propagation (both surface as `UsbAccessError`).

---

## Follow-ups

- Run the live sweep on the 12fe G6020 (service mode, usblp detached) to find
  which candidate returns a non-baseline reply once Lane A's corrected cipher is
  primed; record the winning `RecvControlSetup` and promote it to the default.
- If no candidate answers, the wall is firmware session-gating (see
  `wicreset-device-keyword-read.md` / `live-handshake-experiment-2026-05-31.md`),
  not the transport — escalate to the keyed-unlock path.
