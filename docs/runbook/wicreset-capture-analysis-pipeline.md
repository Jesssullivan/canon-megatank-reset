# WICReset capture → analysis → encode pipeline (Lane C)

**Status:** turnkey, awaiting a real WICReset capture.
**Owner:** Lane C (analysis + encode). **Touches no hardware.**
**Repo:** `canon-megatank-reset` (neo + mbp-13). **tshark lives on mbp-13.**

This runbook is the post-capture pipeline for the G6020 5B00 absorber reset. The
moment a **real working WICReset reset** is captured on the lab box, this turns
the pcap into (1) extracted bytes, (2) a local-vs-cloud verdict, and (3) a native
key-free reset path in `ops.py` — without spending the single-use WICReset key on
guesses.

## Transport recap (what we are capturing)

The G6020 enumerates as **`04a9:1865`** in normal mode and **`04a9:12fe`**
("Printer in service mode") once service mode is entered. The maintenance
transport is **USB EP0 CONTROL transfers**, not bulk:

| transfer | bmRequestType | bRequest | wValue | wIndex | data | meaning |
|---|---|---|---|---|---|---|
| reset (OUT) | `0x40` (vendor) | `0x85` | `0x0000` | `0x0000` | `00 03 01 03 07` | absorber reset, idx 0x07 = Main |
| 1284-id (IN) | `0xa1` (class) | `0x00` | `0x0000` | `0x0000` | — | GET_DEVICE_ID |
| status (IN) | `0xa1` (class) | `0x01` | `0x0000` | `0x0000` | — | GET_PORT_STATUS |

The v5103-derived **bulk** path (`encode_send` → BULK_OUT `0x03` on interface 4)
sends the *same* `[00 03 01 03 07]` payload and is ACK'd, but it is
firmware-**GATED**: 5B00 persists after it. WICReset uses the **control** path
above; whether that path is *locally replayable* or *cloud-nonce-gated* is the
question step 2 answers.

---

## Step 1 — Extract the capture (`scripts/parse-wicreset-capture.py`)

The parser is a dependency-free wrapper around `tshark`. It extracts **every**
control transfer to/from the service-mode device — `bmRequestType`, `bRequest`,
`wValue`, `wIndex`, `data` (hex) and the device response — in order with
timestamps, plus any bulk frames, and prints a clean annotated sequence. It
auto-flags the absorber-reset frame.

### Run it

```bash
# On the capture host (mbp-13), where tshark lives:
python3 scripts/parse-wicreset-capture.py captures/<capture>.pcapng

# Clean output: filter to the service-mode device's usbmon address
# (find it from the GET_DESCRIPTOR enumeration; e.g. 42):
python3 scripts/parse-wicreset-capture.py captures/<capture>.pcapng --device-address 42

# Machine-readable (for diffing / pinning):
python3 scripts/parse-wicreset-capture.py captures/<capture>.pcapng --json

# Emit a CONTROL_SEQUENCE list ready to paste into the SSOT / ops.py:
python3 scripts/parse-wicreset-capture.py captures/<capture>.pcapng --replay-snippet

# Or via just (forwards extra args after the pcap):
just parse-capture captures/<capture>.pcapng --device-address 42
```

### tshark field mapping (verified, tshark 4.4.2)

| field | meaning |
|---|---|
| `usb.bmRequestType` | direction\|type\|recipient byte |
| `usb.setup.bRequest` / `usbprinter.bRequest` | request code (class reqs use the `usbprinter` dissector) |
| `usb.setup.wValue` / `usb.setup.wIndex` | setup wValue / wIndex |
| `usb.setup.wLength` / `usbprinter.max_len` | host-requested length |
| `usb.data_fragment` | OUT control data (**the reset bytes `0003010307` land here**) + undissected response payloads |
| `usb.capdata` | bulk payloads |
| `usbprinter.device_id` | dissected IEEE-1284 device-id text (class GET_DEVICE_ID response) |
| `usb.urb_status` | URB completion status (`0` = success, `-32` EPIPE/STALL) |
| `usb.urb_type` | `S` submit (carries SETUP) / `C` complete (carries response) |

### Validated against a real capture

The parser is validated against
`captures/ctrl-reset-sample-20260601.pcapng.gz` (a control-transfer reset
rehearsal pulled from mbp-13, committed as a fixture). It correctly extracts the
control transfers and flags frame 13 as the reset:

```
 13   1.787  OUT  vendor   0x40 0x85  0x0000 0x0000    5 0003010307
        └─ *** ABSORBER RESET (matches known [00 03 01 03 07]) ***
```

---

## Step 2 — The OFFLINE-REPLAY local-vs-cloud test

**Goal:** decide whether the captured control sequence clears 5B00 by itself
(*locally replayable* → we can ship a native, key-free tool) or whether WICReset
injects a server-side nonce/token that the printer validates (*cloud-nonce-gated*
→ replay alone will not clear it).

**Principle:** replay ONLY the captured USB control transfers, from Linux, over
EP0, **with the network physically disconnected**, then power-cycle and read the
absorber back. No WICReset process, no internet — just the bytes.

### Preconditions

- A real WICReset reset has been captured and extracted (step 1).
- The captured `control_sequence` is pinned in
  `printers/canon-g6020/maintenance.yaml::supported.absorber_reset.control_sequence`.
- Waste-ink pads are installed on the test unit (physical safety precondition for
  ANY real reset write).
- A pre-flight EEPROM dump exists as rollback evidence (`eeprom.dump_eeprom`).

### Protocol (exact commands)

```bash
# ── On mbp-13 (the test unit's host). Run as the lab user; root via sops. ──

# 0. Identify the service-mode device + record the absorber baseline.
lsusb | grep -i 04a9                      # expect 04a9:12fe (service mode) or 04a9:1865
#   read the absorber/status BEFORE (read-only, safe):
just read --cmd 0x86 --arg 0x0000         # generic status RECV; note the value

# 1. CUT THE NETWORK. Physically unplug ethernet AND disable wifi/tailscale so
#    nothing can reach a WICReset server. Verify there is NO route out:
sudo nmcli networking off                 # or: sudo ip link set <iface> down
sudo tailscale down
ip route                                   # expect NO default route
ping -c1 -W2 8.8.8.8 ; echo "exit=$?"      # MUST fail (exit non-zero) — no internet

# 2. REPLAY the captured control sequence ONLY — no WICReset, offline.
#    This drives ops.replay_control_sequence over ClaimedDevice EP0, behind the
#    existing gates (UUID, status==verified-captured, EEPROM dump, write budget,
#    lockfile). Dry-run first to print the exact transfers, then execute:
just replay-control                        # DRY-RUN: prints the steps, writes nothing
just replay-control --execute              # gated execute: drives EP0 control-OUT

# 3. POWER-CYCLE the printer (operator action): hard power off, wait 10s, power on.
#    5B00 state is latched in EEPROM and re-evaluated at boot.

# 4. READ THE ABSORBER BACK (still offline) and compare to the baseline:
just read --cmd 0x86 --arg 0x0000          # status RECV
#   (and the EEPROM read-back once the EEPROM read cmd is derived:)
#   just eeprom-dump  → compare absorber region to the pre-replay dump
```

### Verdict

| Offline replay result | Online WICReset result | Verdict | Action |
|---|---|---|---|
| **clears 5B00** | n/a | **LOCAL — locally replayable** | ship native key-free tool: pin `control_sequence`, promote SSOT `status: verified-captured`, set `control_sequence_offline_verified: true` |
| does **not** clear offline | **does** clear (network up) | **CLOUD — nonce-gated** | the OUT carries a server token; native replay is insufficient. Re-capture WITH a usbmon trace AND a network trace, diff the reset OUT across two WICReset runs to locate the variable nonce field |
| does not clear offline | does not clear online either | inconclusive | capture was incomplete / wrong device state — re-capture a confirmed-clearing WICReset run |

**Decision rule:** *offline replay clears 5B00 = LOCAL. Offline fails but
online-WICReset clears = CLOUD-NONCE-GATED.* The control sequence being
byte-identical across two independent WICReset runs is corroborating evidence for
LOCAL (a nonce would vary the reset OUT between runs).

### Re-capture for the CLOUD case (locating the nonce)

If cloud-gated, run WICReset twice and diff the reset control-OUT:

```bash
# Two captures, network up, same unit:
python3 scripts/parse-wicreset-capture.py captures/run-A.pcapng --json > A.json
python3 scripts/parse-wicreset-capture.py captures/run-B.pcapng --json > B.json
diff <(jq '.control[] | select(.req_type=="vendor")' A.json) \
     <(jq '.control[] | select(.req_type=="vendor")' B.json)
# A field that differs run-to-run is the candidate nonce. A reset OUT that is
# byte-identical across runs argues for LOCAL (no per-run token).
```

---

## Step 3 — Encode the native reset (`ops.replay_control_sequence`)

The service-mode control-transfer reset is implemented in
`src/canon_megatank/ops.py` as `replay_control_sequence`, the sibling of the
bulk `reset_absorber`. It drives the captured `(bmRequestType, bRequest, wValue,
wIndex, data)` sequence via `ClaimedDevice.control_transfer` over EP0, behind the
**existing** safety gates — unchanged, not loosened.

### Gate ladder (identical to `reset_absorber`, in order)

1. **UUID isolation** — `verify_fingerprint_matches` vs the locked `test_unit`.
2. **Validation status** — `maintenance.yaml::absorber_reset.status` must be
   `verified-captured`. While it is `derived-unvalidated` (current state — the
   `control_sequence` is a **placeholder**) → HARD STOP `ResetNotValidatedError`.
   Additionally refuses if `control_sequence` is empty (no invented reset).
3. **EEPROM baseline** — `eeprom_dump_done` must be `True` (rollback evidence).
4. **Write budget** — `charge()` raises at the cap, *before* any OUT transfer.
5. **Lockfile** — held by the caller (`lockfile.write_lock`).

Dry-run is the default: it prints the exact transfers and writes nothing, without
consulting any gate. Only an all-gates-pass `execute=True` issues the control
transfers — and issues **exactly** the captured sequence, in order.

### Wiring added

- `usb.py`: `ClaimedDevice.control_transfer(bmRequestType, bRequest, wValue,
  wIndex, data_or_length)` — a thin, gated EP0 `ctrl_transfer` helper (the Linux
  equivalent of WICReset's service-mode transport). OUT for the vendor reset, IN
  for the class reads. USB errors surface as `UsbAccessError`.
- `ops.py`: `ControlStep`, `parse_control_sequence` (SSOT → steps),
  `replay_control_sequence` (the gated driver), and the captured-reset anchor
  constants `CTRL_RESET_*`.
- `maintenance.yaml`: `transport: control`, `service_mode_product_id: 0x12fe`, a
  placeholder `control_sequence: []`, and `control_sequence_offline_verified:
  false`. Populate `control_sequence` ONLY from a verified offline-clearing
  capture (use `--replay-snippet`), then promote `status` and flip
  `control_sequence_offline_verified: true`.

### Promotion checklist (after a LOCAL verdict)

1. `parse-wicreset-capture.py --replay-snippet` → paste into
   `maintenance.yaml::supported.absorber_reset.control_sequence` (as the
   `{bmRequestType, bRequest, wValue, wIndex, data|read_length}` mapping form).
2. Set `control_sequence_captured_at`, `control_sequence_offline_verified: true`.
3. Promote `supported.absorber_reset.status: verified-captured` (gated on
   pads-installed + offline-clearing proof).
4. Re-run `just test` — green.
5. `just replay-control --execute` now passes the gates against the locked unit.

---

## Tests

All scaffolding is covered and the suite is green (`just test` /
`uv run --extra dev pytest`):

- `tests/test_control_reset.py` — the full gate ladder for
  `replay_control_sequence` (dry-run writes nothing; each gate blocks in order;
  empty-sequence guard; happy path drives exactly the captured sequence).
- `tests/test_usb.py` — `control_transfer` OUT forwards setup+data and returns
  `b""`; IN returns the reply bytes; USB errors surface as `UsbAccessError`.

**Latest:** 87 passed, 11 skipped (the 11 are tshark-gated pcap tests, skipped on
hosts without tshark — they pass on mbp-13).
