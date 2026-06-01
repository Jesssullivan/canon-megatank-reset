# G6020 reset — one-run LIVE validation procedure

**Date:** 2026-06-01 · **Status:** procedure (not yet run) · **Risk:** the ONE real
EEPROM write on the dedicated debug unit.

This is the single, gated, authorized live run that promotes the
WICReset-derived `waste:common` (5B00) clear from **derived** to **validated**.
Everything upstream is pure derivation (no key spent, no device touched); this
runbook is the first time the derived enciphered sequence touches hardware.

> **Unit scope.** Run this ONLY against the dedicated debug/RE G6020 — the
> non-functional, 5B00-locked unit on mbp-13 whose UUID is pinned in
> `printers/canon-g6020/maintenance.yaml::test_unit`
> (`00000000-0000-1000-8000-00186501807c`). The UUID gate refuses any other unit.
> **Waste-ink pads must be physically installed/serviced first** — a counter
> reset on saturated pads risks ink overflow.

---

## 0. What this run drives

`ops.reset_absorber_wicreset(...)` over the pinned maintenance lane
(iface 4, OUT `0x03` / IN `0x86`), every frame functor-3 enciphered by the Lane A
encoder, in this order:

```
1. set_session   81 00 00 03            send_and_receive   opens the session
2. get_keyword   82 00 00 00            send_and_receive   RECV → live 4-byte keyword
                                                           → encoder.seed_keyword(reply)
3. set_command   85 00 00 | 10 07 7C    send_command       waste-row selector
4. set_command   85 00 00 | 0D 00 00    send_command       'common' operand  ← THE 5B00 WRITE
5. get_command   86 00 00 00            send_and_receive   verify read-back
```

The **template-default-keyword** wire bytes (what dry-run prints; recorded in the
SSOT `derived_template.derived_sequence`) are:

| step | plaintext | wire (default kw 4D B6 AB 00 → bound 00 FF 00 F8) |
|---|---|---|
| set_session | `81 00 00 03` | `ed f4 75 21 a3 c4 69 2c ba fb 46 12 16 b8 73 c0 69 66 13 4e` |
| get_keyword | `82 00 00 00` | `ed f4 75 21 a3 c4 69 2c ba fb 45 12 16 b8 73 c0 69 66 13 4e` |
| set_command[10 07 7C] | `85 00 00 10 07 7c` | `f3 0d 61 e7 bb bc 64 31 a7 0b a9 22 95 fb e6 1b a0 00 e1 c9 ce a3` |
| set_command[0D 00 00] | `85 00 00 0d 00 00` | `10 4e 0a 87 71 01 7c 48 06 06 bd a2 a8 c4 df 42 ba 06 08 6e 7c 3d` |
| get_command | `86 00 00 00` | `ed f4 75 21 a3 c4 69 2c ba fb 45 12 16 b8 73 c0 69 66 13 4e` |

> **On the LIVE wire these change.** After step 2 the encoder is reseeded with the
> printer's real keyword (`functor_initialization`), so EVERY enciphered byte of
> the two `set_command` frames differs from the table above (device binding). The
> table is the key-free derivation; the live keyword is the only runtime input.

---

## 1. Detach the printer from the capture VM → host

If the Win11 capture VM is up and has the USB device attached, return it to the
Rocky host so Linux pyusb can claim it. On mbp-13 (libvirt/qemu):

```bash
# list the attached USB hostdev on the running capture domain
sudo -n virsh dumpxml win11-capture | grep -A3 '<hostdev'
# detach the 04a9 device from the guest (use the vendor/product the dump shows:
# 0x1865 normal, or 0x12fe if the guest already put it in service mode)
sudo -n virsh detach-device win11-capture /dev/stdin <<'XML'
<hostdev mode='subsystem' type='usb' managed='yes'>
  <source><vendor id='0x04a9'/><product id='0x12fe'/></source>
</hostdev>
XML
```

If no VM is involved (printer cabled straight to the host), skip this step.

**Put the printer in service mode** (idProduct flips `0x1865` → `0x12fe`): power
off, then power on holding the documented service-mode key combo for this G-series
(Stop ×N while holding Power); confirm with `lsusb -d 04a9:12fe`.

---

## 2. Unbind `usblp` and free the CUPS/ipp-usb claim

```bash
# stop the office print path so nothing else holds the interface (scoped sudo)
sudo -n systemctl stop ipp-usb cups || true

# unbind the kernel usblp driver from the printer interface(s) if attached
for d in /sys/bus/usb/drivers/usblp/*-*; do
  [ -e "$d" ] && echo "$(basename "$d")" | sudo -n tee /sys/bus/usb/drivers/usblp/unbind
done
lsmod | grep -q usblp && sudo -n modprobe -r usblp || true   # optional: drop the module
```

Restore on exit: `sudo -n systemctl start ipp-usb cups` (the office queue). The
tier-0 probe (`scripts/tier0-claim-probe.sh`) already does the ipp-usb toggle with
a trap — model the cleanup on it.

---

## 3. Claim the maintenance lane (sanity: tier-0 first, send nothing)

Confirm the stack can bind the lane on the service-mode unit **before** issuing any
bytes:

```bash
cd ~/git/canon-megatank-reset
PYTHONPATH="$PWD/src" nix develop --command bash -lc \
  'PYTHONPATH="$PWD/src" uv run --no-project --with pyusb python - <<PY
from canon_megatank.usb import open_g6020, MAINT_INTERFACE, MAINT_BULK_OUT, MAINT_BULK_IN
print("expected: iface", MAINT_INTERFACE, "OUT", hex(MAINT_BULK_OUT), "IN", hex(MAINT_BULK_IN))
with open_g6020(product_id=0x12fe) as dev:          # service-mode product id
    print("CLAIM_OK", hex(dev.vendor_id), hex(dev.product_id), dev.serial_number)
    assert dev.bulk_out_endpoint == MAINT_BULK_OUT and dev.bulk_in_endpoint == MAINT_BULK_IN
    print("ENDPOINTS_VERIFIED — bound the maintenance lane, sent nothing")
PY'
```

A clean `CLAIM_OK` + `ENDPOINTS_VERIFIED` means iface 4 / OUT 0x03 / IN 0x86 is
claimable. If `open_g6020` cannot find iface 4 on the `0x12fe` descriptor, the
service-mode interface map differs — fall back to `interface=0` (the ground-truth
transport line names iface0 / EP 0x01 OUT / 0x82 IN as the alternate); re-run the
probe with `open_g6020(product_id=0x12fe, interface=0, bulk_out_ep=0x01,
bulk_in_ep=0x82)` and record which lane answered.

---

## 4. Dry-run the gated sequence (prints the enciphered wire, touches nothing)

```bash
cd ~/git/canon-megatank-reset
PYTHONPATH="$PWD/src" nix develop --command bash -lc \
  'PYTHONPATH="$PWD/src" uv run --no-project --with pyusb python - <<PY
from canon_megatank.usb import open_g6020
from canon_megatank.ops import reset_absorber_wicreset
from canon_megatank.fingerprint import build_runtime_fingerprint   # however ops reads it
import sys
# Build (or stub) the Lane A encoder: promote scripts/canon_sr5_cipher.py to
# canon_megatank.protocol.wicreset.build_encoder, OR inject an adapter here.
from importlib import import_module
enc = import_module("canon_megatank.protocol.wicreset").build_encoder(printer_id="canon-g6020")
with open_g6020(product_id=0x12fe) as dev:
    fp = build_runtime_fingerprint(dev)              # the real fingerprint for the UUID gate
    plan = reset_absorber_wicreset(dev, runtime_fingerprint=fp,
                                   eeprom_dump_done=True, encoder=enc, execute=False)
    print(plan.outcome.response_summary)             # DRY-RUN seq=[...] — the enciphered wire
    for s in plan.steps:
        print(f"  {s.kind:12s} plain={s.plaintext.hex()} wire={s.wire.hex()}")
PY'
```

Confirm the dry-run preview matches the SSOT `derived_sequence.frames` table
(template-default keyword). This proves the SSOT + encoder + transport agree
before any write.

---

## 5. THE one real run (behind a temporary verified flag / override)

`execute=True` still HARD STOPS on `status != 'verified-captured'`. For the
one-run validation, authorize the single write with the explicit operator override
**without mutating the SSOT** — `accept_derived=True` bypasses ONLY the status gate
(UUID isolation, EEPROM baseline, write budget, lockfile, and the live-keyword
guard all still apply, and the override is stamped loudly in the outcome):

```bash
cd ~/git/canon-megatank-reset
# 5a. MANDATORY pre-flight EEPROM baseline (rollback evidence) — gate 3
PYTHONPATH="$PWD/src" nix develop --command bash -lc \
  'PYTHONPATH="$PWD/src" uv run --no-project --with pyusb python -m canon_megatank.cli eeprom-dump --product-id 0x12fe'

# 5b. the authorized one-run clear (accept_derived = the temporary verified flag)
PYTHONPATH="$PWD/src" nix develop --command bash -lc \
  'PYTHONPATH="$PWD/src" uv run --no-project --with pyusb python - <<PY
from canon_megatank.usb import open_g6020
from canon_megatank.ops import reset_absorber_wicreset
from canon_megatank.fingerprint import build_runtime_fingerprint
from importlib import import_module
enc = import_module("canon_megatank.protocol.wicreset").build_encoder(printer_id="canon-g6020")
with open_g6020(product_id=0x12fe) as dev:
    fp = build_runtime_fingerprint(dev)
    plan = reset_absorber_wicreset(
        dev, runtime_fingerprint=fp,
        eeprom_dump_done=True,        # set by 5a; ops also enforces gate 3
        encoder=enc,
        execute=True,
        accept_derived=True,          # TEMPORARY one-run override (debug unit only)
        verify_readback=True,
    )
    print("OUTCOME:", plan.outcome.response_summary)        # expect the OVERRIDE banner
    print("device_keyword:", plan.device_keyword.hex())     # the live 4-byte keyword
    for s in plan.steps:
        print(f"  {s.kind:12s} wire={s.wire.hex()} reply={s.reply.hex()}")
PY'
```

> **Do NOT promote `absorber_reset.status` to `verified-captured` before this run.**
> The override is the seam; the SSOT promotion is a separate, manual commit you
> make ONLY after step 7 confirms 5B00 cleared. Keep `--execute` ungated for the
> fleet (status stays `derived-unvalidated`).

---

## 6. Operator power-cycles the printer

Exit service mode and power-cycle: power off, wait ~10 s, power on normally
(no key combo) so the printer re-reads the absorber counter from EEPROM and
re-enumerates as `04a9:1865`.

---

## 7. Confirm 5B00 cleared + report

- The printer boots to **Ready** (no flashing error, no "5B00" / "support code
  5B00" on panel or the Canon utility).
- Optional read-back: `04a9:1865` again, run a status query / IPP
  `get-printer-attributes` and confirm no marker-waste-full error.

If 5B00 is gone: the derivation is **validated**. Then (separate manual commit)
promote `printers/canon-g6020/maintenance.yaml`:
`derived_template.validation: validated`, `derived_sequence.validation:
live-validated`, and `absorber_reset.status: verified-captured` — after which
`--execute` runs WITHOUT `accept_derived`.

---

## What to watch (capture all of this in the run log)

| signal | where | good | bad → STOP |
|---|---|---|---|
| **set_session RECV** (step 1 reply) | `plan.steps[0].reply` | non-empty ACK bytes | empty → session never opened |
| **keyword reply bytes** (step 2) | `plan.device_keyword` / `steps[1].reply` | a 4-byte word (e.g. not `00 00 00 00`) | `< 4 bytes` → the live-keyword guard HARD STOPS before any write (Lane C R1) — **no clear was sent** |
| **set_command ACK** (steps 3,4) | `send_command` return / no `UsbAccessError` | each write returns its byte count, no USBError | a stall/`UsbAccessError` mid-sequence → the second write may not have landed |
| **get_command verify** (step 5) | `plan.steps[-1].reply` | status row decodes `0x00` success (per `derived_template.statuses`) | `0x01` not-ready / `0xFF` unsupported → reset rejected by firmware |
| **OVERRIDE banner** | `plan.outcome.response_summary` | contains `[accept_derived OVERRIDE...]` | absent on a derived unit → status gate path wrong |
| **post power-cycle** | printer panel / IPP status | Ready, no 5B00 | 5B00 persists → derived ciphertext likely wrong (the MEDIUM-confidence set_command bytes); re-examine FUN_004e76c0 fold vs a keyed capture |

**If the keyword reply is zero/short** (the most likely first-run snag — the live
handshake experiment already saw zero-byte reads): the session prologue did not
take. Recheck service mode (step 1 must be ACKed), try the iface0/EP 0x01/0x82
alternate lane (step 3 fallback), and confirm `set_session` enciphered correctly.
The guard guarantees no `set_command` write fires until a real keyword is read, so
a failed handshake costs nothing.

**Rollback:** the pre-flight EEPROM dump (step 5a) is the baseline; re-flash it if
a write lands wrong. The write budget (`write_budget.cap`) caps total writes
against the unit before manual review.
```
