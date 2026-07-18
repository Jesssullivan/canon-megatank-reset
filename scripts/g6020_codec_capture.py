#!/usr/bin/env python3
"""READ-ONLY service-mode codec capture: N fresh sessions -> {i,kw,r84,r8c}.

Extends the 0x84/0x8c readback-codec dataset (the one ``g6020_wire_codec_crack.py``
consumes) with denser per-session keyword coverage. Each session does ONLY the
read-path steps, in order, then STOPS:

    1. set_session  (81 00 00 03)   -- opens the session (no EEPROM write)
    2. get_keyword  (82 00 00)       -- the live per-session 3-byte keyword -> kw
    3. read 0x84    (84 00 00)       -- the cracked status readback   -> r84
    4. read 0x8c    (8c 00 00)       -- the OPEN waste-counter readback -> r8c

It NEVER issues a set_command (85 ..) write -- no waste-row selector, no clear
operand, nothing that mutates the EEPROM. It is the exact read-only prefix of the
validated reset session plus two extra VENDOR_GET reads. Safe to run unattended
against the live debug unit.

Self-contained on raw pyusb (no canon_megatank import) so it runs on any branch.
The wire framing is the usbprint.sys-derived service-mode transport, byte-for-byte:
    VENDOR_SET (OUT): bmRequestType=0x41, bRequest=frame[0],
                      wValue=(frame[1]<<8)|frame[2], wIndex=0, data=WHOLE frame
    VENDOR_GET (IN):  bmRequestType=0xC1, bRequest=hdr[0],
                      wValue=(hdr[1]<<8)|hdr[2], wIndex=0, wLength=length
(see src/canon_megatank/protocol/servicemode_transport.py for the decompile evidence).

Self-check: every row is validated against the CRACKED 0x84 codec. A faithful
capture MUST decode r84 to the known constant plaintext under the row's keyword;
rows that fail are flagged (bad84) so a mis-sliced keyword or half-open session
can't silently poison the dataset.

Run (on the box with the live 04a9:12fe device):
    .venv/bin/python scripts/g6020_codec_capture.py <count> <out.json> [--reopen]
"""

from __future__ import annotations

import json
import sys
import time

import usb.core
import usb.util

VID = 0x04A9
PID = 0x12FE
W_INDEX = 0x0000
TIMEOUT_MS = 5000

BM_VENDOR_SET = 0x41  # vendor | recipient=interface | OUT
BM_VENDOR_GET = 0xC1  # vendor | recipient=interface | IN

# ─── cracked 0x84 oracle ──────────────────────────────────────────────────────
# Intentionally inlined (NOT imported from g6020_wire_codec_crack): this harness is
# self-contained on raw pyusb so it runs on the lab box's older checkout, which may
# not carry the sibling analysis script. The 4 constants are the single cost of that
# branch-portability; keep them in sync with g6020_wire_codec_crack.R84_* by hand.
R84_KEYSEL: list[object] = [1, "C", 2, 0, 2, 1, 0, "C", 1, "C", 2, 2, 0, 0, 1, "C", 2, 1, 0, "C"]
R84_PLAINTEXT = bytes(
    [0x06, 0x47, 0x1A, 0x0E, 0x1B, 0x01, 0x02, 0x54, 0x07, 0x59,
     0x12, 0x07, 0x1F, 0x0B, 0x08, 0x52, 0x12, 0x01, 0x01, 0x4E]
)


def r84_decode(reply: bytes, kw: bytes) -> bytes:
    """Decode a 0x84 reply to plaintext under a 3-byte keyword (XOR, self-inverse)."""
    out = bytearray(20)
    for p in range(20):
        sel = R84_KEYSEL[p]
        out[p] = reply[p] ^ (0 if sel == "C" else kw[sel])  # type: ignore[index]
    return bytes(out)


# ─── read-path frames (read-only; NO set_command) ────────────────────────────
SET_SESSION = bytes([0x81, 0x00, 0x00, 0x03])
GET_KEYWORD = bytes([0x82, 0x00, 0x00])
READ_0X84 = bytes([0x84, 0x00, 0x00])
READ_0X8C = bytes([0x8C, 0x00, 0x00])
KW_LEN = 3


def _wvalue(frame: bytes) -> int:
    return ((frame[1] << 8) | frame[2]) & 0xFFFF


def vendor_set(dev: usb.core.Device, frame: bytes) -> None:
    dev.ctrl_transfer(BM_VENDOR_SET, frame[0], _wvalue(frame), W_INDEX, bytes(frame), TIMEOUT_MS)


def vendor_get(dev: usb.core.Device, header: bytes, length: int = 64) -> bytes:
    return bytes(dev.ctrl_transfer(BM_VENDOR_GET, header[0], _wvalue(header), W_INDEX, length, TIMEOUT_MS))


def open_device() -> usb.core.Device:
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        raise RuntimeError(f"no {VID:04x}:{PID:04x} device in service mode on USB")
    # Detach any bound kernel driver so EP0 control transfers aren't blocked.
    try:
        for cfg in dev:
            for intf in cfg:
                n = intf.bInterfaceNumber
                try:
                    if dev.is_kernel_driver_active(n):
                        dev.detach_kernel_driver(n)
                except (usb.core.USBError, NotImplementedError):
                    pass
    except usb.core.USBError:
        pass
    try:
        dev.set_configuration()
    except usb.core.USBError:
        pass  # already configured
    return dev


def capture_once(dev: usb.core.Device) -> tuple[bytes, bytes, bytes]:
    """One read-only session. Returns (kw, r84, r8c)."""
    vendor_set(dev, SET_SESSION)                      # open session
    kw = vendor_get(dev, GET_KEYWORD)[:KW_LEN]        # live per-session keyword
    r84 = vendor_get(dev, READ_0X84)[:20]
    r8c = vendor_get(dev, READ_0X8C)[:20]
    return kw, r84, r8c


def main(argv: list[str]) -> int:
    count = int(argv[0]) if argv else 5
    out_path = argv[1] if len(argv) > 1 else "/tmp/codec-capture-new.json"
    reopen = "--reopen" in argv  # default: one handle, re-run set_session per session

    rows: list[dict] = []
    bad = 0

    def run_session(i: int, dev: usb.core.Device) -> None:
        nonlocal bad
        kw, r84, r8c = capture_once(dev)
        ok = len(kw) == KW_LEN and r84_decode(r84, kw) == R84_PLAINTEXT
        bad += 0 if ok else 1
        rows.append({"i": i, "kw": kw.hex(), "r84": r84.hex(), "r8c": r8c.hex(), "ok84": ok})
        print(f"[{i:>4}] kw={kw.hex()} r8c={r8c.hex()} ok84={ok}", flush=True)

    if reopen:
        for i in range(count):
            dev = open_device()
            try:
                run_session(i, dev)
            finally:
                usb.util.dispose_resources(dev)
            time.sleep(0.05)
    else:
        dev = open_device()
        try:
            for i in range(count):
                run_session(i, dev)
        finally:
            usb.util.dispose_resources(dev)

    distinct_kw = len({r["kw"] for r in rows})
    distinct_r8c = len({r["r8c"] for r in rows})
    with open(out_path, "w") as f:
        json.dump(
            {"rows": rows, "n": len(rows), "bad84": bad,
             "distinct_kw": distinct_kw, "distinct_r8c": distinct_r8c, "reopen": reopen},
            f, indent=0,
        )
    print(
        f"\nwrote {len(rows)} rows -> {out_path}  "
        f"bad84={bad}  distinct_kw={distinct_kw}  distinct_r8c={distinct_r8c}",
        flush=True,
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
