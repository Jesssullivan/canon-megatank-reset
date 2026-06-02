#!/usr/bin/env python3
"""EXPERIMENT — live test of Lane A's recovered reset handshake on the debug G6020.

Sends the candidate session-open → preamble → payload sequence the Service Tool
runs, then reads back.
This is the live discriminator for "does the handshake make 5B00 clear?".

⚠ NOT production code. It deliberately sends frames with a few GUESSED bytes
(marked GUESS below) that static RE could not pin (runtime-sourced). A SUCCESS
(5B00 clears after power-cycle) is conclusive; a FAILURE only promotes the VM
capture (we can't tell which guess was wrong). Dedicated debug/RE unit only.

Run on mbp-13 with ipp-usb stopped, wrapped in usbmon (see the .sh harness).
Uses canon_megatank.usb.ClaimedDevice (pinned iface 4, verified endpoints).
"""

from __future__ import annotations

import sys

from canon_megatank.usb import open_g6020

# ─── Candidate sequence (Lane A structure; GUESS = statically-unknown byte) ──
#
# Frame = [cmd][arg_hi][arg_lo][payload]. arg=0x0000 throughout (Lane A).
# The dispatcher order: 0x40-frame → preamble → group-7 payload. The 0x5c/0x20/
# 0x24/0x28 slots do no bulk I/O, so they're omitted.

# 0x40 slot: SEND cmd 0x81 (1-byte payload from DAT_00494ca0, runtime) then RECV
# cmd 0x82 (64-byte reply). The payload byte is GUESS=0x00.
F40_SEND = bytes([0x81, 0x00, 0x00, 0x00])  # GUESS payload 0x00
F40_RECV_HDR = bytes([0x82, 0x00, 0x00])    # read 64 back

# 0x44 slot: 6-byte MODE preamble SEND, cmd 0x85, body starts 12 34 00 00 01 ??
# Byte 5 is GUESS=0x00 → body "12 34 00 00 01 00".
PREAMBLE_SEND = bytes([0x85, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x01, 0x00])  # GUESS byte5=00
PREAMBLE_POLL_HDR = bytes([0x86, 0x00, 0x00])

# 0x48 slot: the group-7 absorber-reset payload (KNOWN, ACKed previously).
PAYLOAD_SEND = bytes([0x85, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0x07])
PAYLOAD_POLL_HDR = bytes([0x86, 0x00, 0x00])


def main() -> int:
    print("EXPERIMENT: live reset handshake (Lane A candidate). GUESS bytes present.")
    with open_g6020() as dev:  # pins iface 4, verifies 0x03/0x86
        print(f"  device serial={dev.serial_number} out={hex(dev.bulk_out_endpoint)} in={hex(dev.bulk_in_endpoint)}")

        def send(label: str, frame: bytes) -> None:
            n = dev.send_command(frame, timeout_ms=5000)
            print(f"  SEND {label}: {frame.hex()} ({n}B written)")

        def recv(label: str, hdr: bytes, length: int) -> None:
            try:
                r = dev.read_response(hdr, timeout_ms=3000, length=length)
                print(f"  RECV {label}: req={hdr.hex()} -> {len(r)}B {r.hex()}")
            except Exception as exc:  # noqa: BLE001 — experiment: report, keep going
                print(f"  RECV {label}: req={hdr.hex()} -> TIMEOUT/err: {exc}")

        # The dispatcher chain, in order:
        send("0x40-frame (cmd81, GUESS payload)", F40_SEND)
        recv("0x40-reply (cmd82, 64B)", F40_RECV_HDR, 64)
        send("preamble (cmd85, GUESS byte5)", PREAMBLE_SEND)
        recv("preamble-poll (cmd86)", PREAMBLE_POLL_HDR, 20)
        send("group-7 payload (cmd85, KNOWN)", PAYLOAD_SEND)
        recv("payload-poll (cmd86)", PAYLOAD_POLL_HDR, 20)

    print("EXPERIMENT done. Power-cycle the printer + re-check 5B00.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
