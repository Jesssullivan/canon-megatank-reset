#!/usr/bin/env python3
"""Reverse the G6020 service-mode readback wire codec from the session dataset.

Pure offline analysis of ``/tmp/codec-dataset.json`` (40 fresh service-mode
sessions; constant device state, per-session 3-byte keyword). NO device is
touched by this script. See docs/research/g6020-wire-codec-crack.md.

Result:
  * 0x84 (VENDOR_GET 0x84) is FULLY cracked: an additive (XOR) stream cipher
    over a CONSTANT 20-byte plaintext, where each output byte is XORed with one
    of the three raw keyword bytes (or with nothing) per a fixed selection
    table. 40/40 dataset rows + 1 out-of-sample log session reconstruct exact.
  * 0x8c (VENDOR_GET 0x8c) is NOT a per-byte keyword XOR/add/multiply: its key
    schedule is nonlinear in all three keyword bytes (GF(2)-linear fit = 0/160
    bits; no LCG/GF256/permutation match). Left as an open item.

Run: python3 scripts/g6020_wire_codec_crack.py /tmp/codec-dataset.json
"""

from __future__ import annotations

import json
import sys

# Recovered 0x84 codec (verified byte-exact, see module docstring).
# keysel[p]: which keyword byte (0,1,2) XORs output position p; 'C' = no key (raw plaintext byte).
R84_KEYSEL: list[object] = [1, "C", 2, 0, 2, 1, 0, "C", 1, "C", 2, 2, 0, 0, 1, "C", 2, 1, 0, "C"]
# The recovered CONSTANT 20-byte plaintext behind every 0x84 reply.
R84_PLAINTEXT = bytes(
    [0x06, 0x47, 0x1A, 0x0E, 0x1B, 0x01, 0x02, 0x54, 0x07, 0x59,
     0x12, 0x07, 0x1F, 0x0B, 0x08, 0x52, 0x12, 0x01, 0x01, 0x4E]
)


def r84_encode(plaintext: bytes, keyword: bytes) -> bytes:
    """Encode a 20-byte plaintext into the on-wire 0x84 reply under a 3-byte keyword."""
    out = bytearray(20)
    for p in range(20):
        sel = R84_KEYSEL[p]
        ks = 0 if sel == "C" else keyword[sel]
        out[p] = plaintext[p] ^ ks
    return bytes(out)


def r84_decode(reply: bytes, keyword: bytes) -> bytes:
    """Decode an on-wire 0x84 reply back to plaintext (XOR is its own inverse)."""
    return r84_encode(reply, keyword)  # symmetric


def _derive_r84(rows: list[dict]) -> tuple[list[object], bytes]:
    """Re-derive the 0x84 keysel + plaintext from the dataset (self-check)."""
    keysel: list[object] = [None] * 20
    plaintext = bytearray(20)
    for p in range(20):
        chosen = None
        for b in range(3):
            consts = {bytes.fromhex(r["r84"])[p] ^ bytes.fromhex(r["kw"])[b] for r in rows}
            if len(consts) == 1:
                chosen = (b, consts.pop())
                break
        if chosen is None:
            consts = {bytes.fromhex(r["r84"])[p] for r in rows}
            assert len(consts) == 1, f"pos {p} not constant and not single-keyword"
            keysel[p] = "C"
            plaintext[p] = consts.pop()
        else:
            keysel[p] = chosen[0]
            plaintext[p] = chosen[1]
    return keysel, bytes(plaintext)


def main(path: str) -> int:
    d = json.load(open(path))
    rows = d["rows"]

    keysel, plaintext = _derive_r84(rows)
    assert keysel == R84_KEYSEL, (keysel, R84_KEYSEL)
    assert plaintext == R84_PLAINTEXT, (plaintext.hex(), R84_PLAINTEXT.hex())

    ok = all(
        r84_encode(R84_PLAINTEXT, bytes.fromhex(r["kw"])) == bytes.fromhex(r["r84"])
        for r in rows
    )
    print(f"0x84 codec reconstructs all {len(rows)} dataset rows: {ok}")
    print(f"0x84 keysel    : {keysel}")
    print(f"0x84 plaintext : {plaintext.hex()}")

    # Out-of-sample validation against the reset log baseline session.
    log_kw = "8b12d7"
    log_r84 = "1447cd85cc1389541559c5d094801a52c5138a4e"
    pred = r84_encode(R84_PLAINTEXT, bytes.fromhex(log_kw)).hex()
    print(f"\nOut-of-sample (reset-log baseline, kw={log_kw}):")
    print(f"  predicted 0x84 = {pred}")
    print(f"  logged    0x84 = {log_r84}")
    print(f"  MATCH = {pred == log_r84}")

    # 0x8c negative result summary.
    sigs = {tuple(sorted(bytes.fromhex(r["r8c"]))) for r in rows}
    print(f"\n0x8c distinct sorted-multisets across rows: {len(sigs)} (1 => permutation; >1 => substitution)")
    print("0x8c: nonlinear key schedule, NOT a per-byte keyword XOR/add/mul (see doc).")
    return 0 if ok and pred == log_r84 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/codec-dataset.json"))
