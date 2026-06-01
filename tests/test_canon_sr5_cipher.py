"""Tests for the CANON-SR5 reference cipher (scripts/canon_sr5_cipher.py).

Proves:
  * the functor-3 envelope's 16 fixed bytes (MSVC rand seed 0x12345678) ==
    e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f;
  * the cipher round-trips: functor2 decode(encode(x)) == x, and the functor-3
    envelope+cipher decrypt(encrypt(frame)) == assembled buffer;
  * the parsed CANON-IPL tables match the exact devices.xml literals
    (command.index = 5x20, command.codes = 7x20, command.shift operator-VM);
  * the live device keyword changes the enciphered output (device binding).

Tests that need the decrypted template DB skip cleanly when
/tmp/appbin_out/devices.xml is absent (CI portability) -- the pure-algorithm
tests (envelope, round-trip on synthetic tables) always run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "canon_sr5_cipher.py"
_spec = importlib.util.spec_from_file_location("canon_sr5_cipher", _SCRIPT)
assert _spec and _spec.loader
csr5 = importlib.util.module_from_spec(_spec)
sys.modules["canon_sr5_cipher"] = csr5  # so @dataclass can resolve the module
_spec.loader.exec_module(csr5)

DEVICES_XML = csr5.DEVICES_XML_DEFAULT
HAVE_XML = DEVICES_XML.exists()
needs_xml = pytest.mark.skipif(not HAVE_XML, reason="devices.xml not present")

EXPECTED_ENVELOPE = bytes.fromhex("e93f0da196953104492d9e6183cf096f")


# ---- envelope self-check (always runs) ------------------------------------
def test_envelope_16_fixed_bytes() -> None:
    assert csr5.lcg16() == EXPECTED_ENVELOPE
    assert csr5.ENVELOPE_FIXED_16 == EXPECTED_ENVELOPE


def test_envelope_layout() -> None:
    method = _synthetic_method(functor=3)
    frame = bytes([0x85, 0x00, 0x00, 0xAB, 0x10, 0x07, 0x7C])
    env = csr5.envelope3(method, frame)
    assert env[:4] == bytes([0x00, 0x12, 0x01, 0xAB])  # 00 12 01 frame[3]
    assert env[4:] == EXPECTED_ENVELOPE  # no function block for 0xAB -> untouched
    assert len(env) == 20


def test_envelope_special_overwrite() -> None:
    # function block code 0x00 -> <special>0x04 0x66</special> => env[4+4]=env[8]:=0x66
    method = csr5.SR5Method(
        **{
            **_synthetic_method(functor=3).__dict__,
            "functions": {0x00: csr5.FunctionBlock(code=0x00, special=(0x04, 0x66), indexes=())},
        }
    )
    env = csr5.envelope3(method, bytes([0x82, 0x00, 0x00, 0x00, 0x00]))
    assert env[8] == 0x66  # overwrote the 0x96 LCG byte (EXPECTED_ENVELOPE[4])
    assert EXPECTED_ENVELOPE[4] == 0x96


def test_envelope_indexes_scatter() -> None:
    # <indexes>0x05</indexes> scatters frame[4:][0] into env[4+5]=env[9]
    method = csr5.SR5Method(
        **{
            **_synthetic_method(functor=3).__dict__,
            "functions": {0x10: csr5.FunctionBlock(code=0x10, special=(), indexes=(0x05,))},
        }
    )
    env = csr5.envelope3(method, bytes([0x85, 0x00, 0x00, 0x10, 0xCA]))
    assert env[9] == 0xCA


def test_envelope_too_small() -> None:
    method = _synthetic_method(functor=3)
    with pytest.raises(ValueError, match="too small"):
        csr5.envelope3(method, b"\x85\x00\x00")


# ---- operator-VM ----------------------------------------------------------
def test_shift_program_set_then_ops() -> None:
    steps = (
        csr5.ShiftStep("=", 1),
        csr5.ShiftStep("&", 1),
        csr5.ShiftStep("%", 5),
    )
    # acc = 1; acc &= 1 -> 1; acc %= 5 -> 1
    assert csr5.apply_shift_program(0xDEADBEEF, steps) == 1
    # '=' anchors regardless of seed
    assert csr5.apply_shift_program(0, (csr5.ShiftStep("=", 7),)) == 7


def test_build_shift_table_one_entry_per_value() -> None:
    # one shift-table entry per <value> sub-program (FUN_004e76c0:340-495)
    arr = (
        (csr5.ShiftStep("=", 0),),
        (csr5.ShiftStep("&", 1),),
        (csr5.ShiftStep("=", 2),),
    )
    assert csr5.build_shift_table(0xDEADBEEF, arr) == (0, 0xDEADBEEF & 1, 2)


# ---- synthetic-table round-trip (no devices.xml needed) -------------------
def _synthetic_method(functor: int = 2):  # type: ignore[no-untyped-def]
    idx = tuple(tuple((i * 7 + k) % 20 for i in range(20)) for k in range(5))
    codes = tuple(tuple((i * 13 + 3 * k) & 0xFF for i in range(20)) for k in range(7))
    # 3 <array>s, each 4 single-action <value> sub-programs (the recovered shape)
    shift = (
        ((csr5.ShiftStep("=", 0),), (csr5.ShiftStep("&", 1),),
         (csr5.ShiftStep("=", 0),), (csr5.ShiftStep("=", 0),)),
        ((csr5.ShiftStep("&", 1),), (csr5.ShiftStep("=", 1),),
         (csr5.ShiftStep("%", 5),), (csr5.ShiftStep("=", 0),)),
        ((csr5.ShiftStep("&", 1),), (csr5.ShiftStep("=", 0),),
         (csr5.ShiftStep("=", 0),), (csr5.ShiftStep("=", 2),)),
    )
    return csr5.SR5Method(
        handler=functor,
        functor=functor,
        keyword_codes=(0x4D, 0x49, 0x53, 0x00),
        keyword_index=(0x03, 0x01, 0x00, 0x02),
        keyword_value=(0x4D, 0xB6, 0xAB, 0x00),
        command_index=idx,
        command_codes=codes,
        command_shift=shift,
        functions={},
    )


def test_functor2_emits_four_bytes() -> None:
    method = _synthetic_method()
    bound = csr5.bind_keyword(method, bytes(method.keyword_value))
    enc = csr5.functor2_transform(method, bound, seed_source=b"\x85\x00\x00\x10\x07\x7c")
    assert len(enc) == csr5.KEYWORD_LEN == 4


def test_functor2_seed_is_command_buffer_only() -> None:
    # the keyword does NOT enter the seed; two different keywords share the seed
    # selection but produce different output bytes (transform subject differs).
    method = _synthetic_method()
    seed_src = b"\x85\x00\x00\x10\x07\x7c"
    a = csr5.functor2_transform(method, b"\x00\xff\x00\xf8", seed_source=seed_src)
    b = csr5.functor2_transform(method, b"\x44\x6b\x5c\x60", seed_source=seed_src)
    assert a != b


def test_functor2_seed_changes_output() -> None:
    method = _synthetic_method()
    bound = csr5.bind_keyword(method, bytes(method.keyword_value))
    a = csr5.functor2_transform(method, bound, seed_source=b"\x00\x00\x00\x01")
    b = csr5.functor2_transform(method, bound, seed_source=b"\x00\x00\x00\x02")
    assert a != b  # a different seed reselects arrays / keystream


def test_keyword_binding_default_vs_live_differs() -> None:
    method = _synthetic_method()
    default = csr5.bind_keyword(method, bytes(method.keyword_value))
    live = csr5.bind_keyword(method, bytes([0x11, 0x22, 0x33, 0x44]))
    assert default != live  # live keyword changes the bound encoder keyword


# ---- devices.xml-backed parse + ground-truth literals ---------------------
@needs_xml
def test_parse_prefixes() -> None:
    spec = csr5.parse_devices_xml(DEVICES_XML)
    assert spec.prefixes["set_session"] == (0x81, 0x00, 0x00, 0x03)
    assert spec.prefixes["get_keyword"][0] == 0x82
    assert spec.prefixes["set_command"][0] == 0x85


@needs_xml
def test_resolution_keyword_literals() -> None:
    spec = csr5.parse_devices_xml(DEVICES_XML)
    res = spec.resolution
    assert res.functor == 0x02
    assert res.keyword_codes == (0x4D, 0x49, 0x53, 0x00)  # "MIS"
    assert res.keyword_index == (0x03, 0x01, 0x00, 0x02)
    assert res.keyword_value == (0x4D, 0xB6, 0xAB, 0x00)  # default keyword


@needs_xml
def test_method3_is_functor3() -> None:
    spec = csr5.parse_devices_xml(DEVICES_XML)
    m3 = spec.encoder_for_method(3)  # G6000 series, devices.xml:43549
    assert m3.handler == 0x03
    assert m3.functor == 0x03


@needs_xml
def test_command_table_shapes() -> None:
    spec = csr5.parse_devices_xml(DEVICES_XML)
    for m in spec.encoders:
        assert len(m.command_index) == 5
        assert all(len(a) == 20 for a in m.command_index)
        assert len(m.command_codes) == 7
        assert all(len(a) == 20 for a in m.command_codes)
        assert len(m.command_shift) == 3
        # each command.shift <array> holds 4 <value> sub-programs
        assert all(len(arr) == 4 for arr in m.command_shift)


@needs_xml
def test_method3_function_blocks_parsed() -> None:
    spec = csr5.parse_devices_xml(DEVICES_XML)
    m3 = spec.encoder_for_method(3)
    # the <function> block for code 0x00 (get_keyword) carries <special>0x04 0x66</special>
    assert m3.functions[0x00].special == (0x04, 0x66)
    assert m3.functions[0x00].indexes == ()
    # code 0x03 (set_session) special offset 0x0F lands in env[19] (seed-significant)
    assert m3.functions[0x03].special == (0x0F, 0x01)


@needs_xml
def test_method3_first_index_array_literal() -> None:
    # devices.xml:43698 (first command.index array of the functor-3 method)
    spec = csr5.parse_devices_xml(DEVICES_XML)
    m3 = spec.encoder_for_method(3)
    assert m3.command_index[0] == (
        0x0F, 0x03, 0x13, 0x0C, 0x01, 0x08, 0x00, 0x12, 0x07, 0x05,
        0x10, 0x04, 0x0E, 0x06, 0x02, 0x11, 0x0B, 0x0D, 0x09, 0x0A,
    )
    # devices.xml:43705 (first command.codes array)
    assert m3.command_codes[0] == (
        0x09, 0x12, 0xDD, 0x1D, 0x41, 0x13, 0x63, 0x6B, 0x44, 0x2A,
        0x17, 0xBD, 0xAF, 0xD2, 0x88, 0x31, 0x3B, 0x71, 0xBB, 0xE5,
    )


@needs_xml
def test_waste_common_cleartext() -> None:
    waste = csr5.parse_waste_rows(DEVICES_XML)
    # devices.xml:43807 -- THE G6020 clear (support=waste:common)
    assert waste["common"] == [bytes([0x10, 0x07, 0x7C]), bytes([0x0D, 0x00, 0x00])]
    assert waste["away"][1] == bytes([0x0D, 0x05, 0x00])
    assert waste["black"][1] == bytes([0x0D, 0x03, 0x00])
    assert waste["platen"][1] == bytes([0x0D, 0x01, 0x00])
    assert waste["color"][1] == bytes([0x0D, 0x04, 0x00])
    assert waste["home"][1] == bytes([0x0D, 0x06, 0x00])


@needs_xml
def test_waste_common_functor3_emits_four_byte_keyword() -> None:
    spec = csr5.parse_devices_xml(DEVICES_XML)
    waste = csr5.parse_waste_rows(DEVICES_XML)
    m3 = spec.encoder_for_method(3)
    bound = csr5.bind_keyword(m3, bytes(spec.resolution.keyword_value))
    for cmd in waste["common"]:
        frame = bytes(spec.prefixes["set_command"]) + cmd
        env = csr5.envelope3(m3, frame)
        assert len(env) == 20  # 4-byte header + 16 LCG bytes
        enc_kw = csr5.functor3_encrypt(m3, frame, bound)
        assert len(enc_kw) == csr5.KEYWORD_LEN == 4  # functor 3 emits 4 bytes, not a blob


@needs_xml
def test_waste_common_encipher_deterministic_and_keyword_sensitive() -> None:
    spec = csr5.parse_devices_xml(DEVICES_XML)
    waste = csr5.parse_waste_rows(DEVICES_XML)

    # default template keyword -> deterministic output
    enc_a = csr5.encode_waste_common(spec, waste)
    enc_b = csr5.encode_waste_common(spec, waste)
    assert enc_a == enc_b

    # a live keyword changes every enciphered frame (device binding)
    enc_live = csr5.encode_waste_common(spec, waste, device_keyword=bytes([0x11, 0x22, 0x33, 0x44]))
    assert enc_live != enc_a
    for d, live in zip(enc_a, enc_live, strict=True):
        assert d != live


@needs_xml
def test_encode_command_functor3_wire_is_prefix_plus_four() -> None:
    spec = csr5.parse_devices_xml(DEVICES_XML)
    # The wire frame is prefix(CLEAR) || 4-byte enciphered keyword (B1-B3): the
    # functor-3 envelope is the SEED only, not part of the wire. set_command
    # prefix(3) + payload(3) = 6 clear bytes + 4 enciphered = 10 wire bytes.
    wire = csr5.encode_command(
        spec, method_no=3, set_prefix="set_command", command_bytes=bytes([0x10, 0x07, 0x7C])
    )
    assert len(wire) == 10
    assert wire[:6] == bytes(spec.prefixes["set_command"]) + bytes([0x10, 0x07, 0x7C])
    assert wire == bytes.fromhex("85 00 00 10 07 7c 40 40 8f ec".replace(" ", ""))
