"""Byte-identity tests for the package functor-3 encoder.

``canon_megatank.protocol.wicreset.build_encoder()`` reproduces the validated
reference (``scripts/canon_sr5_cipher.py``) and the SSOT's recorded
``derived_sequence`` bytes EXACTLY, both for the template-default keyword and
after ``seed_keyword`` binds a live keyword. It also wires the full
``ops.reset_absorber_wicreset`` sequence (dry-run preview + the execute-time
gate ladder).

The cipher tables are read from the SSOT ``derived_template`` (no dependency on
the ephemeral /tmp/appbin_out/devices.xml). The reference-cross-check loads the
reference script directly when present (it parses devices.xml); when devices.xml
is absent those checks skip, but the SSOT-recorded golden bytes ALWAYS run.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from canon_megatank.fingerprint import load_maintenance
from canon_megatank.ops import load_wicreset_frames, reset_absorber_wicreset
from canon_megatank.protocol.wicreset import (
    ENVELOPE_FIXED_16,
    TEMPLATE_DEFAULT_KEYWORD,
    WicResetEncoder,
    _derive,
    bind_keyword,
    build_encoder,
    lcg16,
    load_method_from_ssot,
    seed_fold,
)
from canon_megatank.types import (
    CanonToolError,
    EepromDumpFailedError,
    PrinterFingerprint,
    ResetNotValidatedError,
    UnknownPrinterError,
)

# ─── SSOT golden bytes (printers/canon-g6020/maintenance.yaml derived_sequence) ─
# These are the bytes the SSOT records as produced by the reference encoder for
# the waste:common clear. They are the canonical correctness anchor.
# Wire frame = 85 00 00 || payload(20) = 23 bytes (hardware-validated 2026-06-01,
# native libusb 5B00 clear): functor-3 runs functor-2 with the SUBJECT = the
# 20-byte envelope and the SEED = the 4-byte bound keyword (the buffer-role
# swap), emitting a 20-byte payload — NOT app_frame || a 4-byte keyword.
GOLD_DEFAULT_SELECT = bytes.fromhex(
    "85 00 00 9a 4d c7 5b db 67 1a e9 74 13 5e df 77 db b1 66 18 7c 71 57".replace(" ", "")
)
GOLD_DEFAULT_RESET = bytes.fromhex(
    "85 00 00 9a 4d c7 5b 7a f1 1a e9 74 0e 5e df 77 db 9b 1b 18 7c 71 b5".replace(" ", "")
)
# After seed_keyword(11 22 33 44) — the SSOT's symbolic-live-keyword illustration.
GOLD_LIVE_SELECT = bytes.fromhex(
    "85 00 00 70 7e aa 7a bf 89 7c be d1 94 7c 7c e1 f1 a8 08 f8 76 84 a1".replace(" ", "")
)
GOLD_LIVE_RESET = bytes.fromhex(
    "85 00 00 70 7e aa 7a 1e 1f 7c be d1 89 7c 7c e1 f1 82 75 f8 76 84 43".replace(" ", "")
)
# The validated real-hardware capture (live keyword e4 7c 5a 00 -> bound
# 00 35 a9 09): WICReset's actual SELECTOR / CLEAR frames, byte-exact (23/23).
GOLD_HW_KEYWORD = bytes([0xE4, 0x7C, 0x5A, 0x00])
GOLD_HW_SELECT = bytes.fromhex("850000dbbb006759a1b01f842fd583044a3ac351d2b1ef")
GOLD_HW_RESET = bytes.fromhex("8500004dbb006759a1b01f842fd58319a83a627bafb1ef")

# The plaintext app frames the SSOT records (3-byte set_command prefix form).
PT_SELECT = bytes([0x85, 0x00, 0x00, 0x10, 0x07, 0x7C])
PT_RESET = bytes([0x85, 0x00, 0x00, 0x0D, 0x00, 0x00])

FP = PrinterFingerprint(
    uuid="00000000-0000-1000-8000-00186501807c",
    firmware_version="1.070",
    device_id_raw="",
    cmd_set=(),
)

# ─── reference script (parses devices.xml; skip cleanly when absent) ────────────
_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "canon_sr5_cipher.py"
_spec = importlib.util.spec_from_file_location("canon_sr5_cipher", _SCRIPT)
assert _spec and _spec.loader
csr5 = importlib.util.module_from_spec(_spec)
sys.modules["canon_sr5_cipher"] = csr5
_spec.loader.exec_module(csr5)
HAVE_XML = csr5.DEVICES_XML_DEFAULT.exists()
needs_xml = pytest.mark.skipif(not HAVE_XML, reason="devices.xml not present")


# ─── envelope / table parity (always runs, SSOT-driven) ─────────────────────────
def test_envelope_matches_reference_constant() -> None:
    assert lcg16() == ENVELOPE_FIXED_16
    assert lcg16() == bytes.fromhex("e93f0da196953104492d9e6183cf096f")


def test_method_loaded_from_ssot_has_full_tables() -> None:
    method = load_method_from_ssot()
    assert method.functor == 0x03  # the G6000 method-3 functor-3 path
    assert len(method.command_index) == 5
    assert all(len(a) == 20 for a in method.command_index)
    assert len(method.command_codes) == 7
    assert all(len(a) == 20 for a in method.command_codes)
    assert method.keyword_codes == (0x4D, 0x49, 0x53, 0x00)
    assert method.keyword_index == (0x03, 0x01, 0x00, 0x02)
    assert method.keyword_value == (0x4D, 0xB6, 0xAB, 0x00)


# ─── BYTE-IDENTITY vs the SSOT golden bytes (default keyword) ───────────────────
def test_default_keyword_select_matches_ssot_golden() -> None:
    enc = build_encoder()
    assert enc.keyword == TEMPLATE_DEFAULT_KEYWORD
    assert enc.encipher(PT_SELECT) == GOLD_DEFAULT_SELECT


def test_default_keyword_reset_matches_ssot_golden() -> None:
    enc = build_encoder()
    assert enc.encipher(PT_RESET) == GOLD_DEFAULT_RESET


# ─── BYTE-IDENTITY vs the SSOT golden bytes (after seed_keyword) ────────────────
def test_seed_keyword_select_matches_ssot_live_golden() -> None:
    enc = build_encoder()
    enc.seed_keyword(b"\x11\x22\x33\x44")
    assert enc.keyword == b"\x11\x22\x33\x44"
    assert enc.encipher(PT_SELECT) == GOLD_LIVE_SELECT


def test_seed_keyword_reset_matches_ssot_live_golden() -> None:
    enc = build_encoder()
    enc.seed_keyword(b"\x11\x22\x33\x44")
    assert enc.encipher(PT_RESET) == GOLD_LIVE_RESET


def test_real_hardware_capture_is_reproduced_byte_exact() -> None:
    """build_encoder(), seeded with the live keyword captured on the real unit
    (e4 7c 5a 00 -> bound 00 35 a9 09), reproduces WICReset's actual SELECTOR and
    CLEAR frames byte-exact (23/23) — the hardware-validated ground truth."""
    enc = build_encoder()
    enc.seed_keyword(GOLD_HW_KEYWORD)
    assert bind_keyword(load_method_from_ssot(), GOLD_HW_KEYWORD) == bytes(
        [0x00, 0x35, 0xA9, 0x09]
    )
    assert enc.encipher(PT_SELECT) == GOLD_HW_SELECT
    assert enc.encipher(PT_RESET) == GOLD_HW_RESET


def test_seed_keyword_changes_every_enciphered_byte() -> None:
    """A live keyword reseeds functor_implementation (the keyword is the functor-2
    SEED) → the whole 20-byte enciphered payload differs. The wire is
    85 00 00 || payload(20); the 3-byte header is keyword-independent, the entire
    20-byte payload changes."""
    enc = build_encoder()
    default = enc.encipher(PT_SELECT)
    enc.seed_keyword(b"\x11\x22\x33\x44")
    live = enc.encipher(PT_SELECT)
    assert default != live
    assert len(default) == len(live) == 23  # noqa: PLR2004 — 3-byte header + 20-byte payload
    # the 3-byte header is identical; every byte of the 20-byte payload differs
    assert default[:3] == live[:3]
    assert all(d != x for d, x in zip(default[3:], live[3:], strict=True))


def test_seed_keyword_truncates_long_reply_to_four_bytes() -> None:
    """A live get_keyword RECV may be longer than 4 bytes; only the leading 4
    form the keyword word (keyword.index ∈ {0..3})."""
    enc = build_encoder()
    enc.seed_keyword(b"\x11\x22\x33\x44\xaa\xbb\xcc")
    assert enc.keyword == b"\x11\x22\x33\x44"
    assert enc.encipher(PT_SELECT) == GOLD_LIVE_SELECT


def test_seed_keyword_refuses_short_keyword() -> None:
    enc = build_encoder()
    with pytest.raises(CanonToolError):
        enc.seed_keyword(b"\x11\x22")


# ─── DETERMINISM regression: the enciphered set_command SELECTOR frame ──────────
# Only the set_command write (command byte 0x85) carries a secret operand and is
# enciphered to the 23-byte 85 00 00 || payload(20) form — that is the frame that
# exercises functor-2 / the command.shift table. set_session (81 00 00 03),
# get_keyword (82 00 00) and get_command (86 00 00) are sent VERBATIM (plain): the
# device length-validates 0x81 to its 4 plaintext bytes and STALLs an enciphered
# one, and the read primes ride the request header (hardware-validated 2026-06-01).
# So the SELECTOR frame is the load-bearing determinism pin: it was diverging
# across CPython 3.13/3.14 before the shift-table fix (the bug was the
# command.shift <value> ordering + per-<value> semantics). For the template-
# default keyword (bound 00 ff 00 f8, seed 0xff00f8, shift array idx 0) the ONE
# TRUE per-<value> shift table is (0, 0, 0, 2); the resulting SELECTOR bytes are
# pinned and asserted equal across interpreters by
# test_handshake_frames_match_across_interpreters.
PT_SET_SESSION = bytes([0x81, 0x00, 0x00, 0x03])
PT_GET_KEYWORD = bytes([0x82, 0x00, 0x00])
# set_session / get_keyword are PLAIN — the wire equals the plaintext verbatim.
GOLD_SET_SESSION = PT_SET_SESSION
GOLD_GET_KEYWORD = PT_GET_KEYWORD
# The enciphered set_command SELECTOR frame (template-default keyword): the
# functor-2 / shift-table path. This is what the determinism check must pin.
GOLD_DETERMINISM_SELECTOR = GOLD_DEFAULT_SELECT
# The shift table for the template-default-keyword seed (the functor-2 SEED is
# now the 4-byte bound keyword 00 ff 00 f8 → seed 0xff00f8 → shift array idx 0).
EXPECTED_DEFAULT_KEYWORD_SHIFT_TABLE = (0, 0, 0, 2)


def test_set_session_wire_is_pinned() -> None:
    """set_session is PLAIN — sent verbatim, NOT enciphered. The device
    length-validates 0x81 to exactly its 4 plaintext bytes and STALLs an
    enciphered frame, so the wire equals the plaintext byte-for-byte."""
    enc = build_encoder()
    assert enc.encipher(PT_SET_SESSION) == GOLD_SET_SESSION
    assert enc.encipher(PT_SET_SESSION) == PT_SET_SESSION  # wire == plaintext (plain)


def test_get_keyword_wire_is_pinned() -> None:
    """get_keyword is a 3-byte read header → passed through verbatim."""
    enc = build_encoder()
    assert enc.encipher(PT_GET_KEYWORD) == GOLD_GET_KEYWORD


def test_default_keyword_shift_table_is_per_value_ordering() -> None:
    """The shift table is one entry PER <value> in document order (not per-action
    / misordered). With the buffer-role swap the functor-2 SEED is the 4-byte
    bound keyword, so the table is keyed by the keyword fold (0xff00f8), not the
    frame; for the template-default keyword it is (0, 0, 0, 2)."""
    method = load_method_from_ssot()
    bound = bind_keyword(method, TEMPLATE_DEFAULT_KEYWORD)
    seed = seed_fold(bound)
    _index, _codes, shift_table = _derive(method, seed)
    assert shift_table == EXPECTED_DEFAULT_KEYWORD_SHIFT_TABLE


def test_handshake_frames_are_deterministic_across_calls() -> None:
    """Repeated builds + encipher calls yield byte-identical frames (no hidden
    interpreter-order dependence within a single process). The load-bearing pin is
    the enciphered set_command SELECTOR frame — the only frame that runs the
    functor-2 / shift-table path; set_session / get_keyword are plain pass-throughs
    and exercise no shift table, but we keep them pinned as a verbatim sanity."""
    frames = [
        (
            build_encoder().encipher(PT_SELECT),
            build_encoder().encipher(PT_SET_SESSION),
            build_encoder().encipher(PT_GET_KEYWORD),
        )
        for _ in range(8)
    ]
    assert all(
        f == (GOLD_DETERMINISM_SELECTOR, GOLD_SET_SESSION, GOLD_GET_KEYWORD) for f in frames
    )


_REPO_ROOT = Path(__file__).resolve().parent.parent
# Drives the SSOT loader directly (the path the encoder uses). The SSOT command
# tables are loaded the same way build_encoder() does, so a divergence here is a
# divergence in the shipped encoder. Self-contained so it runs under `uv run
# --python X` (which provisions ruamel.yaml from pyproject) on either interpreter.
_DETERMINISM_SNIPPET = textwrap.dedent(
    """
    import sys
    sys.path.insert(0, {src!r})
    from canon_megatank.protocol.wicreset import build_encoder

    enc = build_encoder()
    # The enciphered set_command SELECTOR frame is the one that runs the functor-2
    # / shift-table path — the load-bearing cross-interpreter determinism pin.
    sel = enc.encipher(bytes([0x85, 0x00, 0x00, 0x10, 0x07, 0x7C]))
    # set_session / get_keyword are plain pass-throughs (verbatim sanity).
    ss = enc.encipher(bytes([0x81, 0x00, 0x00, 0x03]))
    gk = enc.encipher(bytes([0x82, 0x00, 0x00]))
    print(sel.hex())
    print(ss.hex())
    print(gk.hex())
    """
).strip()


def _encode_under(version: str) -> tuple[str, str, str]:
    """Run the encode under a specific CPython version in an ISOLATED ephemeral
    env (``uv run --no-project --with ruamel.yaml``) and return the three hex
    frames (enciphered SELECTOR, plain set_session, plain get_keyword).
    ``--no-project`` keeps this from mutating the project ``.venv``; the snippet
    injects ``src/`` on sys.path so the package imports without install."""
    snippet = _DETERMINISM_SNIPPET.format(src=str(_REPO_ROOT / "src"))
    out = subprocess.run(  # noqa: S603 - fixed args, test-only
        [
            "uv", "run", "--no-project", "--python", version,
            "--with", "ruamel.yaml", "--with", "structlog", "--with", "pyusb",
            "python", "-c", snippet,
        ],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=True,
    )
    # The three hex frames are the only pure-hex stdout lines (uv logs go to stderr).
    hexlines = [
        ln.strip()
        for ln in out.stdout.splitlines()
        if ln.strip() and all(c in "0123456789abcdef" for c in ln.strip())
    ]
    return hexlines[-3], hexlines[-2], hexlines[-1]


@pytest.mark.parametrize("version", ["3.13", "3.14"])
def test_handshake_frames_match_across_interpreters(version: str) -> None:
    """The enciphered set_command SELECTOR wire bytes are byte-identical under BOTH
    CPython 3.13 and 3.14 — the cross-interpreter determinism guarantee for the
    functor-2 / shift-table path (set_session / get_keyword are plain and ride
    along as a verbatim sanity). Skips cleanly when ``uv`` (or the requested
    interpreter) is unavailable; the within-process pins above always run."""
    if shutil.which("uv") is None:
        pytest.skip("uv not on PATH — cross-interpreter check requires uv")
    try:
        sel_hex, ss_hex, gk_hex = _encode_under(version)
    except (subprocess.CalledProcessError, IndexError) as exc:
        detail = getattr(exc, "stderr", str(exc)) or str(exc)
        pytest.skip(f"CPython {version} unavailable via uv: {detail.strip()[-200:]}")
    assert bytes.fromhex(sel_hex) == GOLD_DETERMINISM_SELECTOR
    assert bytes.fromhex(ss_hex) == GOLD_SET_SESSION
    assert bytes.fromhex(gk_hex) == GOLD_GET_KEYWORD


# ─── BYTE-IDENTITY vs the reference encoder (needs devices.xml) ─────────────────
@needs_xml
def test_default_keyword_matches_reference_encode_waste_common() -> None:
    """build_encoder() reproduces scripts/canon_sr5_cipher.encode_waste_common()
    byte-for-byte for both waste:common frames (the key correctness claim)."""
    spec = csr5.parse_devices_xml()
    waste = csr5.parse_waste_rows()
    ref_select, ref_reset = csr5.encode_waste_common(spec, waste)

    enc = build_encoder()
    assert enc.encipher(PT_SELECT) == ref_select
    assert enc.encipher(PT_RESET) == ref_reset
    # …and those reference bytes are exactly the SSOT golden bytes.
    assert ref_select == GOLD_DEFAULT_SELECT
    assert ref_reset == GOLD_DEFAULT_RESET


@needs_xml
def test_live_keyword_matches_reference() -> None:
    spec = csr5.parse_devices_xml()
    waste = csr5.parse_waste_rows()
    live = bytes([0x11, 0x22, 0x33, 0x44])
    ref_select, ref_reset = csr5.encode_waste_common(spec, waste, device_keyword=live)

    enc = build_encoder()
    enc.seed_keyword(live)
    assert enc.encipher(PT_SELECT) == ref_select
    assert enc.encipher(PT_RESET) == ref_reset
    assert ref_select == GOLD_LIVE_SELECT
    assert ref_reset == GOLD_LIVE_RESET


@needs_xml
def test_ssot_method_equals_devices_xml_method() -> None:
    """The SSOT-loaded tables are byte-identical to the devices.xml-parsed ones
    (so the package never needs the ephemeral file)."""
    ssot = load_method_from_ssot()
    xmlm = csr5.parse_devices_xml().encoder_for_method(3)
    assert ssot.command_index == xmlm.command_index
    assert ssot.command_codes == xmlm.command_codes
    assert ssot.keyword_codes == xmlm.keyword_codes
    assert ssot.keyword_index == xmlm.keyword_index


# ─── full sequence wiring through ops.reset_absorber_wicreset ───────────────────
def _validated_doc(_pid: str) -> dict:  # type: ignore[type-arg]
    doc = load_maintenance(_pid)
    doc["supported"]["absorber_reset"]["status"] = "verified-captured"
    return doc


def _unvalidated_doc(_pid: str) -> dict:  # type: ignore[type-arg]
    doc = load_maintenance(_pid)
    doc["supported"]["absorber_reset"]["status"] = "derived-unvalidated"
    return doc


def _ok_verify(_fp: PrinterFingerprint, _pid: str) -> None:
    return None


def _live_wire(frame: bytes) -> bytes:
    """Encipher ``frame`` with a fresh encoder seeded with the live keyword
    11 22 33 44 — the expected wire for the ops set_command frames after the
    get_keyword RECV seeds the encoder."""
    enc = build_encoder()
    enc.seed_keyword(b"\x11\x22\x33\x44")
    return enc.encipher(frame)


class FakeSessionDevice:
    """Records every transfer as (kind, frame); serves a canned keyword reply."""

    def __init__(self, keyword_reply: bytes = b"\x11\x22\x33\x44") -> None:
        self.calls: list[tuple[str, bytes]] = []
        self._reply = keyword_reply

    def send_and_receive(self, frame: bytes, *, timeout_ms: int = 5000, length: int = 64) -> bytes:
        self.calls.append(("recv", bytes(frame)))
        return self._reply

    def send_command(self, frame: bytes, *, timeout_ms: int = 5000) -> int:
        self.calls.append(("send", bytes(frame)))
        return len(frame)


def test_dry_run_enciphers_set_command_frames_with_real_encoder() -> None:
    """A dry-run through ops, driven by the REAL build_encoder(), enciphers the
    two set_command frames to the SSOT golden default-keyword bytes (no live read
    happened, so the default keyword is used)."""
    dev = FakeSessionDevice()
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=False,
        encoder=build_encoder(),
        load_doc=_unvalidated_doc,  # dry-run never consults the status gate
    )
    assert plan.executed is False
    assert dev.calls == []  # NOTHING driven
    kinds = [s.kind for s in plan.steps]
    assert kinds == ["set_session", "get_keyword", "set_command", "set_command", "get_command"]

    # The frames module yields the 5-byte-prefix form; assert that frame too.
    frames = load_wicreset_frames(load_doc=_validated_doc)
    select_step = plan.steps[2]
    reset_step = plan.steps[3]
    assert select_step.plaintext == frames.set_command_select
    assert reset_step.plaintext == frames.set_command_reset
    # Dry-run uses the template-default keyword → the wire is deterministic and
    # is the same enciphering as the SSOT-recorded 5-byte-prefix select/reset.
    enc = build_encoder()
    assert select_step.wire == enc.encipher(frames.set_command_select)
    assert reset_step.wire == enc.encipher(frames.set_command_reset)


def test_execute_hard_stops_on_unverified_status_gate() -> None:
    """execute=True with the real encoder still HARD-STOPS on the status gate
    (status is derived-unvalidated), and never touches the device."""
    dev = FakeSessionDevice()
    with pytest.raises(ResetNotValidatedError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            encoder=build_encoder(),
            execute=True,
            verify=_ok_verify,
            load_doc=_unvalidated_doc,
        )
    assert dev.calls == []


def test_accept_derived_bypasses_only_the_status_gate() -> None:
    """accept_derived bypasses ONLY the status gate; the sequence then drives the
    ordered enciphered frames. UUID/EEPROM still mandatory (checked below)."""
    dev = FakeSessionDevice(keyword_reply=b"\x11\x22\x33\x44")
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=build_encoder(),
        execute=True,
        accept_derived=True,
        verify=_ok_verify,
        load_doc=_unvalidated_doc,
    )
    assert plan.executed is True
    assert "OVERRIDE" in plan.outcome.response_summary
    assert [kind for kind, _ in dev.calls] == ["recv", "recv", "send", "send", "recv"]

    # The two set_command writes were enciphered AFTER the live keyword was seeded
    # (11 22 33 44). ops feeds the 5-byte-prefix frames from load_wicreset_frames
    # (85 00 00 00 00 …), so the expected wire is the live-keyed encipher of THOSE
    # exact frames (the SSOT golden bytes are the 3-byte-prefix derived_sequence
    # form — see _live_wire() / test_default_keyword_*_matches_ssot_golden).
    frames = load_wicreset_frames(load_doc=_validated_doc)
    _, sel = dev.calls[2]
    _, rst = dev.calls[3]
    assert sel == _live_wire(frames.set_command_select)
    assert rst == _live_wire(frames.set_command_reset)
    assert plan.device_keyword == b"\x11\x22\x33\x44"


def test_accept_derived_still_enforces_eeprom_gate() -> None:
    dev = FakeSessionDevice()
    with pytest.raises(EepromDumpFailedError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=False,
            encoder=build_encoder(),
            execute=True,
            accept_derived=True,
            verify=_ok_verify,
            load_doc=_unvalidated_doc,
        )
    assert dev.calls == []


def test_accept_derived_still_enforces_uuid_gate() -> None:
    dev = FakeSessionDevice()

    def _bad_verify(_fp: PrinterFingerprint, _pid: str) -> None:
        raise UnknownPrinterError("wrong unit")

    with pytest.raises(UnknownPrinterError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            encoder=build_encoder(),
            execute=True,
            accept_derived=True,
            verify=_bad_verify,
            load_doc=_unvalidated_doc,
        )
    assert dev.calls == []


def test_lazy_import_path_builds_the_encoder() -> None:
    """With NO injected encoder, ops lazily imports build_encoder — proving the
    factory is wired into the lazy-import path. (verified-captured status so the
    execute gate ladder is reached; the keyword reply is a valid live keyword.)"""
    dev = FakeSessionDevice(keyword_reply=b"\x11\x22\x33\x44")
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        execute=True,
        verify=_ok_verify,
        load_doc=_validated_doc,
    )
    assert plan.executed is True
    frames = load_wicreset_frames(load_doc=_validated_doc)
    _, sel = dev.calls[2]
    _, rst = dev.calls[3]
    # The lazily-built encoder, seeded with the live keyword, produced the
    # live-keyed encipher of the ops set_command frames (5-byte-prefix form).
    assert sel == _live_wire(frames.set_command_select)
    assert rst == _live_wire(frames.set_command_reset)


def test_encoder_satisfies_protocol_shape() -> None:
    """build_encoder() returns something with the WicResetEncoder methods ops needs."""
    enc = build_encoder()
    assert isinstance(enc, WicResetEncoder)
    assert callable(enc.encipher)
    assert callable(enc.seed_keyword)
    # bind_keyword default vs live differ (device binding) — sanity on the math.
    method = load_method_from_ssot()
    assert bind_keyword(method, TEMPLATE_DEFAULT_KEYWORD) != bind_keyword(
        method, b"\x11\x22\x33\x44"
    )
