"""Ground-truth regression for the validated functor-2 buffer-role-swap cipher.

Hardware-validated 2026-06-01 (native libusb 5B00 clear on a real G6020): the
genuine ``set_command`` is functor-2 with the buffer roles SWAPPED — SUBJECT =
the 20-byte functor-3 envelope, SEED = the 4-byte bound keyword — and the wire
frame is ``85 00 00 || payload(20)`` = 23 bytes. For the real live keyword
``e4 7c 5a`` (padded ``e4 7c 5a 00`` -> bound ``00 35 a9 09``) this reproduces
WICReset's captured frames byte-exact:

    SELECTOR (operand 10 07 7c): 850000dbbb006759a1b01f842fd583044a3ac351d2b1ef
    CLEAR    (operand 0d 00 00): 8500004dbb006759a1b01f842fd58319a83a627bafb1ef

This file pins those 23/23 frames through BOTH cipher mirrors and proves they
agree:

  1. the package encoder ``protocol.wicreset.build_encoder`` (the SSOT path —
     reads ``maintenance.yaml::derived_template``, NO devices.xml dependency);
  2. the reference ``scripts/canon_sr5_cipher.encode_command`` (parses
     ``/tmp/appbin_out/devices.xml`` directly).

The reference path skips cleanly when devices.xml is absent (CI portability);
the SSOT path ALWAYS runs. A separate sequence/shape test asserts the native
reset transport builds set_session/get_keyword/selector/clear with the validated
EP0 setup fields (0x41/0x85 VENDOR_SET, 0xC1/0x82 VENDOR_GET) and 23-byte frames,
driven entirely through the injectable fakes (no hardware).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from canon_megatank.ops import reset_absorber_wicreset
from canon_megatank.protocol.servicemode_transport import (
    BMREQTYPE_VENDOR_GET,
    BMREQTYPE_VENDOR_SET,
    ServiceModeTransport,
)
from canon_megatank.protocol.wicreset import (
    bind_keyword,
    build_encoder,
    load_method_from_ssot,
)
from canon_megatank.types import PrinterFingerprint

# Import the reference cipher the way MEMORY mandates: sys.path + plain import,
# NOT importlib.spec_from_file_location (custom-name import breaks its dataclass
# annotations). Done once at module import; the module is the validated mirror.
_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
import canon_sr5_cipher as csr5  # noqa: E402 — path set above before import

HAVE_XML = csr5.DEVICES_XML_DEFAULT.exists()
needs_xml = pytest.mark.skipif(not HAVE_XML, reason="devices.xml not present")

# ─── the hardware-validated ground truth ───────────────────────────────────────
# The real live keyword the device returned (3 bytes), padded to the 4-byte
# functor-2 SEED width before binding.
LIVE_KEYWORD = bytes([0xE4, 0x7C, 0x5A, 0x00])
BOUND_KEYWORD = bytes([0x00, 0x35, 0xA9, 0x09])  # bind_keyword(LIVE_KEYWORD)

# The plaintext app frames (3-byte set_command header 85 00 00 + operand).
PT_SELECTOR = bytes([0x85, 0x00, 0x00, 0x10, 0x07, 0x7C])
PT_CLEAR = bytes([0x85, 0x00, 0x00, 0x0D, 0x00, 0x00])

# WICReset's REAL captured frames (23 bytes each, byte-exact).
GT_SELECTOR = bytes.fromhex("850000dbbb006759a1b01f842fd583044a3ac351d2b1ef")
GT_CLEAR = bytes.fromhex("8500004dbb006759a1b01f842fd58319a83a627bafb1ef")

WIRE_LEN = 23  # 3-byte header + 20-byte functor-2 payload

FP = PrinterFingerprint(
    uuid="00000000-0000-1000-8000-00186501807c",
    firmware_version="1.070",
    device_id_raw="",
    cmd_set=(),
)


# ─── (1) the SSOT path: build_encoder reproduces the ground truth (always runs) ─
def test_ssot_encoder_reproduces_ground_truth_selector_and_clear() -> None:
    """``build_encoder`` (SSOT ``derived_template``, no devices.xml), seeded with
    the real live keyword, emits WICReset's captured SELECTOR and CLEAR frames
    byte-exact (23/23) — the hardware-validated functor-2 buffer-role swap."""
    method = load_method_from_ssot()
    # The keyword binding is the documented ground truth: e4 7c 5a 00 -> 00 35 a9 09.
    assert bind_keyword(method, LIVE_KEYWORD) == BOUND_KEYWORD

    enc = build_encoder()
    enc.seed_keyword(LIVE_KEYWORD)

    sel = enc.encipher(PT_SELECTOR)
    clr = enc.encipher(PT_CLEAR)

    assert len(sel) == len(clr) == WIRE_LEN
    assert sel[:3] == clr[:3] == bytes([0x85, 0x00, 0x00])  # the set_command header
    assert sel == GT_SELECTOR
    assert clr == GT_CLEAR


# ─── (2) the reference path: canon_sr5_cipher + devices.xml agrees ──────────────
@needs_xml
def test_reference_cipher_reproduces_ground_truth_selector_and_clear() -> None:
    """``scripts/canon_sr5_cipher.encode_command`` (method 3 parsed straight from
    devices.xml), with the same live keyword, emits the identical 23/23 frames."""
    spec = csr5.parse_devices_xml()
    sel = csr5.encode_command(
        spec,
        method_no=3,
        set_prefix="set_command",
        command_bytes=bytes([0x10, 0x07, 0x7C]),
        device_keyword=LIVE_KEYWORD,
    )
    clr = csr5.encode_command(
        spec,
        method_no=3,
        set_prefix="set_command",
        command_bytes=bytes([0x0D, 0x00, 0x00]),
        device_keyword=LIVE_KEYWORD,
    )
    assert len(sel) == len(clr) == WIRE_LEN
    assert sel == GT_SELECTOR
    assert clr == GT_CLEAR


# ─── (3) the two mirrors agree byte-for-byte (no SSOT-vs-devices.xml drift) ─────
@needs_xml
def test_ssot_and_reference_paths_agree_byte_for_byte() -> None:
    """The SSOT-driven package encoder and the devices.xml-driven reference cipher
    produce IDENTICAL bytes for both frames — the re-synced SSOT ``derived_template``
    carries no drift from the devices.xml-parsed SR5 method (was 17/20 before the
    functor3_functions resync; now 23/23 on both)."""
    enc = build_encoder()
    enc.seed_keyword(LIVE_KEYWORD)
    pkg_sel = enc.encipher(PT_SELECTOR)
    pkg_clr = enc.encipher(PT_CLEAR)

    spec = csr5.parse_devices_xml()
    ref_sel = csr5.encode_command(
        spec, method_no=3, set_prefix="set_command",
        command_bytes=bytes([0x10, 0x07, 0x7C]), device_keyword=LIVE_KEYWORD,
    )
    ref_clr = csr5.encode_command(
        spec, method_no=3, set_prefix="set_command",
        command_bytes=bytes([0x0D, 0x00, 0x00]), device_keyword=LIVE_KEYWORD,
    )

    assert pkg_sel == ref_sel == GT_SELECTOR
    assert pkg_clr == ref_clr == GT_CLEAR


# ─── (4) sequence/shape: the native reset builds the right transport frames ─────
class RecordingCtrl:
    """Injectable control-transfer fake: records every EP0 setup tuple and serves
    the 3-byte live keyword on the get_keyword VENDOR_GET (bRequest 0x82). The
    set_session ack and the get_command (0x86) RECV return empty, as the real
    device does (0x86 is empty by design; there is no finalize command)."""

    def __init__(self, keyword: bytes = bytes([0xE4, 0x7C, 0x5A])) -> None:
        self.calls: list[tuple[str, int, int, int, bytes | int]] = []
        self._keyword = keyword

    def __call__(  # noqa: PLR0913 — mirrors the USB setup packet (5 wire fields)
        self,
        bm: int,
        br: int,
        wv: int,
        wi: int,
        data_or_len: bytes | int,
        *,
        timeout_ms: int = 5000,
    ) -> bytes:
        is_in = bool(bm & 0x80)
        self.calls.append(("IN" if is_in else "OUT", bm, br, wv, data_or_len))
        if is_in:
            return self._keyword if br == 0x82 else b""  # 0x82 = get_keyword
        return b""


def test_native_reset_builds_setsession_getkeyword_selector_clear_frames() -> None:
    """Driving ``reset_absorber_wicreset`` through ``ServiceModeTransport`` (the
    validated native path) issues, IN ORDER, set_session / get_keyword / SELECTOR
    / CLEAR / get_command with the validated EP0 setup fields:

      * set_session  -> VENDOR_SET OUT 0x41/0x81, whole frame verbatim
      * get_keyword  -> VENDOR_GET IN  0xC1/0x82 (returns the live keyword)
      * SELECTOR     -> VENDOR_SET OUT 0x41/0x85, 23-byte frame (ground truth)
      * CLEAR        -> VENDOR_SET OUT 0x41/0x85, 23-byte frame (ground truth)
      * get_command  -> VENDOR_GET IN  0xC1/0x86 (empty by design, never gated)

    Everything runs through the injectable fakes — no hardware, no SSOT mutation."""
    ctrl = RecordingCtrl()
    transport = ServiceModeTransport(ctrl)

    plan = reset_absorber_wicreset(
        transport,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=build_encoder(printer_id="canon-g6020"),
        execute=True,
        accept_derived=True,  # status is derived-unvalidated on the live SSOT
        verify=lambda _fp, _pid: None,
        keyword_min_len=3,  # native VENDOR_GET returns a 3-byte live keyword
        keyword_pad_to=4,  # functor-2 SEED is 4 bytes -> 0x00-pad
    )

    assert plan.executed is True
    assert plan.device_keyword == LIVE_KEYWORD  # 3-byte read padded to 4

    # The exact ordered (direction, bmRequestType, bRequest) shape.
    dirs = [(k, bm, br) for k, bm, br, _wv, _d in ctrl.calls]
    assert dirs == [
        ("OUT", BMREQTYPE_VENDOR_SET, 0x81),  # set_session
        ("IN", BMREQTYPE_VENDOR_GET, 0x82),   # get_keyword
        ("OUT", BMREQTYPE_VENDOR_SET, 0x85),  # SELECTOR
        ("OUT", BMREQTYPE_VENDOR_SET, 0x85),  # CLEAR
        ("IN", BMREQTYPE_VENDOR_GET, 0x86),   # get_command verify
    ]
    # VENDOR_SET is 0x41 (vendor | iface | host->device); VENDOR_GET is 0xC1.
    assert BMREQTYPE_VENDOR_SET == 0x41
    assert BMREQTYPE_VENDOR_GET == 0xC1

    # The two set_command OUT frames are 23-byte (header || payload(20)) and equal
    # WICReset's captured ground truth, pushed whole/verbatim on the wire.
    set_cmd_out = [d for k, _bm, br, _wv, d in ctrl.calls if k == "OUT" and br == 0x85]
    assert len(set_cmd_out) == 2
    assert all(isinstance(d, bytes) and len(d) == WIRE_LEN for d in set_cmd_out)
    assert set_cmd_out[0] == GT_SELECTOR
    assert set_cmd_out[1] == GT_CLEAR

    # set_session (81 00 00 03) is sent PLAIN — pushed VERBATIM on the OUT stage,
    # NOT enciphered: the device length-validates 0x81 to exactly its 4 plaintext
    # bytes and STALLs an enciphered frame (hardware-validated 2026-06-01). The
    # 4-byte plaintext frame is the wire. The IN read stages carry an int
    # read-length, not data.
    (_, _, _, _, ss_data) = ctrl.calls[0]
    assert isinstance(ss_data, bytes)
    assert ss_data == bytes([0x81, 0x00, 0x00, 0x03])  # plain set_session, 4 bytes verbatim
    for k, _bm, _br, _wv, payload in ctrl.calls:
        if k == "IN":
            assert isinstance(payload, int)  # read length, not OUT data


def test_native_reset_empty_get_command_does_not_gate_the_clear() -> None:
    """The trailing get_command (0x86) RECV is empty by design — the op records it
    as an empty reply, NOT an error, and reports the clear done off the two writes."""
    ctrl = RecordingCtrl(keyword=bytes([0x11, 0x22, 0x33]))
    transport = ServiceModeTransport(ctrl)
    plan = reset_absorber_wicreset(
        transport,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=build_encoder(printer_id="canon-g6020"),
        execute=True,
        accept_derived=True,
        verify=lambda _fp, _pid: None,
        keyword_min_len=3,
        keyword_pad_to=4,
    )
    assert plan.executed is True
    gv = plan.steps[-1]
    assert gv.kind == "get_command"
    assert gv.reply == b""
    assert "CLEARED" in plan.outcome.response_summary
    assert "POWER-BUTTON" in plan.outcome.response_summary  # mandatory commit step
