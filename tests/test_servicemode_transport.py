"""Tests for the native usbprint-derived service-mode transport + its use as the
WICReset session device in ``ops.reset_absorber_wicreset``.

``protocol.servicemode_transport.ServiceModeTransport`` replicates, on libusb, the
EXACT EP0 vendor control transfers usbprint.sys emits (see that module's docstring
+ docs/research/usbprint-vendor-urb-mapping.md). This is the path that cleared 5B00
on real hardware 2026-06-01. These tests pin:

  (a) the per-frame DIRECTION + setup fields match the validated reference
      (set_session 0x41/0x81 OUT, get_keyword 0xC1/0x82 IN, set_command 0x41/0x85
      OUT, get_command 0xC1/0x86 IN);
  (b) the OUT data stage is the WHOLE frame VERBATIM (usbprint does not strip the
      prefix) — a split frame STALLs on hardware;
  (c) driving ``ops.reset_absorber_wicreset`` through the transport with the
      corrected encoder reproduces WICReset's captured ground-truth 23-byte
      SELECTOR/CLEAR frames byte-exact, with the live 3-byte keyword padded to 4;
  (d) the get_command (0x86) RECV is empty by design and does NOT gate the clear.
"""

from __future__ import annotations

from canon_megatank.ops import reset_absorber_wicreset
from canon_megatank.protocol.servicemode_transport import (
    BMREQTYPE_VENDOR_GET,
    BMREQTYPE_VENDOR_SET,
    ServiceModeTransport,
    vendor_set_setup,
)
from canon_megatank.protocol.wicreset import build_encoder
from canon_megatank.types import PrinterFingerprint

FP = PrinterFingerprint(
    uuid="00000000-0000-1000-8000-00186501807c",
    firmware_version="1.070",
    device_id_raw="",
    cmd_set=(),
)

# WICReset's real captured ground-truth frames (live keyword e4 7c 5a -> padded
# e4 7c 5a 00 -> bound 00 35 a9 09), pinned in the SSOT hardware_validated_frames.
GT_SELECTOR = bytes.fromhex("850000dbbb006759a1b01f842fd583044a3ac351d2b1ef")
GT_CLEAR = bytes.fromhex("8500004dbb006759a1b01f842fd58319a83a627bafb1ef")
LIVE_KEYWORD_3B = bytes([0xE4, 0x7C, 0x5A])


class RecordingCtrl:
    """Records every EP0 control transfer and serves the 3-byte live keyword on the
    get_keyword VENDOR_GET (bRequest 0x82). set_session ack + get_command(0x86) RECVs
    return empty (as the real device does)."""

    def __init__(self, keyword: bytes = LIVE_KEYWORD_3B) -> None:
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
        kind = "IN" if is_in else "OUT"
        self.calls.append((kind, bm, br, wv, data_or_len))
        if is_in:
            return self._keyword if br == 0x82 else b""  # noqa: PLR2004 — 0x82 = get_keyword
        return b""


# ─── (a)/(b) per-frame setup resolution ───────────────────────────────────────


def test_vendor_set_pushes_whole_frame_verbatim() -> None:
    """usbprint does NOT strip the [cmd][arg][arg] prefix — the OUT data stage is
    the WHOLE frame. bRequest = frame[0], wValue = (frame[1]<<8)|frame[2]."""
    s = vendor_set_setup(GT_SELECTOR)
    assert s.bm_request_type == BMREQTYPE_VENDOR_SET  # 0x41 (vendor, iface, OUT)
    assert s.b_request == 0x85
    assert s.w_value == 0x0000
    assert s.data_or_length == GT_SELECTOR  # all 23 bytes, verbatim
    assert s.is_out


def test_send_command_drives_vendor_set_out() -> None:
    ctrl = RecordingCtrl()
    transport = ServiceModeTransport(ctrl)
    n = transport.send_command(GT_CLEAR)
    assert n == len(GT_CLEAR)
    (kind, bm, br, wv, data), = ctrl.calls
    assert (kind, bm, br, wv) == ("OUT", BMREQTYPE_VENDOR_SET, 0x85, 0x0000)
    assert data == GT_CLEAR  # whole frame verbatim


def test_send_and_receive_routes_read_header_to_vendor_get_in() -> None:
    """A bare 3-byte read header (82/86 00 00) -> VENDOR_GET control-IN (0xC1)."""
    ctrl = RecordingCtrl()
    transport = ServiceModeTransport(ctrl)
    reply = transport.send_and_receive(bytes([0x82, 0x00, 0x00]))
    assert reply == LIVE_KEYWORD_3B
    (kind, bm, br, wv, length), = ctrl.calls
    assert (kind, bm, br, wv) == ("IN", BMREQTYPE_VENDOR_GET, 0x82, 0x0000)
    assert isinstance(length, int)  # IN read length, not data


def test_send_and_receive_routes_write_shaped_frame_to_vendor_set_out() -> None:
    """A write-shaped frame (set_session, > 3 bytes / carries an operand) is the
    validated VENDOR_SET OUT (0x41/0x81), not an IN — routing it IN STALLed live."""
    ctrl = RecordingCtrl()
    transport = ServiceModeTransport(ctrl)
    ss = bytes([0x81, 0x00, 0x00, 0x03, 0x2D, 0x2D, 0xBA, 0x2B])
    reply = transport.send_and_receive(ss)
    assert reply == b""  # OUT has no IN data stage; op discards it
    (kind, bm, br, wv, data), = ctrl.calls
    assert (kind, bm, br, wv) == ("OUT", BMREQTYPE_VENDOR_SET, 0x81, 0x0000)
    assert data == ss  # whole frame verbatim


# ─── (c)/(d) end-to-end through ops.reset_absorber_wicreset ────────────────────


def test_native_sequence_reproduces_ground_truth_frames() -> None:
    """The op driven through ServiceModeTransport with the real encoder reproduces
    WICReset's captured SELECTOR/CLEAR byte-exact (23/23), with the live 3-byte
    keyword padded to 4 — the validated native clear, end to end."""
    ctrl = RecordingCtrl(keyword=LIVE_KEYWORD_3B)
    transport = ServiceModeTransport(ctrl)
    plan = reset_absorber_wicreset(
        transport,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=build_encoder(printer_id="canon-g6020"),
        execute=True,
        accept_derived=True,
        verify=lambda _fp, _pid: None,
        keyword_min_len=3,  # native VENDOR_GET returns a 3-byte live keyword
        keyword_pad_to=4,  # functor-2 SEED is 4 bytes -> 0x00-pad
    )
    assert plan.executed is True
    assert plan.device_keyword == bytes([0xE4, 0x7C, 0x5A, 0x00])  # padded

    # Directions + requests match the validated native reference, in order.
    dirs = [(k, bm, br) for k, bm, br, _wv, _d in ctrl.calls]
    assert dirs == [
        ("OUT", BMREQTYPE_VENDOR_SET, 0x81),  # set_session
        ("IN", BMREQTYPE_VENDOR_GET, 0x82),   # get_keyword (live keyword)
        ("OUT", BMREQTYPE_VENDOR_SET, 0x85),  # set_command SELECTOR
        ("OUT", BMREQTYPE_VENDOR_SET, 0x85),  # set_command CLEAR
        ("IN", BMREQTYPE_VENDOR_GET, 0x86),   # get_command verify (empty by design)
    ]

    # The two set_command OUT frames are WICReset's captured ground truth, byte-exact.
    set_cmd_data = [d for k, _bm, br, _wv, d in ctrl.calls if k == "OUT" and br == 0x85]
    assert set_cmd_data[0] == GT_SELECTOR
    assert set_cmd_data[1] == GT_CLEAR

    # The clear is reported done off the two writes; the empty 0x86 readback did NOT
    # gate it, and the mandatory clean-power-button commit step is surfaced.
    assert "CLEARED" in plan.outcome.response_summary
    assert "POWER-BUTTON" in plan.outcome.response_summary
    assert "OVERRIDE" in plan.outcome.response_summary  # accept_derived on unvalidated SSOT


def test_empty_get_command_readback_does_not_fail_the_clear() -> None:
    """0x86 RECV is empty by design — the op must not gate on it (no finalize cmd)."""
    ctrl = RecordingCtrl(keyword=bytes([0x11, 0x22, 0x33]))  # any valid 3-byte read
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
    # the trailing get_command step recorded an empty reply, not an error
    gv = plan.steps[-1]
    assert gv.kind == "get_command"
    assert gv.reply == b""
