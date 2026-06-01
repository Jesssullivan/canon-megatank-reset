"""Unit tests for the read-only bulk transfer in usb.py.

These use a fake pyusb ``Device`` (a tiny in-memory object implementing the
``read``/``write`` surface ``ClaimedDevice`` calls) so the full
write-header-then-read-reply path is exercised WITHOUT hardware. No real USB,
no Canon printer required.
"""

from __future__ import annotations

import pytest
import usb.core
import usb.util

from canon_megatank.types import UsbAccessError
from canon_megatank.usb import CANON_VENDOR_ID, ClaimedDevice


class _FakeEndpoint:
    def __init__(self, address: int, attributes: int) -> None:
        self.bEndpointAddress = address
        self.bmAttributes = attributes


class _FakeInterface:
    def __init__(self, number: int, endpoints: list[_FakeEndpoint]) -> None:
        self.bInterfaceNumber = number
        self._endpoints = endpoints

    def __iter__(self) -> object:
        return iter(self._endpoints)


class _FakeConfiguration:
    def __init__(self, interfaces: list[_FakeInterface]) -> None:
        self._interfaces = interfaces

    def __iter__(self) -> object:
        return iter(self._interfaces)


# Bulk maintenance interface 4: OUT 0x03, IN 0x86 (matches maintenance.yaml).
_BULK = usb.util.ENDPOINT_TYPE_BULK


def _maintenance_config() -> _FakeConfiguration:
    out_ep = _FakeEndpoint(0x03, _BULK)
    in_ep = _FakeEndpoint(0x86, _BULK)
    return _FakeConfiguration([_FakeInterface(4, [out_ep, in_ep])])


def _g6020_like_config() -> _FakeConfiguration:
    """Mirrors the REAL G6020: interface 0 has a bulk in+out pair (0x07/0x88)
    BEFORE the maintenance interface 4 (0x03/0x86). First-match auto-pick would
    wrongly claim interface 0 — pinning must select interface 4."""
    iface0 = _FakeInterface(0, [_FakeEndpoint(0x07, _BULK), _FakeEndpoint(0x88, _BULK)])
    iface4 = _FakeInterface(4, [_FakeEndpoint(0x03, _BULK), _FakeEndpoint(0x86, _BULK)])
    return _FakeConfiguration([iface0, iface4])


class FakeDevice:
    """In-memory stand-in for ``usb.core.Device`` — only the bits ClaimedDevice
    touches. Records writes and serves a queued reply on read."""

    def __init__(
        self,
        reply: bytes = b"",
        *,
        vendor: int = CANON_VENDOR_ID,
        config: _FakeConfiguration | None = None,
    ) -> None:
        self.idVendor = vendor
        self.idProduct = 0x1865
        self.iSerialNumber = 0
        self._config = config if config is not None else _maintenance_config()
        self._reply = reply
        self.writes: list[tuple[int, bytes, int]] = []
        self.reads: list[tuple[int, int, int]] = []
        self.ctrls: list[tuple[int, int, int, int, bytes | int, int]] = []

    # Configuration / driver lifecycle ------------------------------------
    def is_kernel_driver_active(self, _iface: int) -> bool:
        return False

    def set_configuration(self) -> None:
        return None

    def get_active_configuration(self) -> _FakeConfiguration:
        return self._config

    # Bulk transfer -------------------------------------------------------
    def write(self, endpoint: int, data: bytes, timeout: int) -> int:
        self.writes.append((endpoint, bytes(data), timeout))
        return len(data)

    def read(self, endpoint: int, length: int, timeout: int) -> bytes:
        self.reads.append((endpoint, length, timeout))
        return self._reply

    # Control transfer (EP0) ----------------------------------------------
    def ctrl_transfer(  # noqa: PLR0913 — pyusb's ctrl_transfer signature (5 setup fields)
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int,
        wIndex: int,
        data_or_wLength: bytes | int,
        timeout: int = 5000,
    ) -> bytes | int:
        self.ctrls.append(
            (bmRequestType, bRequest, wValue, wIndex, data_or_wLength, timeout)
        )
        if bmRequestType & 0x80:  # IN: return canned reply bytes
            return self._reply
        return len(data_or_wLength) if isinstance(data_or_wLength, (bytes, bytearray)) else 0


@pytest.fixture(autouse=True)
def _patch_usb_util(monkeypatch: pytest.MonkeyPatch) -> None:
    """ClaimedDevice calls usb.util.claim_interface / release_interface /
    dispose_resources — no-op them so the fake device needs no real USB."""
    monkeypatch.setattr(usb.util, "claim_interface", lambda *a, **k: None)
    monkeypatch.setattr(usb.util, "release_interface", lambda *a, **k: None)
    monkeypatch.setattr(usb.util, "dispose_resources", lambda *a, **k: None)


def test_claimed_device_refuses_non_canon_vendor() -> None:
    with pytest.raises(UsbAccessError):
        ClaimedDevice(FakeDevice(vendor=0x1234))  # type: ignore[arg-type]


def test_enter_discovers_bulk_endpoints() -> None:
    dev = FakeDevice()
    with ClaimedDevice(dev) as cd:  # type: ignore[arg-type]
        assert cd.bulk_out_endpoint == 0x03
        assert cd.bulk_in_endpoint == 0x86


def test_read_response_writes_header_then_reads_reply() -> None:
    """read_response writes the request header to bulk-OUT and returns the
    reply read from bulk-IN."""
    reply = bytes([0x85, 0x00, 0x07, 0xDE, 0xAD])
    dev = FakeDevice(reply=reply)
    header = bytes([0x85, 0x00, 0x07])
    with ClaimedDevice(dev) as cd:  # type: ignore[arg-type]
        got = cd.read_response(header, timeout_ms=1234, length=32)

    assert got == reply
    # exactly one write of the header to the OUT endpoint
    assert dev.writes == [(0x03, header, 1234)]
    # exactly one read from the IN endpoint with the requested length
    assert dev.reads == [(0x86, 32, 1234)]


def test_read_response_propagates_usb_error_as_usb_access_error() -> None:
    class _Boom(FakeDevice):
        def write(self, endpoint: int, data: bytes, timeout: int) -> int:
            raise usb.core.USBError("pipe error")

    dev = _Boom()
    with ClaimedDevice(dev) as cd, pytest.raises(UsbAccessError):  # type: ignore[arg-type]
        cd.read_response(b"\x85\x00\x00")


def test_endpoint_properties_raise_before_enter() -> None:
    cd = ClaimedDevice(FakeDevice())  # type: ignore[arg-type]
    with pytest.raises(UsbAccessError):
        _ = cd.bulk_out_endpoint
    with pytest.raises(UsbAccessError):
        _ = cd.bulk_in_endpoint


# ─── Interface pinning (the real-G6020 bug guard) ─────────────────────────────


def test_pinning_selects_maintenance_interface_not_first_bulk() -> None:
    """On a G6020-like device (iface 0 has bulk endpoints before iface 4),
    pinning interface=4 binds iface 4 / 0x03 / 0x86 — NOT the first bulk pair."""
    dev = FakeDevice(config=_g6020_like_config())
    with ClaimedDevice(  # type: ignore[arg-type]
        dev, interface=4, bulk_out_ep=0x03, bulk_in_ep=0x86
    ) as cd:
        assert cd.bulk_out_endpoint == 0x03
        assert cd.bulk_in_endpoint == 0x86


def test_auto_pick_would_grab_the_wrong_interface() -> None:
    """Documents WHY pinning matters: with no pin, auto-pick claims iface 0's
    bulk pair (0x07/0x88) — the wrong lane. This is the bug pinning prevents."""
    dev = FakeDevice(config=_g6020_like_config())
    with ClaimedDevice(dev, interface=None) as cd:  # type: ignore[arg-type]
        assert cd.bulk_out_endpoint == 0x07  # iface 0 — NOT the maintenance lane


def test_pinning_refuses_on_endpoint_mismatch() -> None:
    """If the pinned interface's endpoints don't match the expected maintenance
    endpoints, refuse to bind rather than talk to the wrong endpoint."""
    dev = FakeDevice(config=_g6020_like_config())
    with pytest.raises(UsbAccessError):
        # interface 0 exists but its bulk-OUT is 0x07, not the expected 0x03
        ClaimedDevice(dev, interface=0, bulk_out_ep=0x03, bulk_in_ep=0x86).__enter__()  # type: ignore[arg-type]


def test_pinning_refuses_when_interface_absent() -> None:
    dev = FakeDevice(config=_maintenance_config())  # only iface 4
    with pytest.raises(UsbAccessError):
        ClaimedDevice(dev, interface=9, bulk_out_ep=0x03, bulk_in_ep=0x86).__enter__()  # type: ignore[arg-type]


# ─── EP0 control transfer (the WICReset service-mode transport) ───────────────


def test_control_transfer_out_passes_data_and_returns_empty() -> None:
    """A vendor control-OUT (the captured reset) forwards the exact setup +
    data to ctrl_transfer and returns b'' (OUT has no read payload)."""
    dev = FakeDevice()
    data = bytes([0x00, 0x03, 0x01, 0x03, 0x07])
    with ClaimedDevice(dev) as cd:  # type: ignore[arg-type]
        got = cd.control_transfer(0x40, 0x85, 0x0000, 0x0000, data, timeout_ms=1234)
    assert got == b""
    assert dev.ctrls == [(0x40, 0x85, 0x0000, 0x0000, data, 1234)]


def test_control_transfer_in_returns_reply_bytes() -> None:
    """A class control-IN (1284-id / status read) passes the read length and
    returns the device reply bytes."""
    reply = bytes([0x10, 0x20, 0x30])
    dev = FakeDevice(reply=reply)
    with ClaimedDevice(dev) as cd:  # type: ignore[arg-type]
        got = cd.control_transfer(0xA1, 0x00, 0x0000, 0x0000, 1024)
    assert got == reply
    assert dev.ctrls == [(0xA1, 0x00, 0x0000, 0x0000, 1024, 5000)]


def test_control_transfer_propagates_usb_error() -> None:
    class _Boom(FakeDevice):
        def ctrl_transfer(self, *a: object, **k: object) -> bytes | int:
            raise usb.core.USBError("pipe stall")

    dev = _Boom()
    with ClaimedDevice(dev) as cd, pytest.raises(UsbAccessError):  # type: ignore[arg-type]
        cd.control_transfer(0x40, 0x85, 0x0000, 0x0000, b"\x00")


# ─── Send-primed RECV (the WICReset get_keyword / set_session transport) ──────


def test_send_and_receive_writes_full_frame_then_reads_reply() -> None:
    """send_and_receive writes the FULL (enciphered) frame to bulk-OUT and
    returns the reply from bulk-IN — the get_keyword shape."""
    reply = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    dev = FakeDevice(reply=reply)
    # an enciphered set_session/get_keyword frame is longer than a 3-byte header
    frame = bytes([0x00, 0x12, 0x01, 0x03, 0xE9, 0x3F, 0x0D, 0xA1])
    with ClaimedDevice(dev) as cd:  # type: ignore[arg-type]
        got = cd.send_and_receive(frame, timeout_ms=4321, length=16)

    assert got == reply
    # exactly one write of the full frame to OUT, one read from IN
    assert dev.writes == [(0x03, frame, 4321)]
    assert dev.reads == [(0x86, 16, 4321)]


def test_send_and_receive_propagates_usb_error() -> None:
    class _Boom(FakeDevice):
        def write(self, endpoint: int, data: bytes, timeout: int) -> int:
            raise usb.core.USBError("pipe error")

    dev = _Boom()
    with ClaimedDevice(dev) as cd, pytest.raises(UsbAccessError):  # type: ignore[arg-type]
        cd.send_and_receive(b"\x81\x00\x00\x03")
