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
from canon_megatank.usb import CANON_VENDOR_ID, ClaimedDevice
from canon_megatank.types import UsbAccessError


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


class FakeDevice:
    """In-memory stand-in for ``usb.core.Device`` — only the bits ClaimedDevice
    touches. Records writes and serves a queued reply on read."""

    def __init__(self, reply: bytes = b"", *, vendor: int = CANON_VENDOR_ID) -> None:
        self.idVendor = vendor
        self.idProduct = 0x1865
        self.iSerialNumber = 0
        self._config = _maintenance_config()
        self._reply = reply
        self.writes: list[tuple[int, bytes, int]] = []
        self.reads: list[tuple[int, int, int]] = []

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
    with ClaimedDevice(dev) as cd:  # type: ignore[arg-type]
        with pytest.raises(UsbAccessError):
            cd.read_response(b"\x85\x00\x00")


def test_endpoint_properties_raise_before_enter() -> None:
    cd = ClaimedDevice(FakeDevice())  # type: ignore[arg-type]
    with pytest.raises(UsbAccessError):
        _ = cd.bulk_out_endpoint
    with pytest.raises(UsbAccessError):
        _ = cd.bulk_in_endpoint
