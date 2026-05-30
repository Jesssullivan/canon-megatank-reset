"""Unit tests for the read-only counter op (ops.read_counter).

A small fake device implements the ``ReadableDevice`` protocol so the full
encode → transfer → decode round-trip is tested WITHOUT hardware. The real read
``(cmd, arg)`` for the absorber counter is PENDING Lane A; these tests pass it
explicitly (or assert the guard fires when it's unset) and NEVER assert a
guessed counter command.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from canon_megatank.fingerprint import load_maintenance, locked_test_unit
from canon_megatank.ops import (
    ABSORBER_READ_ARG,
    ABSORBER_READ_CMD,
    ReadCommandNotDerivedError,
    read_counter,
)
from canon_megatank.protocol import decode_frame, encode_recv_header, encode_send
from canon_megatank.types import (
    PrinterFingerprint,
    UnknownPrinterError,
)

u8 = st.integers(min_value=0, max_value=0xFF)
u16 = st.integers(min_value=0, max_value=0xFFFF)


class FakeReadableDevice:
    """Implements ReadableDevice. Records the request header it was given and
    serves a canned reply frame."""

    def __init__(self, reply: bytes) -> None:
        self._reply = reply
        self.last_request: bytes | None = None
        self.calls = 0

    def read_response(
        self, request_header: bytes, *, timeout_ms: int = 5000, length: int = 64
    ) -> bytes:
        self.calls += 1
        self.last_request = bytes(request_header)
        return self._reply


def _locked_runtime_fingerprint() -> PrinterFingerprint:
    """A runtime fingerprint that matches the locked SSOT (passes the gate)."""
    doc = load_maintenance()
    fp = doc["protocol_fingerprint"]
    tu = doc["test_unit"]
    return PrinterFingerprint(
        uuid=tu["uuid"],
        firmware_version=fp["printer_firmware_version"],
        device_id_raw=fp.get("printer_device_id", ""),
        cmd_set=tuple(fp["cmd_set"]),
    )


# ─── PENDING guard: never guess the counter command ───────────────────────────


def test_pending_defaults_are_unset() -> None:
    """The module ships the absorber read (cmd, arg) as PENDING (None) — no
    guessed values committed."""
    assert ABSORBER_READ_CMD is None
    assert ABSORBER_READ_ARG is None


def test_read_counter_guard_fires_when_command_unset() -> None:
    """With no cmd/arg and PENDING defaults still None, the op refuses to run
    and never touches the device."""
    dev = FakeReadableDevice(reply=encode_send(0x85, 0x0000, b""))
    fp = _locked_runtime_fingerprint()
    with pytest.raises(ReadCommandNotDerivedError):
        read_counter(dev, runtime_fingerprint=fp)
    assert dev.calls == 0  # the guard fires BEFORE any transfer


# ─── encode → transfer → decode round-trip ────────────────────────────────────


@given(cmd=u8, arg=u16, payload=st.binary(min_size=0, max_size=60))
def test_read_counter_request_header_is_exact(cmd: int, arg: int, payload: bytes) -> None:
    """The bytes written to the device are EXACTLY encode_recv_header(cmd, arg),
    and the reply decodes correctly."""
    reply = encode_send(cmd, arg, payload)
    dev = FakeReadableDevice(reply=reply)
    fp = _locked_runtime_fingerprint()

    reading = read_counter(dev, runtime_fingerprint=fp, cmd=cmd, arg=arg)

    assert dev.last_request == encode_recv_header(cmd, arg)
    assert (reading.cmd, reading.arg, reading.payload) == decode_frame(reply)
    assert reading.payload == payload


def test_read_counter_populates_outcome() -> None:
    """OperationOutcome carries bytes_sent/received, elapsed_ms, summary."""
    payload = bytes([0x00, 0x42, 0x00])
    reply = encode_send(0x86, 0x0007, payload)
    dev = FakeReadableDevice(reply=reply)
    fp = _locked_runtime_fingerprint()

    reading = read_counter(dev, runtime_fingerprint=fp, cmd=0x86, arg=0x0007)
    oc = reading.outcome

    assert oc.op_name == "read_counter"
    assert oc.success is True
    assert oc.bytes_sent == 3  # the RECV header
    assert oc.bytes_received == len(reply)
    assert oc.elapsed_ms >= 0
    assert oc.response_summary.startswith(f"{len(payload)}B:")
    assert oc.error is None


def test_read_counter_applies_decode_callable() -> None:
    """A supplied decode() interprets the payload into a counter value."""
    payload = bytes([0x00, 0x00, 0x2A])  # arbitrary; decode reads last byte
    reply = encode_send(0x86, 0x0001, payload)
    dev = FakeReadableDevice(reply=reply)
    fp = _locked_runtime_fingerprint()

    reading = read_counter(
        dev,
        runtime_fingerprint=fp,
        cmd=0x86,
        arg=0x0001,
        decode=lambda p: p[-1],
    )
    assert reading.value == 0x2A
    assert reading.outcome.success is True


def test_read_counter_decode_failure_is_captured_not_raised() -> None:
    """A failing decode() is surfaced in the outcome.error, not raised — the
    read itself still succeeded (raw payload is available)."""
    reply = encode_send(0x86, 0x0001, b"\x00")
    dev = FakeReadableDevice(reply=reply)
    fp = _locked_runtime_fingerprint()

    def _boom(_p: bytes) -> int:
        raise ValueError("bad shape")

    reading = read_counter(dev, runtime_fingerprint=fp, cmd=0x86, arg=0x0001, decode=_boom)
    assert reading.value is None
    assert reading.outcome.success is False
    assert reading.outcome.error is not None
    assert "bad shape" in reading.outcome.error


# ─── fingerprint / UUID gate ──────────────────────────────────────────────────


def test_read_counter_refuses_wrong_uuid_device() -> None:
    """A device whose UUID isn't the locked test_unit is refused before any
    transfer (UUID isolation applies to reads too)."""
    dev = FakeReadableDevice(reply=encode_send(0x86, 0x0001, b"\x00"))
    wrong = PrinterFingerprint(
        uuid="00000000-0000-1000-8000-DEADBEEFCAFE",
        firmware_version="1.070",
        device_id_raw="",
        cmd_set=("BJRaster3", "NCCe", "IVEC", "URF"),
    )
    with pytest.raises(UnknownPrinterError):
        read_counter(dev, runtime_fingerprint=wrong, cmd=0x86, arg=0x0001)
    assert dev.calls == 0  # gate fires before the read


def test_read_counter_gate_runs_before_command_guard() -> None:
    """Identity is verified first: a wrong UUID is rejected even when no
    cmd/arg is supplied (we don't leak the PENDING guard for a bad unit)."""
    dev = FakeReadableDevice(reply=encode_send(0x86, 0x0001, b"\x00"))
    wrong = PrinterFingerprint(
        uuid="00000000-0000-1000-8000-DEADBEEFCAFE",
        firmware_version="1.070",
        device_id_raw="",
        cmd_set=("BJRaster3", "NCCe", "IVEC", "URF"),
    )
    with pytest.raises(UnknownPrinterError):
        read_counter(dev, runtime_fingerprint=wrong)


def test_read_counter_accepts_locked_unit() -> None:
    """The locked test_unit passes the gate and the op completes."""
    assert locked_test_unit().uuid  # sanity: SSOT has a locked unit
    reply = encode_send(0x86, 0x0001, b"\x01\x02")
    dev = FakeReadableDevice(reply=reply)
    fp = _locked_runtime_fingerprint()
    reading = read_counter(dev, runtime_fingerprint=fp, cmd=0x86, arg=0x0001)
    assert reading.outcome.success is True
    assert dev.calls == 1
