"""Tests for the pre-flight EEPROM dump gate (T5)."""

from __future__ import annotations

import hashlib

import pytest

from canon_megatank.eeprom import (
    EepromReadCommandNotDerivedError,
    dump_eeprom,
    verify_dump,
)
from canon_megatank.types import EepromDumpFailedError


class FakeReadable:
    """Serves a fixed EEPROM payload as a RECV reply (header + body)."""

    def __init__(self, body: bytes) -> None:
        # decode_frame strips the 3-byte header, so prepend one.
        self._reply = bytes([0x86, 0x00, 0x00]) + body

    def read_response(
        self, request_header: bytes, *, timeout_ms: int = 5000, length: int = 64
    ) -> bytes:
        return self._reply


def test_dump_refuses_without_derived_command() -> None:
    """No (cmd, arg) supplied and PENDING defaults unset → refuse, don't guess."""
    dev = FakeReadable(b"\x01\x02\x03\x04")
    with pytest.raises(EepromReadCommandNotDerivedError):
        dump_eeprom(dev)


def test_dump_returns_payload_and_sha() -> None:
    body = bytes(range(64))
    dev = FakeReadable(body)
    dump = dump_eeprom(dev, cmd=0x80, arg=0x0000)
    assert dump.data == body
    assert dump.size == 64
    assert dump.sha256 == hashlib.sha256(body).hexdigest()


def test_dump_rejects_empty_payload() -> None:
    dev = FakeReadable(b"")
    with pytest.raises(EepromDumpFailedError):
        dump_eeprom(dev, cmd=0x80, arg=0x0000)


def test_dump_enforces_expected_size() -> None:
    dev = FakeReadable(bytes(10))
    with pytest.raises(EepromDumpFailedError):
        dump_eeprom(dev, cmd=0x80, arg=0x0000, expected_size=4096)


def test_dump_writes_file_when_out_dir_given(tmp_path) -> None:  # type: ignore[no-untyped-def]
    body = b"\xde\xad\xbe\xef"
    dev = FakeReadable(body)
    dump = dump_eeprom(dev, cmd=0x80, arg=0x0000, out_dir=tmp_path, serial="UNIT123")
    assert dump.path is not None
    assert dump.path.parent == tmp_path
    assert dump.path.read_bytes() == body


def test_verify_dump_roundtrip_and_mismatch() -> None:
    body = b"\x00\x11\x22\x33"
    dev = FakeReadable(body)
    dump = dump_eeprom(dev, cmd=0x80, arg=0x0000)
    verify_dump(dump, dump.sha256)  # ok
    with pytest.raises(EepromDumpFailedError):
        verify_dump(dump, "0" * 64)
