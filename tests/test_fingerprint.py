"""Unit tests for fingerprint loading + verification.

These exercise the real maintenance.yaml SSOT (no fixtures yet). When the
file's contents drift, these tests catch it. That's intentional — the
SSOT IS the spec.
"""

from __future__ import annotations

import pytest

from canon_megatank.fingerprint import (
    load_maintenance,
    locked_test_unit,
    locked_write_budget,
    verify_fingerprint_matches,
)
from canon_megatank.types import (
    FingerprintMismatchError,
    PrinterFingerprint,
    UnknownPrinterError,
)


def test_load_maintenance_returns_dict() -> None:
    doc = load_maintenance()
    assert isinstance(doc, dict)
    assert doc["model_family"] == "canon-g6020"
    assert doc["usb_id"] == "04a9:1865"


def test_locked_test_unit_is_the_broken_g6020() -> None:
    tu = locked_test_unit()
    # The currently-broken 5B00 G6020 on mbp-13.
    assert tu.uuid == "00000000-0000-1000-8000-00186501807c"
    assert tu.attached_to_host == "mbp-13"
    assert "5B00" in tu.initial_state


def test_write_budget_is_50_unconsumed() -> None:
    wb = locked_write_budget()
    assert wb.cap == 50
    assert wb.consumed == 0
    assert wb.remaining == 50
    assert not wb.exhausted


def test_fingerprint_matches_locked_baseline() -> None:
    """Synthesize a runtime fingerprint that matches the locked values
    and confirm no exception."""
    doc = load_maintenance()
    fp = doc["protocol_fingerprint"]
    tu = doc["test_unit"]
    runtime = PrinterFingerprint(
        uuid=tu["uuid"],
        firmware_version=fp["printer_firmware_version"],
        device_id_raw=fp["printer_device_id"],
        cmd_set=tuple(fp["cmd_set"]),
    )
    verify_fingerprint_matches(runtime)  # must not raise


def test_fingerprint_rejects_wrong_uuid() -> None:
    runtime = PrinterFingerprint(
        uuid="00000000-0000-1000-8000-DEADBEEFCAFE",
        firmware_version="1.070",
        device_id_raw="",
        cmd_set=("BJRaster3", "NCCe", "IVEC", "URF"),
    )
    with pytest.raises(UnknownPrinterError):
        verify_fingerprint_matches(runtime)


def test_fingerprint_rejects_drifted_firmware() -> None:
    doc = load_maintenance()
    tu = doc["test_unit"]
    runtime = PrinterFingerprint(
        uuid=tu["uuid"],
        firmware_version="1.072",  # drift!
        device_id_raw="",
        cmd_set=("BJRaster3", "NCCe", "IVEC", "URF"),
    )
    with pytest.raises(FingerprintMismatchError):
        verify_fingerprint_matches(runtime)


def test_fingerprint_rejects_changed_cmd_set() -> None:
    doc = load_maintenance()
    tu = doc["test_unit"]
    fp = doc["protocol_fingerprint"]
    runtime = PrinterFingerprint(
        uuid=tu["uuid"],
        firmware_version=fp["printer_firmware_version"],
        device_id_raw="",
        cmd_set=("BJRaster3", "URF"),  # missing NCCe + IVEC
    )
    with pytest.raises(FingerprintMismatchError):
        verify_fingerprint_matches(runtime)


def test_ipp_attributes_parser_extracts_cmd_set() -> None:
    """Verify PrinterFingerprint.from_ipp_attributes correctly parses
    the CMD: token from the device_id field."""
    attrs = {
        "printer-uuid": "00000000-0000-1000-8000-00186501807c",
        "printer-firmware-version": "1.070",
        "printer-device-id": (
            "MFG:Canon;CMD:BJRaster3,NCCe,IVEC,URF;SOJ:CHMP,CHMPu;"
            "MDL:G6000 series;VER:1.070;CID:CA_IVEC1TYPE4_IJP;"
        ),
    }
    fp = PrinterFingerprint.from_ipp_attributes(attrs)
    assert fp.cmd_set == ("BJRaster3", "NCCe", "IVEC", "URF")
    assert fp.firmware_version == "1.070"
    assert fp.uuid == "00000000-0000-1000-8000-00186501807c"
