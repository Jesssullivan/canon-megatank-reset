"""Tests for the service-mode CONTROL-TRANSFER reset path (Lane C / WICReset).

``ops.replay_control_sequence`` drives a captured EP0 control-transfer reset over
``ClaimedDevice.control_transfer``. The point — exactly as for the bulk
``reset_absorber`` — is the SAFETY GATES, so these assert: (a) dry-run never
drives the device and yields the resolved steps, (b) execute=True is blocked at
each gate in order, including the placeholder/empty-sequence guard, and (c) only
an all-gates-pass path issues the control transfers — and issues EXACTLY the
captured sequence. A fake device records every control transfer so we can prove
"nothing was driven".
"""

from __future__ import annotations

import pytest

from canon_megatank.ops import (
    CTRL_RESET_BMREQUESTTYPE,
    CTRL_RESET_BREQUEST,
    CTRL_RESET_DATA,
    ControlStep,
    parse_control_sequence,
    replay_control_sequence,
)
from canon_megatank.types import (
    CanonToolError,
    EepromDumpFailedError,
    PrinterFingerprint,
    ResetNotValidatedError,
    UnknownPrinterError,
    WriteBudgetExhaustedError,
)

FP = PrinterFingerprint(
    uuid="00000000-0000-1000-8000-00186501807c",
    firmware_version="1.070",
    device_id_raw="",
    cmd_set=(),
)

# The captured reset sequence: two class IN reads, the vendor OUT reset, a status read.
RESET_STEP = ControlStep(
    bm_request_type=CTRL_RESET_BMREQUESTTYPE,
    b_request=CTRL_RESET_BREQUEST,
    w_value=0x0000,
    w_index=0x0000,
    data=CTRL_RESET_DATA,
)
ID_READ = ControlStep(0xA1, 0x00, 0x0000, 0x0000, read_length=1024)
STATUS_READ = ControlStep(0xA1, 0x01, 0x0000, 0x0000, read_length=1)
SEQUENCE = [ID_READ, STATUS_READ, RESET_STEP, STATUS_READ]


class FakeControlDevice:
    """Records every control transfer. Serves a canned reply for IN transfers."""

    def __init__(self, in_reply: bytes = b"\x10") -> None:
        self.calls: list[tuple[int, int, int, int, bytes | int]] = []
        self._in_reply = in_reply

    def control_transfer(  # noqa: PLR0913 — mirrors the USB setup packet (5 wire fields)
        self,
        bm_request_type: int,
        b_request: int,
        w_value: int,
        w_index: int,
        data_or_length: bytes | int,
        *,
        timeout_ms: int = 5000,
    ) -> bytes:
        self.calls.append(
            (bm_request_type, b_request, w_value, w_index, data_or_length)
        )
        if bm_request_type & 0x80:  # IN
            return self._in_reply
        return b""


def _ok_verify(fp: PrinterFingerprint, printer_id: str) -> None:
    return None


def _validated_doc(_pid: str) -> dict:
    return {"supported": {"absorber_reset": {"status": "verified-captured"}}}


def _unvalidated_doc(_pid: str) -> dict:
    return {"supported": {"absorber_reset": {"status": "derived-unvalidated"}}}


# ─── The captured reset anchor ────────────────────────────────────────────────


def test_reset_step_is_the_captured_vendor_out() -> None:
    """The known reset control transfer: vendor OUT 0x40/0x85, [00 03 01 03 07]."""
    assert RESET_STEP.is_known_reset()
    assert RESET_STEP.is_out
    assert bytes([0x00, 0x03, 0x01, 0x03, 0x07]) == CTRL_RESET_DATA


# ─── SSOT parsing ─────────────────────────────────────────────────────────────


def test_parse_control_sequence_handles_hex_and_int() -> None:
    raw = [
        {"bmRequestType": 0xA1, "bRequest": 0, "wValue": 0, "wIndex": 0, "read_length": 1024},
        {"bmRequestType": "0x40", "bRequest": "0x85", "wValue": "0x0000",
         "wIndex": "0x0000", "data": "0003010307"},
    ]
    steps = parse_control_sequence(raw)
    assert steps[0].read_length == 1024
    assert steps[1].is_known_reset()


def test_parse_control_sequence_rejects_malformed_entry() -> None:
    with pytest.raises(CanonToolError):
        parse_control_sequence([["not", "a", "mapping"]])


# ─── Dry-run never drives the device ──────────────────────────────────────────


def test_dry_run_default_does_not_drive_device() -> None:
    dev = FakeControlDevice()
    plan = replay_control_sequence(
        dev, runtime_fingerprint=FP, eeprom_dump_done=True, steps=SEQUENCE
    )
    assert plan.executed is False
    assert dev.calls == []  # NOTHING was driven
    assert "DRY-RUN" in plan.outcome.response_summary
    assert plan.steps == tuple(SEQUENCE)


def test_dry_run_ignores_gates() -> None:
    """Dry-run is pure: no verify/doc/dump consulted."""
    dev = FakeControlDevice()
    plan = replay_control_sequence(
        dev, runtime_fingerprint=FP, eeprom_dump_done=False, steps=SEQUENCE
    )
    assert plan.executed is False
    assert dev.calls == []


# ─── execute=True blocked at each gate, IN ORDER ──────────────────────────────


def test_execute_blocked_by_uuid_gate_first() -> None:
    dev = FakeControlDevice()

    def _bad_verify(fp: PrinterFingerprint, pid: str) -> None:
        raise UnknownPrinterError("wrong unit")

    with pytest.raises(UnknownPrinterError):
        replay_control_sequence(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            steps=SEQUENCE,
            execute=True,
            verify=_bad_verify,
            load_doc=_validated_doc,
        )
    assert dev.calls == []


def test_execute_blocked_by_validation_status() -> None:
    """derived-unvalidated status HARD STOPS — the sequence is a placeholder."""
    dev = FakeControlDevice()
    with pytest.raises(ResetNotValidatedError):
        replay_control_sequence(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            steps=SEQUENCE,
            execute=True,
            verify=_ok_verify,
            load_doc=_unvalidated_doc,
        )
    assert dev.calls == []


def test_execute_blocked_on_empty_sequence() -> None:
    """Even validated, an empty captured sequence refuses (no invented reset)."""
    dev = FakeControlDevice()
    with pytest.raises(ResetNotValidatedError):
        replay_control_sequence(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            steps=[],
            execute=True,
            verify=_ok_verify,
            load_doc=_validated_doc,
        )
    assert dev.calls == []


def test_execute_blocked_without_eeprom_dump() -> None:
    dev = FakeControlDevice()
    with pytest.raises(EepromDumpFailedError):
        replay_control_sequence(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=False,
            steps=SEQUENCE,
            execute=True,
            verify=_ok_verify,
            load_doc=_validated_doc,
        )
    assert dev.calls == []


def test_execute_charges_budget_and_can_be_blocked() -> None:
    dev = FakeControlDevice()

    def _charge_exhausted() -> None:
        raise WriteBudgetExhaustedError("cap reached")

    with pytest.raises(WriteBudgetExhaustedError):
        replay_control_sequence(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            steps=SEQUENCE,
            execute=True,
            verify=_ok_verify,
            load_doc=_validated_doc,
            charge=_charge_exhausted,
        )
    assert dev.calls == []


# ─── Happy path: all gates pass → drives exactly the captured sequence ─────────


def test_execute_all_gates_pass_drives_captured_sequence() -> None:
    dev = FakeControlDevice()
    charged: list[bool] = []
    plan = replay_control_sequence(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        steps=SEQUENCE,
        execute=True,
        verify=_ok_verify,
        load_doc=_validated_doc,
        charge=lambda: charged.append(True),
    )
    assert plan.executed is True
    assert charged == [True]
    # exactly the captured sequence, in order; the reset OUT carries the bytes,
    # the IN reads carry their read lengths.
    assert dev.calls == [
        (0xA1, 0x00, 0x0000, 0x0000, 1024),
        (0xA1, 0x01, 0x0000, 0x0000, 1),
        (0x40, 0x85, 0x0000, 0x0000, CTRL_RESET_DATA),
        (0xA1, 0x01, 0x0000, 0x0000, 1),
    ]
    # IN reads are recorded in responses; OUT steps record b"".
    assert plan.responses[2] == b""
    assert plan.responses[0] == b"\x10"


def test_steps_default_to_ssot_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """With steps=None, the op loads control_sequence from the SSOT loader."""
    dev = FakeControlDevice()

    def _doc_with_seq(_pid: str) -> dict:
        return {
            "supported": {
                "absorber_reset": {
                    "status": "derived-unvalidated",
                    "control_sequence": [
                        {"bmRequestType": 0x40, "bRequest": 0x85, "wValue": 0,
                         "wIndex": 0, "data": "0003010307"},
                    ],
                }
            }
        }

    # dry-run resolves steps from the SSOT but consults no gate
    plan = replay_control_sequence(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        load_doc=_doc_with_seq,
    )
    assert plan.executed is False
    assert len(plan.steps) == 1
    assert plan.steps[0].is_known_reset()
    assert dev.calls == []
