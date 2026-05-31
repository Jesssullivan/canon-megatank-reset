"""Tests for the gated absorber-reset op (T5 write path).

The whole point is the SAFETY GATES, so these assert: (a) dry-run never writes
and yields the exact derived frame, (b) execute=True is blocked at each gate in
order, (c) only an all-gates-pass path writes — and writes exactly the derived
bytes. A fake device records any write so we can prove "no write happened".
"""

from __future__ import annotations

import pytest

from canon_megatank.ops import (
    RESET_HEADER_ARG,
    RESET_HEADER_CMD,
    build_absorber_reset_spec,
    reset_absorber,
)
from canon_megatank.protocol import ABSORBER_MAIN_IDX, derive_reset_frame
from canon_megatank.types import (
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

# The label-confirmed main-absorber reset frame: header 0x85 0x00 0x00 + payload.
MAIN_FRAME = derive_reset_frame(build_absorber_reset_spec())


class FakeWritable:
    """Records SEND frames; serves nothing on read. If send_command is ever
    called when a gate should have blocked, the recorded list proves it."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def read_response(
        self, request_header: bytes, *, timeout_ms: int = 5000, length: int = 64
    ) -> bytes:
        return b"\x85\x00\x00"

    def send_command(self, frame: bytes, *, timeout_ms: int = 5000) -> int:
        self.sent.append(bytes(frame))
        return len(frame)


def _ok_verify(fp: PrinterFingerprint, printer_id: str) -> None:
    return None


def _validated_doc(_pid: str) -> dict:
    return {"supported": {"absorber_reset": {"status": "verified-captured"}}}


def _unvalidated_doc(_pid: str) -> dict:
    return {"supported": {"absorber_reset": {"status": "derived-unvalidated"}}}


# ─── The derived frame ────────────────────────────────────────────────────────


def test_main_reset_frame_is_the_recovered_literal() -> None:
    """Header 0x85/0x0000 + payload [00,03,01,03,07] (idx 0x07 = Main)."""
    assert bytes([RESET_HEADER_CMD, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0x07]) == MAIN_FRAME
    assert RESET_HEADER_ARG == 0x0000
    assert build_absorber_reset_spec().idx == ABSORBER_MAIN_IDX


# ─── Dry-run (the default) never writes ───────────────────────────────────────


def test_dry_run_default_does_not_write() -> None:
    dev = FakeWritable()
    plan = reset_absorber(dev, runtime_fingerprint=FP, eeprom_dump_done=True)
    assert plan.executed is False
    assert plan.frame == MAIN_FRAME
    assert dev.sent == []  # NOTHING was written
    assert "DRY-RUN" in plan.outcome.response_summary


def test_dry_run_works_even_with_all_gates_unmet() -> None:
    """Dry-run is pure: it doesn't even consult the gates (no verify/doc/dump)."""
    dev = FakeWritable()
    plan = reset_absorber(dev, runtime_fingerprint=FP, eeprom_dump_done=False)
    assert plan.executed is False
    assert dev.sent == []


# ─── execute=True blocked at each gate, IN ORDER ──────────────────────────────


def test_execute_blocked_by_validation_status() -> None:
    """Even with UUID ok + dump done, derived-unvalidated status HARD STOPS."""
    dev = FakeWritable()
    with pytest.raises(ResetNotValidatedError):
        reset_absorber(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            execute=True,
            verify=_ok_verify,
            load_doc=_unvalidated_doc,
        )
    assert dev.sent == []  # never wrote


def test_execute_blocked_by_uuid_gate_first() -> None:
    """A failing fingerprint verify stops before anything else."""
    dev = FakeWritable()

    def _bad_verify(fp: PrinterFingerprint, pid: str) -> None:
        raise UnknownPrinterError("wrong unit")

    with pytest.raises(UnknownPrinterError):
        reset_absorber(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            execute=True,
            verify=_bad_verify,
            load_doc=_validated_doc,
        )
    assert dev.sent == []


def test_execute_blocked_without_eeprom_dump() -> None:
    """Validated status but no pre-flight dump → EepromDumpFailedError."""
    dev = FakeWritable()
    with pytest.raises(EepromDumpFailedError):
        reset_absorber(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=False,
            execute=True,
            verify=_ok_verify,
            load_doc=_validated_doc,
        )
    assert dev.sent == []


def test_execute_charges_budget_and_can_be_blocked() -> None:
    """The budget charge runs before the write; if it raises, nothing is sent."""
    dev = FakeWritable()

    def _charge_exhausted() -> None:
        raise WriteBudgetExhaustedError("cap reached")

    with pytest.raises(WriteBudgetExhaustedError):
        reset_absorber(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            execute=True,
            verify=_ok_verify,
            load_doc=_validated_doc,
            charge=_charge_exhausted,
        )
    assert dev.sent == []


# ─── The happy path: all gates pass → writes exactly the derived frame ────────


def test_execute_all_gates_pass_writes_derived_frame() -> None:
    dev = FakeWritable()
    charged: list[bool] = []
    plan = reset_absorber(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        execute=True,
        verify=_ok_verify,
        load_doc=_validated_doc,
        charge=lambda: charged.append(True),
    )
    assert plan.executed is True
    assert dev.sent == [MAIN_FRAME]  # exactly the derived bytes, once
    assert charged == [True]  # budget was charged
    assert "SENT" in plan.outcome.response_summary


def test_checkbox_flips_flags_to_0x81() -> None:
    """The dialog checkbox sets flags 0x01 → 0x81 (main + platen)."""
    spec = build_absorber_reset_spec(checkbox=True)
    assert spec.flags == 0x81
    frame = derive_reset_frame(spec)
    # payload byte 2 (after the 3-byte header) is flags
    assert frame[5] == 0x81
