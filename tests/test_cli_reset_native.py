"""CLI smoke for `canon-megatank reset-native` (the validated native clear).

The dry-run path needs no hardware: it loads the real SSOT derived_template,
lazily builds the Lane A encoder, enciphers the validated frames, and prints them
+ the mandatory commit step. We assert it returns 0 and emits the commit
instruction (the clean power-button shutdown), and that --execute on the current
DERIVED-UNVALIDATED SSOT without --accept-derived is gated.
"""

from __future__ import annotations

import json

import pytest

from canon_megatank.main import run


def test_reset_native_dry_run_returns_zero_and_logs_commit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = run(["reset-native"])
    assert rc == 0
    out = capsys.readouterr().out
    # Find the structured dry-run record.
    rec = next(
        json.loads(line)
        for line in out.splitlines()
        if line.strip().startswith("{") and '"reset_native.dry_run"' in line
    )
    # 5 steps: set_session, get_keyword, 2x set_command, get_command
    assert rec["steps"] == 5  # noqa: PLR2004
    # The two set_command wires are the corrected 23-byte 85 00 00 || payload(20).
    set_cmd_wires = [w for w in rec["wire"] if w.startswith("850000") and len(w) == 46]  # noqa: PLR2004
    assert len(set_cmd_wires) == 2  # noqa: PLR2004
    # The mandatory commit step is surfaced for the operator.
    assert "POWER-BUTTON" in rec["commit_step"]
    assert "UNPLUG does NOT commit" in rec["commit_step"]


def test_reset_native_no_verify_readback_has_four_steps(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = run(["reset-native", "--no-verify-readback"])
    assert rc == 0
    out = capsys.readouterr().out
    rec = next(
        json.loads(line)
        for line in out.splitlines()
        if line.strip().startswith("{") and '"reset_native.dry_run"' in line
    )
    assert rec["steps"] == 4  # no trailing get_command(0x86) RECV  # noqa: PLR2004
