"""Tests for the write-budget + in-flight lockfile gates (T5)."""

from __future__ import annotations

import json
import os

import pytest

from canon_megatank.lockfile import charge_write, load_budget, write_lock
from canon_megatank.types import LockfileBusyError, WriteBudgetExhaustedError

# ─── Write budget ─────────────────────────────────────────────────────────────


def test_budget_starts_at_zero(tmp_path) -> None:  # type: ignore[no-untyped-def]
    b = load_budget("UNIT", cap=50, state_dir=tmp_path)
    assert b.consumed == 0
    assert b.remaining == 50


def test_charge_increments_and_persists(tmp_path) -> None:  # type: ignore[no-untyped-def]
    charge_write("UNIT", cap=50, state_dir=tmp_path)
    charge_write("UNIT", cap=50, state_dir=tmp_path)
    assert load_budget("UNIT", cap=50, state_dir=tmp_path).consumed == 2


def test_charge_refuses_at_cap(tmp_path) -> None:  # type: ignore[no-untyped-def]
    for _ in range(3):
        charge_write("UNIT", cap=3, state_dir=tmp_path)
    # 4th charge is over cap — must refuse, and NOT increment past the cap
    with pytest.raises(WriteBudgetExhaustedError):
        charge_write("UNIT", cap=3, state_dir=tmp_path)
    assert load_budget("UNIT", cap=3, state_dir=tmp_path).consumed == 3


def test_budget_is_per_serial(tmp_path) -> None:  # type: ignore[no-untyped-def]
    charge_write("A", cap=5, state_dir=tmp_path)
    assert load_budget("B", cap=5, state_dir=tmp_path).consumed == 0


# ─── Lockfile ─────────────────────────────────────────────────────────────────


def test_lock_acquires_and_releases(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with write_lock("UNIT", run_dir=tmp_path) as p:
        assert p.exists()
    assert not p.exists()  # released on exit


def test_live_lock_blocks_second_holder(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with write_lock("UNIT", run_dir=tmp_path):  # noqa: SIM117 — outer lock MUST stay held while the inner acquire is attempted
        # a second acquire while we (this live pid) hold it must refuse
        with pytest.raises(LockfileBusyError), write_lock("UNIT", run_dir=tmp_path):
            pass


def test_stale_lock_is_reclaimed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    # plant a lock owned by a definitely-dead pid
    lock = tmp_path / "UNIT.lock"
    dead_pid = 2**31 - 1  # not a running process
    lock.write_text(json.dumps({"pid": dead_pid, "started": 0}))
    with write_lock("UNIT", run_dir=tmp_path) as p:
        # reclaimed: now owned by us
        assert json.loads(p.read_text())["pid"] == os.getpid()
