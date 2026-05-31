"""Write-budget + in-flight-op lockfile gate (T5).

Two independent guards a write op must pass:

1. **Write budget** — each test unit has a hard cap (default 50) on EEPROM
   writes before manual review. The count is persisted next to the unit's
   serial so it survives restarts. ``charge_write`` increments it atomically and
   refuses past the cap (``WriteBudgetExhaustedError``).

2. **Lockfile** — a ``/run`` lock so two ops can't drive the same unit at once
   (or a crashed op can't leave the device half-written). ``write_lock`` is a
   context manager; a stale lock (holder PID gone) is reclaimed, a live one
   raises ``LockfileBusyError``.

Both are filesystem-backed and dependency-free so they work identically on the
fleet host and under test (point them at a tmp dir).
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .types import LockfileBusyError, WriteBudget, WriteBudgetExhaustedError

DEFAULT_STATE_DIR = Path("/var/lib/canon-tool")
DEFAULT_RUN_DIR = Path("/run/canon-tool")


# ─── Write budget ─────────────────────────────────────────────────────────────


def _budget_path(serial: str, state_dir: Path) -> Path:
    return state_dir / f"{serial}.writes"


def load_budget(serial: str, *, cap: int, state_dir: Path = DEFAULT_STATE_DIR) -> WriteBudget:
    """Load the persisted write count for ``serial`` (0 if none yet)."""
    path = _budget_path(serial, state_dir)
    consumed = 0
    if path.exists():
        try:
            consumed = int(json.loads(path.read_text()).get("consumed", 0))
        except (ValueError, OSError, json.JSONDecodeError):
            consumed = 0
    return WriteBudget(cap=cap, consumed=consumed)


def charge_write(
    serial: str, *, cap: int, state_dir: Path = DEFAULT_STATE_DIR
) -> WriteBudget:
    """Charge one write against ``serial``'s budget, persisting the new count.

    Raises ``WriteBudgetExhaustedError`` BEFORE incrementing if already at the
    cap, so an exhausted unit is never charged further. Returns the updated
    budget (post-increment)."""
    budget = load_budget(serial, cap=cap, state_dir=state_dir)
    if budget.exhausted:
        raise WriteBudgetExhaustedError(
            f"write budget exhausted for {serial}: {budget.consumed}/{budget.cap} "
            "writes used. Manual review + a new test unit required."
        )
    budget.consumed += 1
    state_dir.mkdir(parents=True, exist_ok=True)
    _budget_path(serial, state_dir).write_text(
        json.dumps({"consumed": budget.consumed, "cap": budget.cap})
    )
    return budget


# ─── In-flight lockfile ───────────────────────────────────────────────────────


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    return True


@contextmanager
def write_lock(serial: str, *, run_dir: Path = DEFAULT_RUN_DIR) -> Iterator[Path]:
    """Hold an exclusive write lock for ``serial`` for the duration of the block.

    A live lock (holder PID still running) raises ``LockfileBusyError``. A stale
    lock (holder gone — e.g. a crashed op) is reclaimed. The lock file records
    the holder PID + start time as JSON.
    """
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise LockfileBusyError(
            f"cannot create lock dir {run_dir} ({exc}). On the fleet host "
            f"/run/canon-tool is writable; elsewhere pass run_dir= to a writable "
            f"path."
        ) from exc
    lock_path = run_dir / f"{serial}.lock"

    if lock_path.exists():
        holder = -1
        try:
            holder = int(json.loads(lock_path.read_text()).get("pid", -1))
        except (ValueError, OSError, json.JSONDecodeError):
            holder = -1
        if holder > 0 and _pid_alive(holder):
            raise LockfileBusyError(
                f"another op holds the lock for {serial} (pid {holder}). "
                f"If that process is gone, remove {lock_path}."
            )
        # stale — reclaim it

    lock_path.write_text(json.dumps({"pid": os.getpid(), "started": time.time()}))
    try:
        yield lock_path
    finally:
        with contextlib.suppress(FileNotFoundError):
            lock_path.unlink()
