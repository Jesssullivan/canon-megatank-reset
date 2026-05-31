"""Pre-flight EEPROM dump + checksum gate (T5).

Before ANY write op (the absorber reset), the tool MUST capture a full EEPROM
dump of the target unit and checksum it. This is the rollback evidence: if a
write goes wrong, the operator has the pre-write state on disk, SHA-pinned.

The dump itself rides the same RECV transport as a counter read
(``usb.ClaimedDevice.read_response`` ← ``protocol.model.encode_recv_header``).
The literal EEPROM-read ``(cmd, arg)`` for the G6020 is **not yet derived** —
like the counter-read command it is PENDING, and we refuse to guess (a wrong
read command is harmless but a wrong *dump* gives false rollback confidence). So
``dump_eeprom`` takes ``cmd``/``arg`` explicitly and raises if unset.

No write/erase helpers live here — this module only READS the EEPROM.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .protocol.model import decode_frame, encode_recv_header
from .types import EepromDumpFailedError

# PENDING (same discipline as ops.ABSORBER_READ_*): the maintenance command that
# reads the EEPROM image. Unknown until recovered; never invented.
EEPROM_READ_CMD: int | None = None
EEPROM_READ_ARG: int | None = None

# Where baseline dumps land on the fleet host (matches WriteBudget's
# /var/lib/canon-tool convention; overridable for tests).
DEFAULT_DUMP_DIR = Path("/var/lib/canon-tool")


class ReadableDevice(Protocol):
    """Minimal read surface (same shape as ops.ReadableDevice)."""

    def read_response(
        self, request_header: bytes, *, timeout_ms: int = ..., length: int = ...
    ) -> bytes: ...


class EepromReadCommandNotDerivedError(EepromDumpFailedError):
    """The EEPROM-read ``(cmd, arg)`` hasn't been recovered yet. Refusing to
    guess — a bad dump gives false rollback confidence."""


@dataclass(frozen=True, slots=True)
class EepromDump:
    """A captured EEPROM image + its integrity metadata. The tool persists this
    (and pins the sha256 into maintenance.yaml) before any write is permitted."""

    data: bytes
    sha256: str
    captured_at_ms: int
    path: Path | None = None

    @property
    def size(self) -> int:
        return len(self.data)


def dump_eeprom(  # noqa: PLR0913 — read params + persistence target, each a distinct knob
    device: ReadableDevice,
    *,
    cmd: int | None = None,
    arg: int | None = None,
    expected_size: int | None = None,
    timeout_ms: int = 5000,
    read_length: int = 4096,
    out_dir: Path | None = None,
    serial: str | None = None,
) -> EepromDump:
    """Read the full EEPROM image and return it with a sha256.

    Refuses (``EepromReadCommandNotDerivedError``) unless an explicit
    ``(cmd, arg)`` is supplied — the G6020 EEPROM-read command is PENDING and we
    never guess it. If ``out_dir`` is given the dump is written to
    ``<out_dir>/<serial>-<ts>.eeprom`` (rollback evidence).

    ``expected_size`` (when known) is enforced: a short read raises
    ``EepromDumpFailedError`` rather than yielding a partial baseline.
    """
    eff_cmd = cmd if cmd is not None else EEPROM_READ_CMD
    eff_arg = arg if arg is not None else EEPROM_READ_ARG
    if eff_cmd is None or eff_arg is None:
        raise EepromReadCommandNotDerivedError(
            "EEPROM-read (cmd, arg) is not derived yet — pass cmd= and arg= "
            "explicitly. Refusing to guess: a wrong dump gives false rollback "
            "confidence."
        )

    request = encode_recv_header(eff_cmd, eff_arg)
    reply = device.read_response(request, timeout_ms=timeout_ms, length=read_length)
    _cmd, _arg, payload = decode_frame(reply)

    if not payload:
        raise EepromDumpFailedError("EEPROM dump returned an empty payload")
    if expected_size is not None and len(payload) != expected_size:
        raise EepromDumpFailedError(
            f"EEPROM dump size mismatch: got {len(payload)} bytes, "
            f"expected {expected_size}"
        )

    digest = hashlib.sha256(payload).hexdigest()
    ts = int(time.time() * 1000)

    out_path: Path | None = None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        name = f"{serial or 'unknown'}-{ts}.eeprom"
        out_path = out_dir / name
        out_path.write_bytes(payload)

    return EepromDump(data=payload, sha256=digest, captured_at_ms=ts, path=out_path)


def verify_dump(dump: EepromDump, expected_sha256: str) -> None:
    """Confirm a dump matches a previously-pinned sha256. Used to re-validate a
    baseline before trusting it as rollback evidence. Raises on mismatch."""
    if dump.sha256 != expected_sha256:
        raise EepromDumpFailedError(
            f"EEPROM dump sha mismatch: got {dump.sha256}, "
            f"expected {expected_sha256}"
        )
