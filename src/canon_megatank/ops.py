"""Read-only maintenance operations over the native pyusb transport (T5, safe subset).

This module implements the *read* path only: build a RECV request header with the
T3 formal model, push it over the claimed bulk endpoints, and decode the reply.
It deliberately contains **no write / reset / EEPROM-write code** — the reset path
is gated on T4 ground-truth (the literal absorber `cmd/arg/flags/idx`) and the
physical waste-ink pads, and is out of scope here.

Layering (one direction only):

    ops.read_counter ──uses──▶ protocol.model.encode_recv_header / decode_frame
                     ──uses──▶ usb.ClaimedDevice.read_response  (bulk OUT then IN)
                     ──gated by──▶ fingerprint.verify_fingerprint_matches

The literal ``(cmd, arg)`` that addresses the G6020 absorber/waste counter is
**NOT YET KNOWN** — Lane A is recovering it from a real capture. We do NOT invent
it. ``read_counter`` takes ``cmd`` / ``arg`` as parameters that default to ``None``
and raise :class:`ReadCommandNotDerivedError` when unset. The plumbing
(encode → transfer → decode) is what this module builds and tests; the concrete
command is filled in once Lane A lands it.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .protocol.model import decode_frame, encode_recv_header
from .types import CanonToolError, OperationOutcome, PrinterFingerprint

# ─── PENDING Lane A ──────────────────────────────────────────────────────────
#
# The maintenance command/argument that reads the G6020 absorber/waste-ink
# counter. These are unknown until Lane A recovers them from a captured
# "Read waste counters" exchange. They are intentionally ``None`` so that any
# attempt to read without supplying them fails loudly rather than guessing.
ABSORBER_READ_CMD: int | None = None  # PENDING Lane A — do NOT invent.
ABSORBER_READ_ARG: int | None = None  # PENDING Lane A — do NOT invent.


class ReadCommandNotDerivedError(CanonToolError):
    """The read ``(cmd, arg)`` hasn't been recovered yet (Lane A / T4).

    Raised when :func:`read_counter` is invoked without an explicit ``cmd`` /
    ``arg`` and the module-level PENDING defaults are still unset. This is a
    guard against shipping a guessed counter command."""


class ReadableDevice(Protocol):
    """The minimal read interface :func:`read_counter` needs from a device.

    ``usb.ClaimedDevice`` satisfies this. Defining it as a Protocol lets the
    unit tests drive a tiny in-memory fake without importing pyusb or touching
    hardware."""

    def read_response(
        self, request_header: bytes, *, timeout_ms: int = ..., length: int = ...
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class CounterReading:
    """Result of a read-counter op: the parsed reply plus an
    :class:`OperationOutcome` for metrics/logging.

    ``cmd`` / ``arg`` / ``payload`` are the decoded RECV reply frame. ``value``
    is the interpreted counter value when a ``decode`` callable is supplied and
    succeeds, else ``None`` (the raw ``payload`` is always available)."""

    outcome: OperationOutcome
    cmd: int
    arg: int
    payload: bytes
    value: int | None = None


def _summarize(payload: bytes, *, limit: int = 16) -> str:
    """Hex preview of a reply payload for the OperationOutcome summary."""
    head = payload[:limit].hex()
    return f"{len(payload)}B:{head}{'…' if len(payload) > limit else ''}"


def read_counter(
    device: ReadableDevice,
    *,
    runtime_fingerprint: PrinterFingerprint,
    cmd: int | None = None,
    arg: int | None = None,
    decode: Callable[[bytes], int] | None = None,
    timeout_ms: int = 5000,
    length: int = 64,
    printer_id: str = "canon-g6020",
    op_name: str = "read_counter",
    verify: Callable[[PrinterFingerprint, str], None] | None = None,
) -> CounterReading:
    """Read a maintenance counter over the native transport (read-only, safe).

    Sequence (the §8 native-tool RECV): verify we're talking to the locked test
    unit, ``encode_recv_header(cmd, arg)`` → ``device.read_response(...)`` →
    ``decode_frame(reply)``. Optionally interpret the payload via ``decode``.

    Gating: before any USB transfer, the runtime fingerprint is checked against
    the locked ``maintenance.yaml`` (UUID isolation + firmware/cmd_set match).
    A wrong-UUID device raises ``UnknownPrinterError``; firmware/cmd_set drift
    raises ``FingerprintMismatchError`` (both from
    :func:`fingerprint.verify_fingerprint_matches`). Reading is safe, but we
    still confirm the unit so a misidentified device can't be poked.

    ``cmd`` / ``arg`` are the RECV header fields. They default to the
    module-level PENDING values (``None``); if still unset,
    :class:`ReadCommandNotDerivedError` is raised — we never guess the absorber
    counter command. Lane A fills :data:`ABSORBER_READ_CMD` /
    :data:`ABSORBER_READ_ARG` once recovered.

    ``verify`` is injectable for testing; it defaults to
    ``fingerprint.verify_fingerprint_matches`` (imported lazily so this module
    stays importable without the SSOT present)."""
    if verify is None:
        from .fingerprint import verify_fingerprint_matches

        verify = verify_fingerprint_matches
    verify(runtime_fingerprint, printer_id)

    eff_cmd = cmd if cmd is not None else ABSORBER_READ_CMD
    eff_arg = arg if arg is not None else ABSORBER_READ_ARG
    if eff_cmd is None or eff_arg is None:
        raise ReadCommandNotDerivedError(
            "read command not yet derived: the absorber/waste-counter "
            "(cmd, arg) is PENDING Lane A — pass cmd= and arg= explicitly, or "
            "wait for ABSORBER_READ_CMD/ABSORBER_READ_ARG to be filled from a "
            "real capture. Refusing to guess."
        )

    request = encode_recv_header(eff_cmd, eff_arg)

    start = time.perf_counter()
    reply = device.read_response(request, timeout_ms=timeout_ms, length=length)
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    r_cmd, r_arg, payload = decode_frame(reply)

    value: int | None = None
    error: str | None = None
    if decode is not None:
        try:
            value = decode(payload)
        except Exception as exc:  # noqa: BLE001 — surface decode failure in outcome, don't crash the read
            error = f"decode failed: {exc}"

    outcome = OperationOutcome(
        op_name=op_name,
        success=error is None,
        elapsed_ms=elapsed_ms,
        bytes_sent=len(request),
        bytes_received=len(reply),
        response_summary=_summarize(payload),
        error=error,
    )
    return CounterReading(outcome=outcome, cmd=r_cmd, arg=r_arg, payload=payload, value=value)
