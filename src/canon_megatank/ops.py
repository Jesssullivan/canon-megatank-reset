"""Maintenance operations over the native pyusb transport (T5).

Two ops:

* ``read_counter`` — the *read* path (RECV): safe, no state change. The literal
  counter ``(cmd, arg)`` is still PENDING and never guessed.
* ``reset_absorber`` — the *write* path (SEND): the 5B00 absorber reset, built on
  the statically-derived payload ``[00,03,flags,03,idx]`` (idx 0x07 = "Main").
  It is **dry-run by default** and ``execute=True`` is HARD-GATED behind, in
  order: UUID isolation, the `derived-unvalidated`→`verified-captured` status
  promotion, a mandatory pre-flight EEPROM dump, the per-unit write budget, and
  an in-flight lockfile. The derived bytes are NOT written to a real printer
  until a physical-validation run promotes the SSOT status (itself gated on the
  waste-ink pads). Until then ``execute=True`` raises ``ResetNotValidatedError``.

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
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .protocol.model import (
    ABSORBER_FLAGS,
    ABSORBER_MAIN_IDX,
    AbsorberResetSpec,
    decode_frame,
    derive_reset_frame,
    encode_recv_header,
)
from .types import (
    CanonToolError,
    OperationOutcome,
    PrinterFingerprint,
    ResetNotValidatedError,
)

# ─── Status-read command (recovered from v5103, not guessed) ─────────────────
#
# The Service Tool's read poll loop (FUN_0040f500) issues a RECV via the
# EncCommService wrapper: FUN_0042b030(handle, 0x86, 0, mode=1/RECV, buf, 0x14,
# ...). So the generic STATUS READ is cmd=0x86, arg=0x0000, reading a 20-byte
# (0x14) status frame. This is the same wrapper that sends with cmd=0x85
# (FUN_0040fa60) — matching our reset header. See
# docs/research/servicetool-v5103-read-re.md.
#
# CAVEAT: 0x86/0x0000 is the *generic status RECV* (a 20-byte frame the tool
# polls). Whether that frame directly carries the absorber counter, or whether a
# SEND must first select the counter, is not yet pinned — so this is the read
# TRANSPORT command, validated safe to issue, not (yet) a proven "absorber value
# at offset N" decode. Callers may still pass cmd=/arg= explicitly to override.
ABSORBER_READ_CMD: int | None = 0x86  # generic status RECV (v5103 FUN_0040f500)
ABSORBER_READ_ARG: int | None = 0x0000
STATUS_READ_LEN = 0x14  # 20-byte status frame the Service Tool reads


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


def read_counter(  # noqa: PLR0913 — gated read API: each kwarg is a distinct safety/injection seam
    device: ReadableDevice,
    *,
    runtime_fingerprint: PrinterFingerprint,
    cmd: int | None = None,
    arg: int | None = None,
    decode: Callable[[bytes], int] | None = None,
    timeout_ms: int = 5000,
    length: int = STATUS_READ_LEN,
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
        from .fingerprint import verify_fingerprint_matches  # noqa: PLC0415

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


# ─── Write path: the absorber reset (gated, dry-run by default) ───────────────


class WritableDevice(ReadableDevice, Protocol):
    """A device that can also SEND. ``usb.ClaimedDevice`` satisfies this; tests
    drive a fake recording the bytes that would be written."""

    def send_command(self, frame: bytes, *, timeout_ms: int = ...) -> int: ...


# The generic SEND header for group-7 (operation identity rides in the payload,
# not the cmd byte — see servicetool-v5103-static-re.md §5). arg=0x0000.
RESET_HEADER_CMD = 0x85
RESET_HEADER_ARG = 0x0000


@dataclass(frozen=True, slots=True)
class ResetPlan:
    """The fully-resolved absorber-reset, returned by ``reset_absorber`` whether
    or not it executed. ``frame`` is the exact wire bytes
    ``derive_reset_frame`` produced; ``executed`` says if they were sent."""

    spec: AbsorberResetSpec
    frame: bytes
    executed: bool
    outcome: OperationOutcome


def build_absorber_reset_spec(
    *, checkbox: bool = False, idx: int = ABSORBER_MAIN_IDX
) -> AbsorberResetSpec:
    """Build the reset spec for the main absorber (idx 0x07) by default.

    ``checkbox`` selects flags 0x81 vs 0x01 (the Service Tool dialog checkbox).
    ``idx`` defaults to the label-confirmed main absorber; override only with a
    value from ``protocol.model.ABSORBER_IDX``."""
    flags = 0x81 if checkbox else 0x01
    if flags not in ABSORBER_FLAGS:  # invariant; AbsorberResetSpec re-validates too
        raise CanonToolError(f"computed flags {flags:#04x} not in {ABSORBER_FLAGS!r}")
    return AbsorberResetSpec(
        cmd=RESET_HEADER_CMD, arg=RESET_HEADER_ARG, flags=flags, idx=idx
    )


def reset_absorber(  # noqa: PLR0913 — each kwarg is a distinct safety gate / injection seam
    device: WritableDevice,
    *,
    runtime_fingerprint: PrinterFingerprint,
    eeprom_dump_done: bool,
    execute: bool = False,
    checkbox: bool = False,
    idx: int = ABSORBER_MAIN_IDX,
    timeout_ms: int = 5000,
    printer_id: str = "canon-g6020",
    verify: Callable[[PrinterFingerprint, str], None] | None = None,
    charge: Callable[[], None] | None = None,
    load_doc: Callable[[str], dict[str, Any]] | None = None,
) -> ResetPlan:
    """Reset the 5B00 ink-absorber counter — DRY-RUN by default.

    Always returns a :class:`ResetPlan` with the exact ``frame`` that would be
    (or was) sent, so a dry run shows the operator the literal bytes.

    ``execute=True`` actually writes, and ONLY after passing every gate, IN ORDER:

      1. **UUID isolation** — ``verify`` (fingerprint match against the locked
         test_unit). Wrong unit → ``UnknownPrinterError``/``FingerprintMismatchError``.
      2. **Validation status** — ``maintenance.yaml::absorber_reset.status`` must
         be ``verified-captured``. While it is ``derived-unvalidated`` (bytes from
         static RE, not yet physically confirmed; pads still full) → HARD STOP
         with ``ResetNotValidatedError``.
      3. **EEPROM baseline** — ``eeprom_dump_done`` must be True (the caller ran
         ``eeprom.dump_eeprom`` first). No rollback evidence → refuse.
      4. **Write budget** — ``charge`` (raises ``WriteBudgetExhaustedError`` at
         the cap). Charged BEFORE the write so an exhausted unit never writes.
      5. **Lockfile** — the caller wraps this in ``lockfile.write_lock`` so two
         ops can't race (passed by the CLI, not re-checked here).

    The dependencies are injectable (``verify``/``charge``/``load_doc``) so the
    full gate sequence is unit-testable without hardware or the SSOT.
    """
    spec = build_absorber_reset_spec(checkbox=checkbox, idx=idx)
    frame = derive_reset_frame(spec)

    if not execute:
        outcome = OperationOutcome(
            op_name="reset_absorber",
            success=True,
            elapsed_ms=0,
            bytes_sent=0,
            bytes_received=0,
            response_summary=f"DRY-RUN frame={frame.hex()}",
        )
        return ResetPlan(spec=spec, frame=frame, executed=False, outcome=outcome)

    # ── execute=True: run the gates in order ──────────────────────────────
    # 1. UUID isolation
    if verify is None:
        from .fingerprint import verify_fingerprint_matches  # noqa: PLC0415

        verify = verify_fingerprint_matches
    verify(runtime_fingerprint, printer_id)

    # 2. derived-unvalidated → verified-captured gate
    if load_doc is None:
        from .fingerprint import load_maintenance  # noqa: PLC0415

        load_doc = load_maintenance
    status = (
        load_doc(printer_id).get("supported", {}).get("absorber_reset", {}).get("status")
    )
    if status != "verified-captured":
        raise ResetNotValidatedError(
            f"absorber_reset.status is {status!r}, not 'verified-captured'. The "
            "reset bytes are statically DERIVED but not yet physically validated "
            "(and the waste-ink pads are not confirmed installed). Refusing to "
            "write derived bytes to a printer. Promote the SSOT status only after "
            "a successful, pads-installed physical-validation run."
        )

    # 3. mandatory EEPROM baseline
    if not eeprom_dump_done:
        from .types import EepromDumpFailedError  # noqa: PLC0415

        raise EepromDumpFailedError(
            "no pre-flight EEPROM dump — run eeprom.dump_eeprom first. Refusing "
            "to write without rollback evidence."
        )

    # 4. write budget (raises at cap, before the write)
    if charge is not None:
        charge()

    # 5. (lockfile held by the caller) — perform the write
    start = time.perf_counter()
    written = device.send_command(frame, timeout_ms=timeout_ms)
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    outcome = OperationOutcome(
        op_name="reset_absorber",
        success=True,
        elapsed_ms=elapsed_ms,
        bytes_sent=written,
        bytes_received=0,
        response_summary=f"SENT frame={frame.hex()}",
    )
    return ResetPlan(spec=spec, frame=frame, executed=True, outcome=outcome)


# ─── Service-mode CONTROL-TRANSFER reset path (the WICReset transport) ─────────
#
# The bulk-frame reset above (encode_send → BULK_OUT 0x03) is the v5103-derived
# path: ACK'd by the printer but firmware-GATED — 5B00 persists after it. The
# REAL working reset WICReset uses is an EP0 *control* transfer to the device in
# service mode (idProduct 0x12fe). Captured shape (Lane C, ctrl-reset pcap):
#
#   bmRequestType=0x40 (vendor, host→device, recipient=device)
#   bRequest=0x85  wValue=0x0000  wIndex=0x0000  data=[00 03 01 03 07]
#
# framed by class control-IN reads (0xA1/0x00 1284-id, 0xA1/0x01 port-status).
# This module drives that captured sequence over ClaimedDevice.control_transfer
# behind the SAME gate stack as reset_absorber. The literal sequence is loaded
# from the SSOT (printers/canon-g6020/maintenance.yaml::supported.absorber_reset
# .control_sequence) and is a PLACEHOLDER until a real WICReset capture lands —
# so this path additionally refuses unless the SSOT marks it captured+verified.

# The known-from-capture reset control transfer (the one vendor OUT). This is the
# annotation/expected-value anchor, NOT a license to write a guessed sequence:
# the actual replayed sequence MUST come from the SSOT control_sequence.
CTRL_RESET_BMREQUESTTYPE = 0x40   # vendor | host→device | recipient=device
CTRL_RESET_BREQUEST = 0x85
CTRL_RESET_WVALUE = 0x0000
CTRL_RESET_WINDEX = 0x0000
CTRL_RESET_DATA = bytes([0x00, 0x03, 0x01, 0x03, 0x07])


class ControlTransferDevice(Protocol):
    """A device that can drive a single EP0 control transfer.
    ``usb.ClaimedDevice`` satisfies this; tests drive a fake that records the
    (bmRequestType, bRequest, wValue, wIndex, data) tuples it was asked to send.
    """

    def control_transfer(  # noqa: PLR0913 — mirrors the USB setup packet (5 wire fields)
        self,
        bm_request_type: int,
        b_request: int,
        w_value: int,
        w_index: int,
        data_or_length: bytes | int,
        *,
        timeout_ms: int = ...,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class ControlStep:
    """One control transfer in a captured/replayed sequence.

    ``data`` is the OUT payload (host→device) for an OUT transfer, or the IN read
    length encoded as ``bytes`` is NOT used — IN steps carry ``read_length``. The
    direction is read from bit 7 of ``bm_request_type``.
    """

    bm_request_type: int
    b_request: int
    w_value: int
    w_index: int
    data: bytes = b""        # OUT payload (ignored for IN steps)
    read_length: int = 0     # IN read length (ignored for OUT steps)

    @property
    def is_out(self) -> bool:
        return (self.bm_request_type & 0x80) == 0

    def is_known_reset(self) -> bool:
        """True iff this is the captured vendor absorber-reset OUT."""
        return (
            self.bm_request_type == CTRL_RESET_BMREQUESTTYPE
            and self.b_request == CTRL_RESET_BREQUEST
            and self.w_value == CTRL_RESET_WVALUE
            and self.w_index == CTRL_RESET_WINDEX
            and self.data == CTRL_RESET_DATA
        )


@dataclass(frozen=True, slots=True)
class ControlReplayPlan:
    """Result of a control-sequence replay (dry-run or executed)."""

    steps: tuple[ControlStep, ...]
    executed: bool
    responses: tuple[bytes, ...]
    outcome: OperationOutcome


def parse_control_sequence(raw: Sequence[Any]) -> tuple[ControlStep, ...]:
    """Build ``ControlStep``s from the SSOT ``control_sequence`` list.

    Each SSOT entry is a mapping with ``bmRequestType``/``bRequest``/``wValue``/
    ``wIndex`` and either ``data`` (hex string, OUT) or ``read_length`` (IN).
    Integers may be given as YAML ints or ``0x..`` strings. Raises
    ``CanonToolError`` on a malformed entry — we never silently drop a step."""
    steps: list[ControlStep] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise CanonToolError(f"control_sequence[{i}] is not a mapping: {entry!r}")

        def _num(key: str, *, idx: int = i, e: Any = entry) -> int:
            v = e.get(key, 0)
            if isinstance(v, str):
                return int(v, 0)
            return int(v)

        data_hex = entry.get("data", "")
        data = bytes.fromhex(data_hex) if data_hex else b""
        steps.append(
            ControlStep(
                bm_request_type=_num("bmRequestType"),
                b_request=_num("bRequest"),
                w_value=_num("wValue"),
                w_index=_num("wIndex"),
                data=data,
                read_length=int(entry.get("read_length", 0) or 0),
            )
        )
    return tuple(steps)


def replay_control_sequence(  # noqa: PLR0913, PLR0912 — gates + injection seams; branchy by design (gate ladder + per-step drive)
    device: ControlTransferDevice,
    *,
    runtime_fingerprint: PrinterFingerprint,
    eeprom_dump_done: bool,
    steps: Sequence[ControlStep] | None = None,
    execute: bool = False,
    timeout_ms: int = 5000,
    printer_id: str = "canon-g6020",
    verify: Callable[[PrinterFingerprint, str], None] | None = None,
    charge: Callable[[], None] | None = None,
    load_doc: Callable[[str], dict[str, Any]] | None = None,
) -> ControlReplayPlan:
    """Replay a captured EP0 control-transfer reset sequence — DRY-RUN by default.

    This is the WICReset service-mode transport (vendor control-OUT on EP0), the
    sibling of :func:`reset_absorber`'s bulk path. It runs the EXACT SAME gate
    stack, IN ORDER, before any OUT transfer touches the device:

      1. **UUID isolation** — ``verify`` (fingerprint match vs locked test_unit).
      2. **Validation status** — ``maintenance.yaml::absorber_reset.status`` must
         be ``verified-captured``. A placeholder/derived sequence → HARD STOP
         (``ResetNotValidatedError``). The control_sequence is itself a PLACEHOLDER
         in the SSOT until a real WICReset capture is extracted + pinned.
      3. **EEPROM baseline** — ``eeprom_dump_done`` must be True.
      4. **Write budget** — ``charge`` (raises at the cap, before any OUT write).
      5. **Lockfile** — held by the caller.

    ``steps`` defaults to the SSOT ``control_sequence`` (via ``load_doc``); if it
    is empty/unset, the op refuses (``ResetNotValidatedError``) rather than
    inventing a sequence. Dry-run returns the resolved steps + the literal bytes
    each OUT would push, WITHOUT consulting any gate or touching the device.

    Dependencies (``verify``/``charge``/``load_doc``) are injectable so the full
    gate sequence is unit-testable without hardware or the SSOT.
    """
    # Resolve the steps from the SSOT when not explicitly supplied.
    if steps is None:
        if load_doc is None:
            from .fingerprint import load_maintenance  # noqa: PLC0415

            load_doc = load_maintenance
        raw = (
            load_doc(printer_id)
            .get("supported", {})
            .get("absorber_reset", {})
            .get("control_sequence")
            or []
        )
        resolved = parse_control_sequence(raw)
    else:
        resolved = tuple(steps)

    def _preview() -> str:
        return ", ".join(
            (
                f"OUT {s.bm_request_type:#04x}/{s.b_request:#04x} {s.data.hex()}"
                if s.is_out
                else f"IN {s.bm_request_type:#04x}/{s.b_request:#04x} len={s.read_length}"
            )
            for s in resolved
        )

    if not execute:
        outcome = OperationOutcome(
            op_name="replay_control_sequence",
            success=True,
            elapsed_ms=0,
            bytes_sent=0,
            bytes_received=0,
            response_summary=f"DRY-RUN steps=[{_preview()}]",
        )
        return ControlReplayPlan(
            steps=resolved, executed=False, responses=(), outcome=outcome
        )

    # ── execute=True: run the gates in order ──────────────────────────────
    # 1. UUID isolation
    if verify is None:
        from .fingerprint import verify_fingerprint_matches  # noqa: PLC0415

        verify = verify_fingerprint_matches
    verify(runtime_fingerprint, printer_id)

    # 2. derived-unvalidated → verified-captured gate (+ require a real sequence)
    if load_doc is None:
        from .fingerprint import load_maintenance  # noqa: PLC0415

        load_doc = load_maintenance
    status = (
        load_doc(printer_id).get("supported", {}).get("absorber_reset", {}).get("status")
    )
    if status != "verified-captured":
        raise ResetNotValidatedError(
            f"absorber_reset.status is {status!r}, not 'verified-captured'. The "
            "control_sequence is a PLACEHOLDER until a real WICReset capture is "
            "extracted (scripts/parse-wicreset-capture.py) and pinned in the SSOT. "
            "Refusing to drive a control-transfer reset before ground-truth."
        )
    if not resolved:
        raise ResetNotValidatedError(
            "control_sequence is empty — no captured EP0 reset to replay. Capture "
            "a real WICReset session, extract it, and pin it in maintenance.yaml."
        )

    # 3. mandatory EEPROM baseline
    if not eeprom_dump_done:
        from .types import EepromDumpFailedError  # noqa: PLC0415

        raise EepromDumpFailedError(
            "no pre-flight EEPROM dump — run eeprom.dump_eeprom first. Refusing "
            "to write without rollback evidence."
        )

    # 4. write budget (charged once, before any OUT write)
    if charge is not None:
        charge()

    # 5. (lockfile held by the caller) — drive the sequence
    start = time.perf_counter()
    responses: list[bytes] = []
    bytes_sent = 0
    bytes_received = 0
    for step in resolved:
        if step.is_out:
            device.control_transfer(
                step.bm_request_type,
                step.b_request,
                step.w_value,
                step.w_index,
                step.data,
                timeout_ms=timeout_ms,
            )
            bytes_sent += len(step.data)
            responses.append(b"")
        else:
            reply = device.control_transfer(
                step.bm_request_type,
                step.b_request,
                step.w_value,
                step.w_index,
                step.read_length,
                timeout_ms=timeout_ms,
            )
            bytes_received += len(reply)
            responses.append(reply)
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    outcome = OperationOutcome(
        op_name="replay_control_sequence",
        success=True,
        elapsed_ms=elapsed_ms,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        response_summary=f"REPLAYED {len(resolved)} control transfers",
    )
    return ControlReplayPlan(
        steps=resolved, executed=True, responses=tuple(responses), outcome=outcome
    )
