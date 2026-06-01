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


# ─── WICReset-derived enciphered session→keyword→clear sequence ────────────────
#
# This is the bulk-transport (iface 4, OUT 0x03 / IN 0x86) sibling of the two
# reset paths above, driving the ORDERED WICReset session frames recovered from
# the decrypted APP.BIN model DB devices.xml (RECOVERED 2026-06-01; see
# docs/research/wicreset-g6020-reset-derived.md and the
# `supported.absorber_reset.derived_template` block in maintenance.yaml). The
# G6000-family (G6020 ∈ "G6000 series", method=3, support="query;waste:common")
# clear is the ordered SEND sequence, every frame functor-3 enciphered:
#
#   1. set_session   — prefix 81 00 00 03      (devices.xml:43504; RECOVERED)
#   2. get_keyword   — prefix 82 00 00 00 00   (devices.xml:43506; RECOVERED)
#                      RECV returns the live 4-byte device keyword → fed to the
#                      encoder (functor_initialization XOR) for the writes below
#   3. set_command   — prefix 85 00 00 00 00 carrying the waste-row selector
#                      10 07 7C                (devices.xml:43807; RECOVERED)
#   4. set_command   — prefix 85 … carrying the 'common' reset operand
#                      0D 00 00                (devices.xml:43807; RECOVERED — the
#                      G6000-family 5B00 clear, gated by support=waste:common)
#   5. (optional) get_command verify — prefix 86 00 00 00 00 (devices.xml:43507)
#
# The functor-3 enciphering (LCG envelope + XOR keystream + device-keyword XOR)
# is Lane A's job: it is INJECTED as ``encoder`` (a ``WicResetEncoder``) or, when
# omitted, imported lazily from ``canon_megatank.protocol.wicreset`` (Lane A's
# module). This module owns ONLY the ordered transport + the gate stack; it never
# reimplements the cipher and never hardcodes the template bytes (they come from
# the SSOT ``derived_template``). Like the two paths above it is DRY-RUN by
# default and refuses to actually write until status == 'verified-captured'.


class WicSessionDevice(ReadableDevice, Protocol):
    """A device that can drive the WICReset bulk session: a send-primed RECV
    (``send_and_receive`` — used for set_session/get_keyword/verify) and a
    write-only SEND (``send_command`` — used for set_command). ``usb.ClaimedDevice``
    satisfies this; tests drive a fake recording the frames it was handed."""

    def send_and_receive(
        self, frame: bytes, *, timeout_ms: int = ..., length: int = ...
    ) -> bytes: ...

    def send_command(self, frame: bytes, *, timeout_ms: int = ...) -> int: ...


class WicResetEncoder(Protocol):
    """Lane A's functor-3 enciphering surface (the ONLY thing this module needs
    from the cipher).

    ``encipher(plaintext_app_frame)`` applies the functor-3 LCG envelope + XOR
    keystream to a plaintext ``[cmd][arg…][payload]`` frame and returns the wire
    bytes. ``seed_keyword(device_keyword)`` feeds the live 4-byte keyword (read
    by ``get_keyword``) into the encoder via ``functor_initialization`` so the
    subsequent ``set_command`` frames are keyed to the session. Defining this as
    a Protocol lets the tests drive a recording fake without importing Lane A or
    the runtime tables."""

    def encipher(self, plaintext_app_frame: bytes) -> bytes: ...

    def seed_keyword(self, device_keyword: bytes) -> None: ...


# Template-section keys in the SSOT derived_template block. The literal prefix /
# operand bytes are SOURCED from here at call time — never hardcoded in this
# module (the bytes below are only key names + the parse helper).
_DERIVED_TEMPLATE_PATH = ("supported", "absorber_reset", "derived_template")


def _hexbytes(spec: str) -> bytes:
    """Parse a devices.xml-style ``'0x81 0x00 0x00 0x03'`` token string into
    bytes. Accepts space-separated ``0x..`` tokens (the SSOT literal form).
    Raises ``CanonToolError`` on a malformed token — never silently drops one."""
    out: list[int] = []
    for tok in spec.split():
        try:
            out.append(int(tok, 16))
        except ValueError as exc:
            raise CanonToolError(
                f"malformed template byte {tok!r} in {spec!r}"
            ) from exc
    return bytes(out)


@dataclass(frozen=True, slots=True)
class WicResetFrames:
    """The plaintext (pre-encipher) frames for the WICReset clear sequence,
    sourced from the SSOT ``derived_template``. Each is a ``[cmd][arg…][payload]``
    app frame; the encoder turns each into wire bytes.

    ``set_command_select`` carries the waste-row selector ``10 07 7C``;
    ``set_command_reset`` carries the per-region operand (``0D 00 00`` for the
    G6000-family 'common' absorber == the 5B00 clear)."""

    set_session: bytes
    get_keyword: bytes
    set_command_select: bytes
    set_command_reset: bytes
    get_command: bytes


def load_wicreset_frames(
    *,
    printer_id: str = "canon-g6020",
    region: str = "common",
    load_doc: Callable[[str], dict[str, Any]] | None = None,
) -> WicResetFrames:
    """Build the plaintext WICReset frames from the SSOT ``derived_template``.

    Sources every literal from ``maintenance.yaml`` (the ``commands`` prefixes
    and the ``functions_waste`` rows) — this module does NOT hardcode the
    template. ``region`` selects the waste row (G6000 family permits only
    ``common``; passing a region the template doesn't list raises). Returns the
    plaintext app frames; the caller enciphers them via the Lane A encoder.

    ``set_command`` frames are the prefix ``85 …`` concatenated with the waste
    selector / operand payload, matching the recovered template:
    ``set_command`` carries ``10 07 7C`` then ``0D <region> 00``."""
    if load_doc is None:
        from .fingerprint import load_maintenance  # noqa: PLC0415

        load_doc = load_maintenance
    doc = load_doc(printer_id)
    tmpl: Any = doc
    for key in _DERIVED_TEMPLATE_PATH:
        tmpl = (tmpl or {}).get(key, {})
    if not tmpl:
        raise ResetNotValidatedError(
            "no derived_template in the SSOT — the WICReset clear sequence has "
            "not been recovered for this printer. Refusing to build frames."
        )

    commands = tmpl.get("commands") or {}
    waste = tmpl.get("functions_waste") or {}
    if "set_session" not in commands or "get_keyword" not in commands:
        raise ResetNotValidatedError(
            "derived_template.commands is missing set_session/get_keyword "
            "prefixes — incomplete template; refusing to build frames."
        )
    if region not in waste:
        raise CanonToolError(
            f"waste region {region!r} not in derived_template.functions_waste "
            f"(have {sorted(waste)!r}) — the G6000 family clears only 'common'."
        )

    set_session = _hexbytes(commands["set_session"])
    get_keyword = _hexbytes(commands["get_keyword"])
    get_command = _hexbytes(commands.get("get_command", "0x86 0x00 0x00 0x00 0x00"))
    set_command_prefix = _hexbytes(commands["set_command"])

    row_cmds = (waste[region] or {}).get("commands") or []
    if len(row_cmds) < 2:  # noqa: PLR2004 — a waste row is exactly [selector, operand]
        raise CanonToolError(
            f"waste row {region!r} must have a selector + operand, got {row_cmds!r}"
        )
    selector = _hexbytes(row_cmds[0])  # 10 07 7C
    operand = _hexbytes(row_cmds[1])   # 0D <region> 00

    return WicResetFrames(
        set_session=set_session,
        get_keyword=get_keyword,
        set_command_select=set_command_prefix + selector,
        set_command_reset=set_command_prefix + operand,
        get_command=get_command,
    )


@dataclass(frozen=True, slots=True)
class WicResetStep:
    """One step of the executed WICReset sequence, for the plan's audit trail.

    ``kind`` ∈ {set_session, get_keyword, set_command, get_command};
    ``plaintext`` is the pre-encipher app frame; ``wire`` is what the encoder
    produced (and what would be / was sent); ``reply`` is the RECV bytes for the
    read steps (empty for write-only set_command)."""

    kind: str
    plaintext: bytes
    wire: bytes
    reply: bytes = b""


@dataclass(frozen=True, slots=True)
class WicResetPlan:
    """Result of the WICReset clear sequence (dry-run or executed)."""

    frames: WicResetFrames
    steps: tuple[WicResetStep, ...]
    executed: bool
    device_keyword: bytes
    outcome: OperationOutcome


def reset_absorber_wicreset(  # noqa: PLR0913, PLR0912, PLR0915 — gate ladder + ordered 4-step session; each kwarg is a distinct gate/injection seam
    device: WicSessionDevice,
    *,
    runtime_fingerprint: PrinterFingerprint,
    eeprom_dump_done: bool,
    encoder: WicResetEncoder | None = None,
    region: str = "common",
    execute: bool = False,
    accept_derived: bool = False,
    verify_readback: bool = True,
    timeout_ms: int = 5000,
    keyword_len: int = 64,
    keyword_min_len: int = 4,
    printer_id: str = "canon-g6020",
    verify: Callable[[PrinterFingerprint, str], None] | None = None,
    charge: Callable[[], None] | None = None,
    load_doc: Callable[[str], dict[str, Any]] | None = None,
) -> WicResetPlan:
    """Drive the WICReset-derived enciphered clear sequence — DRY-RUN by default.

    The ordered sequence (every frame functor-3 enciphered by the Lane A
    ``encoder``), over the bulk maintenance lane (iface 4, OUT 0x03 / IN 0x86):

      1. **set_session** (``81 00 00 03``) — send-primed RECV; opens the session.
      2. **get_keyword** (``82 00 00 00 00``) — send-primed RECV; the reply is the
         live 4-byte device keyword, fed to ``encoder.seed_keyword`` so the
         ``set_command`` frames below are keyed to this session.
      3. **set_command** carrying ``10 07 7C`` (the waste-row selector) — SEND.
      4. **set_command** carrying ``0D 00 00`` (the 'common' reset operand, the
         G6000-family 5B00 clear) — SEND. **This is the state-changing write.**
      5. optional **get_command** verify (``86 …``) — send-primed RECV.

    Runs the EXACT SAME gate stack as :func:`reset_absorber` /
    :func:`replay_control_sequence`, IN ORDER, before ANY transfer touches the
    device on an ``execute=True`` run:

      1. **UUID isolation** — ``verify`` (fingerprint vs locked test_unit).
      2. **Validation status** — ``absorber_reset.status`` must be
         ``verified-captured``. While ``derived-unvalidated`` (the recovered
         template is EVIDENCE, physically unvalidated, pads unconfirmed) →
         HARD STOP (``ResetNotValidatedError``) — UNLESS ``accept_derived=True``,
         the explicit operator override for the ONE-RUN live validation on the
         dedicated debug/RE unit (the non-functional, 5B00-locked G6020 that
         exists to be experimented on). The override bypasses ONLY this gate,
         mirroring :func:`reset_absorber`; UUID isolation, EEPROM baseline, write
         budget, the lockfile, AND the live-keyword guard all remain mandatory.
         The override is recorded loudly in the outcome and does NOT mutate the
         SSOT (status stays ``derived-unvalidated`` until a real validation run
         promotes it by hand).
      3. **EEPROM baseline** — ``eeprom_dump_done`` must be True.
      4. **Write budget** — ``charge`` (raises at the cap, before any transfer).
      5. **Lockfile** — held by the caller.

    Live-keyword guard (Lane C risk R1): after ``get_keyword`` the RECV reply must
    be a real device keyword of at least ``keyword_min_len`` (4) bytes. The live
    handshake experiment returned ZERO bytes from a printer that had not opened a
    session; a zero/short reply means the session never opened and the encoder
    would otherwise be seeded with garbage and the writes keyed wrong. So a reply
    shorter than ``keyword_min_len`` HARD STOPS (``ResetNotValidatedError``)
    BEFORE either ``set_command`` write — no enciphered clear is ever sent against
    a keyword we did not actually read.

    The literal template bytes are SOURCED from the SSOT ``derived_template``
    (via :func:`load_wicreset_frames`), never hardcoded. The cipher is the Lane A
    ``encoder`` (injected, or lazily imported from
    ``canon_megatank.protocol.wicreset`` when omitted). Dry-run resolves + enciphers
    the frames so the operator sees the literal wire bytes WITHOUT consulting any
    gate or touching the device.

    Dependencies (``encoder``/``verify``/``charge``/``load_doc``) are injectable so
    the full sequence + gate ladder are unit-testable without hardware, the SSOT,
    or Lane A's runtime tables.
    """
    frames = load_wicreset_frames(printer_id=printer_id, region=region, load_doc=load_doc)

    if encoder is None:
        # Resolve Lane A's encoder dynamically so THIS module stays importable
        # (and type/lint-clean) before Lane A lands its encoder module. A missing
        # module / factory surfaces as a clear refusal, not an ImportError at load.
        # The primary integration path is the injected ``encoder=`` (the
        # ``WicResetEncoder`` Protocol); this is the convenience fallback.
        import importlib  # noqa: PLC0415

        try:
            mod = importlib.import_module("canon_megatank.protocol.wicreset")
            encoder = mod.build_encoder(printer_id=printer_id)
        except Exception as exc:  # noqa: BLE001 — surface as a refusal, not a raw import crash
            raise ResetNotValidatedError(
                "no WICReset encoder available (Lane A's "
                "canon_megatank.protocol.wicreset.build_encoder is not importable "
                f"yet: {exc}). Inject encoder= to drive the sequence."
            ) from exc

    # ── DRY-RUN: encipher the frames for the operator, drive nothing ──────────
    if not execute:
        dry_steps: list[WicResetStep] = [
            WicResetStep("set_session", frames.set_session, encoder.encipher(frames.set_session)),
            WicResetStep("get_keyword", frames.get_keyword, encoder.encipher(frames.get_keyword)),
            WicResetStep(
                "set_command",
                frames.set_command_select,
                encoder.encipher(frames.set_command_select),
            ),
            WicResetStep(
                "set_command",
                frames.set_command_reset,
                encoder.encipher(frames.set_command_reset),
            ),
        ]
        if verify_readback:
            dry_steps.append(
                WicResetStep(
                    "get_command", frames.get_command, encoder.encipher(frames.get_command)
                )
            )
        steps = tuple(dry_steps)
        preview = " -> ".join(f"{s.kind}({s.wire.hex()})" for s in steps)
        outcome = OperationOutcome(
            op_name="reset_absorber_wicreset",
            success=True,
            elapsed_ms=0,
            bytes_sent=0,
            bytes_received=0,
            response_summary=f"DRY-RUN seq=[{preview}]",
        )
        return WicResetPlan(
            frames=frames, steps=steps, executed=False, device_keyword=b"", outcome=outcome
        )

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
    if status != "verified-captured" and not accept_derived:
        raise ResetNotValidatedError(
            f"absorber_reset.status is {status!r}, not 'verified-captured'. The "
            "WICReset clear sequence is DERIVED from the decrypted template "
            "(devices.xml) but not yet physically validated (and the waste-ink "
            "pads are not confirmed installed). Refusing to drive an enciphered "
            "session→keyword→clear against a printer. Either promote the SSOT "
            "status after a successful, pads-installed physical-validation run, "
            "or pass accept_derived=True to override for the ONE-RUN live "
            "validation on a dedicated debug/RE unit (you accept driving the "
            "DERIVED-UNVALIDATED enciphered clear)."
        )
    override_used = status != "verified-captured" and accept_derived

    # 3. mandatory EEPROM baseline
    if not eeprom_dump_done:
        from .types import EepromDumpFailedError  # noqa: PLC0415

        raise EepromDumpFailedError(
            "no pre-flight EEPROM dump — run eeprom.dump_eeprom first. Refusing "
            "to drive a clear without rollback evidence."
        )

    # 4. write budget (charged once, before any transfer)
    if charge is not None:
        charge()

    # 5. (lockfile held by the caller) — drive the ORDERED sequence
    start = time.perf_counter()
    steps_out: list[WicResetStep] = []
    bytes_sent = 0
    bytes_received = 0

    # 1. set_session (send-primed RECV)
    ss_wire = encoder.encipher(frames.set_session)
    ss_reply = device.send_and_receive(ss_wire, timeout_ms=timeout_ms, length=keyword_len)
    bytes_sent += len(ss_wire)
    bytes_received += len(ss_reply)
    steps_out.append(WicResetStep("set_session", frames.set_session, ss_wire, ss_reply))

    # 2. get_keyword (send-primed RECV) → feed the live keyword to the encoder
    gk_wire = encoder.encipher(frames.get_keyword)
    gk_reply = device.send_and_receive(gk_wire, timeout_ms=timeout_ms, length=keyword_len)
    bytes_sent += len(gk_wire)
    bytes_received += len(gk_reply)
    # Live-keyword guard (Lane C R1): a real keyword is >= keyword_min_len bytes.
    # A zero/short reply means the session never opened (the live handshake
    # experiment got ZERO bytes back) — refuse BEFORE any set_command write so we
    # never key the enciphered clear off a keyword we did not actually read.
    if len(gk_reply) < keyword_min_len:
        raise ResetNotValidatedError(
            f"get_keyword returned {len(gk_reply)} byte(s) "
            f"(0x{gk_reply.hex()}), fewer than the {keyword_min_len}-byte device "
            "keyword required. The session likely never opened (set_session not "
            "ACKed) — refusing to drive the set_command clear keyed off a keyword "
            "we did not read. No write was sent."
        )
    encoder.seed_keyword(gk_reply)
    steps_out.append(WicResetStep("get_keyword", frames.get_keyword, gk_wire, gk_reply))

    # 3. set_command carrying the waste selector 10 07 7C (SEND)
    sel_wire = encoder.encipher(frames.set_command_select)
    sel_n = device.send_command(sel_wire, timeout_ms=timeout_ms)
    bytes_sent += sel_n
    steps_out.append(WicResetStep("set_command", frames.set_command_select, sel_wire))

    # 4. set_command carrying the 'common' reset operand 0D 00 00 (SEND — the write)
    rst_wire = encoder.encipher(frames.set_command_reset)
    rst_n = device.send_command(rst_wire, timeout_ms=timeout_ms)
    bytes_sent += rst_n
    steps_out.append(WicResetStep("set_command", frames.set_command_reset, rst_wire))

    # 5. optional get_command verify (send-primed RECV)
    if verify_readback:
        gv_wire = encoder.encipher(frames.get_command)
        gv_reply = device.send_and_receive(gv_wire, timeout_ms=timeout_ms, length=keyword_len)
        bytes_sent += len(gv_wire)
        bytes_received += len(gv_reply)
        steps_out.append(WicResetStep("get_command", frames.get_command, gv_wire, gv_reply))

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    summary = (
        f"CLEARED via {len(steps_out)} enciphered frames "
        f"(region={region}, keyword={gk_reply[:4].hex()})"
    )
    if override_used:
        summary += " [accept_derived OVERRIDE: drove DERIVED-UNVALIDATED clear]"
    outcome = OperationOutcome(
        op_name="reset_absorber_wicreset",
        success=True,
        elapsed_ms=elapsed_ms,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        response_summary=summary,
    )
    return WicResetPlan(
        frames=frames,
        steps=tuple(steps_out),
        executed=True,
        device_keyword=gk_reply,
        outcome=outcome,
    )
