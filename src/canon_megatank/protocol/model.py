"""Executable reference model of the Canon MegaTank maintenance protocol (T3).

This is the **formal, offline, CI-checkable** model derived from two independent
reverse-engineering oracles, so the property tests in
``tests/test_protocol_model.py`` can assert the protocol invariants WITHOUT
hardware and WITHOUT spending the single-use WICReset key.

Sources (see ``docs/spec/megatank-maintenance-protocol.md`` for the full
derivation, and the cited research notes):

* **Canon Service Tool** — IOCTL primitive ``FUN_004302c0``
  (``docs/research/canon-tool-ghidra-notes.md``)::

      SEND  0x220038: [cmd][arg_hi][arg_lo][payload]   buffer len = 3 + len(payload)
      RECV  0x22003c: [cmd][arg_hi][arg_lo]            3-byte header, response read back

  ``arg`` is **big-endian** in the header.

* **WICReset** — ``service.sendcmd`` / ``service.readcmd``
  (``docs/research/wicreset-static-re.md``): the *same* usbscan transport
  (``0x220038`` / ``0x22003c`` over a ``CreateFileW`` handle) under a
  template (``$INDEX`` / ``$VALUE``) builder. Two-tool corroboration of the
  transport is what lets us trust this model before T4.

* **Group-7 absorber payload** ``[00, 03, flags, 03, idx]``
  (``printers/canon-g6020/maintenance.yaml::supported.absorber_reset``).

KNOWN vs PENDING (honesty boundary the model enforces):

* **KNOWN** (two-tool corroborated): transport, IOCTL codes, frame grammar,
  endpoint binding, the absorber payload *shape*.
* **PENDING** (resolved by T4 ground-truth capture, AFTER the waste-ink pads are
  installed): the literal ``flags`` / ``idx`` for the G6020 absorber reset. The
  model **parameterizes** these and asserts structure only; T4 fills the concrete
  values and the captured wire bytes MUST equal ``derive_reset_frame(...)``.
"""

from __future__ import annotations

from dataclasses import dataclass

from canon_megatank.types import CanonToolError

# ─── Transport constants (two-tool corroborated; mirror maintenance.yaml) ─────
#
# These MUST stay in lockstep with
# ``printers/canon-g6020/maintenance.yaml::command_protocol``. The
# ``test_model_matches_ssot`` property test fails on any drift.

IOCTL_SEND = 0x220038
"""usbscan SEND IOCTL: host -> printer, header + payload, out-buffer NULL."""

IOCTL_RECV = 0x22003C
"""usbscan RECV IOCTL: printer -> host, 3-byte header out, response read back."""

HEADER_LEN = 3
"""Every maintenance frame is prefixed by ``[cmd][arg_hi][arg_lo]``."""

MAINT_INTERFACE = 4
"""Vendor-specific maintenance interface (class 0xff) on the G6020."""

BULK_OUT_EP = 0x03
"""Bulk OUT endpoint on interface 4 — the Linux equivalent of IOCTL_SEND."""

BULK_IN_EP = 0x86
"""Bulk IN endpoint on interface 4 — the Linux equivalent of IOCTL_RECV."""

# Absorber "Set" flags byte recovered from the Service Tool dialog handler
# (FUN_0040b6c0): base 0x01, OR 0x80 when the dialog checkbox is set → 0x01/0x81.
# This is the checkbox bit, independent of which absorber is selected (that is the
# idx byte below). See docs/research/servicetool-v5103-static-re.md.
ABSORBER_FLAGS = (0x01, 0x81)

# Absorber index values, label-confirmed from the Service Tool's DAT_0048295c
# table (sel → idx → name). The 5B00 MAIN ink absorber is idx 0x07 ("Main").
ABSORBER_IDX = {
    "platen": 0x00,
    "main_black": 0x01,
    "main_color": 0x03,
    "main_and_platen": 0x06,
    "main": 0x07,
}
ABSORBER_MAIN_IDX = 0x07
"""The 5B00 main ink absorber selector — the reset target (idx, not flags)."""

U8_MAX = 0xFF
U16_MAX = 0xFFFF


class ProtocolError(CanonToolError):
    """A frame / payload violated the modelled grammar (out-of-range field,
    truncated frame, illegal flag). Raised by the reference model only; it is a
    *modelling* error, distinct from a runtime USB failure."""


def _u8(name: str, value: int) -> int:
    if not 0 <= value <= U8_MAX:
        raise ProtocolError(f"{name} must be a u8 (0..255), got {value!r}")
    return value


def _u16(name: str, value: int) -> int:
    if not 0 <= value <= U16_MAX:
        raise ProtocolError(f"{name} must be a u16 (0..65535), got {value!r}")
    return value


# ─── Wire grammar ─────────────────────────────────────────────────────────────


def encode_send(cmd: int, arg: int, payload: bytes) -> bytes:
    """Encode a SEND frame: ``[cmd:u8][arg_hi:u8][arg_lo:u8][payload...]``.

    ``arg`` is serialized **big-endian** (Service Tool ``FUN_004302c0``:
    ``hdr[1] = arg >> 8``, ``hdr[2] = arg & 0xff``). This is the exact byte
    string a pyusb tool writes to ``BULK_OUT_EP`` on ``MAINT_INTERFACE``.
    """
    _u8("cmd", cmd)
    _u16("arg", arg)
    return bytes([cmd, (arg >> 8) & 0xFF, arg & 0xFF]) + payload


def encode_recv_header(cmd: int, arg: int) -> bytes:
    """Encode the 3-byte RECV request header ``[cmd][arg_hi][arg_lo]``.

    For a read, the Service Tool writes this header (no payload) and reads the
    response back; on Linux the header goes to ``BULK_OUT_EP`` then the reply is
    read from ``BULK_IN_EP``.
    """
    _u8("cmd", cmd)
    _u16("arg", arg)
    return bytes([cmd, (arg >> 8) & 0xFF, arg & 0xFF])


def decode_frame(frame: bytes) -> tuple[int, int, bytes]:
    """Inverse of :func:`encode_send`: ``frame -> (cmd, arg, payload)``.

    Raises :class:`ProtocolError` if the frame is shorter than the 3-byte header.
    """
    if len(frame) < HEADER_LEN:
        raise ProtocolError(f"frame too short: need >= {HEADER_LEN} bytes, got {len(frame)}")
    cmd = frame[0]
    arg = (frame[1] << 8) | frame[2]
    return cmd, arg, bytes(frame[HEADER_LEN:])


# ─── Absorber reset payload + derivation ──────────────────────────────────────


def absorber_reset_payload(flags: int, idx: int) -> bytes:
    """Build the group-7 absorber payload ``[00, 03, flags, 03, idx]``.

    ``flags`` ∈ :data:`ABSORBER_FLAGS`; ``idx`` is the absorber selector (u8).
    Shape is two-tool corroborated; the concrete ``flags`` / ``idx`` for the
    G6020 are PENDING T4 ground-truth.
    """
    if flags not in ABSORBER_FLAGS:
        raise ProtocolError(f"flags must be one of {ABSORBER_FLAGS!r}, got {flags!r}")
    _u8("idx", idx)
    return bytes([0x00, 0x03, flags, 0x03, idx])


@dataclass(frozen=True, slots=True)
class AbsorberResetSpec:
    """Fully-specified absorber-reset operation. Pure description of *one* SEND
    frame; the literal ``flags`` / ``idx`` are filled from T4 ground-truth before
    any native write is enabled.

    ``cmd`` / ``arg`` are the maintenance command/argument carried in the 3-byte
    header (the operation identity also rides in the transformed payload — see
    ``maintenance.yaml::command_protocol.wire_frame.note``).
    """

    cmd: int
    arg: int
    flags: int
    idx: int

    def __post_init__(self) -> None:
        _u8("cmd", self.cmd)
        _u16("arg", self.arg)
        if self.flags not in ABSORBER_FLAGS:
            raise ProtocolError(f"flags must be one of {ABSORBER_FLAGS!r}, got {self.flags!r}")
        _u8("idx", self.idx)


def derive_reset_frame(spec: AbsorberResetSpec) -> bytes:
    """The **reset-derivation function**: ``spec -> exact SEND wire bytes``.

    Pure and total over a valid :class:`AbsorberResetSpec`. This is the single
    artifact T4 validates: the captured reset bytes MUST equal
    ``derive_reset_frame(spec)`` for the recovered ``spec``. Determinism +
    invertibility are asserted by the property tests.
    """
    return encode_send(spec.cmd, spec.arg, absorber_reset_payload(spec.flags, spec.idx))


# ─── Device-state model (idempotency) ─────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CounterState:
    """Minimal model of the absorber counter: a saturating percentage 0..100.

    5B00 fires at ``>= threshold`` (100 by default). The reset op drives the
    counter to 0 regardless of its prior value — the basis for idempotency.
    """

    value: int
    threshold: int = 100

    def __post_init__(self) -> None:
        if not 0 <= self.value <= self.threshold:
            raise ProtocolError(f"counter value {self.value} out of range 0..{self.threshold}")

    @property
    def is_blocked(self) -> bool:
        """True when the 5B00 absorber-full error would be raised."""
        return self.value >= self.threshold


def apply_reset(state: CounterState) -> CounterState:
    """Model the device-side effect of an absorber reset: counter -> 0.

    Idempotent: ``apply_reset(apply_reset(s)) == apply_reset(s)``. The wire frame
    is independent of the current counter value, so re-issuing it is safe.
    """
    return CounterState(value=0, threshold=state.threshold)


# ─── Safety gate predicate ────────────────────────────────────────────────────


def uuid_permits_write(runtime_uuid: str, locked_uuid: str) -> bool:
    """Write-gate predicate: a write op is permitted ONLY against the locked
    ``test_unit`` UUID. Any other (or empty) UUID is refused.

    Exact, case-insensitive match on a non-empty UUID. This mirrors the
    ``UnknownPrinterError`` gate the native tool enforces at runtime.
    """
    if not runtime_uuid or not locked_uuid:
        return False
    return runtime_uuid.strip().lower() == locked_uuid.strip().lower()
