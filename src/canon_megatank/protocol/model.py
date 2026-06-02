"""Executable reference model of the Canon MegaTank **normal-mode** maintenance
transport and frame grammar (the early T3 model).

This is the **formal, offline, CI-checkable** model derived from two independent
reverse-engineering oracles, so the property tests in
``tests/test_protocol_model.py`` can assert the protocol invariants WITHOUT
hardware and WITHOUT spending the single-use WICReset key.

> **Status — legacy normal-mode model.** The G6020 5B00 reset was since recovered
> and **hardware-validated over a different path**: the **service-mode**
> (``04a9:12fe``) vendor **control-transfer** transport with a keyed, functor-3
> enciphered session (see ``protocol/wicreset.py``,
> ``protocol/servicemode_transport.py``, and
> ``docs/research/canon-service-mode-field-guide.md``). The plaintext
> ``[00, 03, flags, 03, idx]`` **absorber-payload derivation modelled below was
> FALSIFIED on hardware** — it ACKs but does **not** clear 5B00. That derivation
> (``absorber_reset_payload`` / ``AbsorberResetSpec`` / ``derive_reset_frame``)
> is retained ONLY as the legacy normal-mode grammar artifact and is firewalled
> from real writes by the ``verified-captured`` gate in ``ops.py`` (it can only
> ever produce a dry-run frame). Do not treat it as the reset of record.
>
> Everything else here remains **valid and corroborated**: the generic wire
> grammar (round-trip, determinism, big-endian arg, length / range guards), the
> idempotency + counter-block model, the write-budget and UUID safety gates, and
> the no-SSOT-drift checks. The validated path reuses this same grammar
> (``85 00 00 || payload``).

Sources (see ``docs/spec/megatank-maintenance-protocol.md`` for the full
derivation history, and the cited research notes):

* **Canon Service Tool** — IOCTL primitive ``FUN_004302c0``::

      SEND  0x220038: [cmd][arg_hi][arg_lo][payload]   buffer len = 3 + len(payload)
      RECV  0x22003c: [cmd][arg_hi][arg_lo]            3-byte header, response read back

  ``arg`` is **big-endian** in the header.

* **WICReset** — ``service.sendcmd`` / ``service.readcmd``: the *same* usbscan
  transport (``0x220038`` / ``0x22003c`` over a ``CreateFileW`` handle) under a
  template (``$INDEX`` / ``$VALUE``) builder. Two-tool corroboration of the
  transport is what lets us trust this model before T4.

* **Group-7 absorber payload** ``[00, 03, flags, 03, idx]``
  (``printers/canon-g6020/maintenance.yaml::supported.absorber_reset``).

KNOWN vs FALSIFIED (honesty boundary the model enforces):

* **KNOWN / still valid** (two-tool corroborated, independent of which transport
  actually clears 5B00): the normal-mode transport, IOCTL codes, frame grammar,
  endpoint binding, and the absorber payload *shape*. These are asserted by the
  property tests and remain true.
* **FALSIFIED** (by T4-era hardware testing): the claim that the plaintext
  ``[00, 03, flags, 03, idx]`` SEND frame *clears 5B00*. On hardware it ACKs but
  does not clear. The real clear is the service-mode control-transfer + functor-3
  cipher path. The model still **builds** that legacy payload deterministically —
  the tests assert only its shape / determinism / invertibility, never the
  (false) behavioral claim — and the runtime gate keeps it dry-run only.
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
# idx byte below). See docs/research/canon-service-mode-field-guide.md.
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


# ─── Absorber reset payload + derivation (LEGACY normal-mode; FALSIFIED) ───────
#
# The plaintext SEND frame built here was FALSIFIED on hardware: it ACKs but does
# NOT clear 5B00. The validated reset is the service-mode control-transfer +
# functor-3 cipher path (see protocol/wicreset.py). These builders are retained
# only as the legacy normal-mode grammar artifact; the property tests assert their
# byte shape / determinism / invertibility (all still true), never any clearing
# behavior, and the ops.py ``verified-captured`` gate keeps them dry-run only.


def absorber_reset_payload(flags: int, idx: int) -> bytes:
    """Build the legacy group-7 absorber payload ``[00, 03, flags, 03, idx]``.

    ``flags`` ∈ :data:`ABSORBER_FLAGS`; ``idx`` is the absorber selector (u8).
    The byte *shape* is two-tool corroborated; the claim that this plaintext frame
    clears 5B00 was **FALSIFIED** on hardware (it ACKs but does not clear — the
    real clear is the service-mode functor-cipher path). Kept for the grammar
    invariants only.
    """
    if flags not in ABSORBER_FLAGS:
        raise ProtocolError(f"flags must be one of {ABSORBER_FLAGS!r}, got {flags!r}")
    _u8("idx", idx)
    return bytes([0x00, 0x03, flags, 0x03, idx])


@dataclass(frozen=True, slots=True)
class AbsorberResetSpec:
    """Fully-specified **legacy normal-mode** absorber-reset operation. Pure
    description of *one* SEND frame. NOTE: the plaintext frame this describes was
    FALSIFIED on hardware (ACKs but does not clear 5B00); it survives only as the
    legacy grammar artifact and is gated dry-run-only in ``ops.py``.

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
    """The legacy normal-mode **frame-derivation function**: ``spec -> exact SEND
    wire bytes``.

    Pure and total over a valid :class:`AbsorberResetSpec`; determinism +
    invertibility are asserted by the property tests. The resulting plaintext
    frame does **not** clear 5B00 on hardware (FALSIFIED — ACKs only); the
    validated reset uses the service-mode functor-cipher path. This builder is
    still imported by ``ops.py`` / ``main.py`` but is firewalled to dry-run output
    by the ``verified-captured`` gate.
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
