"""Typed exceptions + dataclasses for canon-megatank."""

from __future__ import annotations

from dataclasses import dataclass

# ─── Exceptions (hierarchical, so callers can catch families) ────────────────


class CanonToolError(Exception):
    """Base class for all canon-megatank errors."""


class FingerprintMismatchError(CanonToolError):
    """Runtime printer fingerprint doesn't match the locked
    `protocol_fingerprint` in `maintenance.yaml`.

    This is a HARD failure — the captured byte sequences may no longer be
    valid. The caller MUST NOT proceed with any write op.
    """


class UnknownPrinterError(CanonToolError):
    """The connected printer's UUID isn't in the allowlist (not the named
    `test_unit`). Refused as a safety measure."""


class PingSuiteFailedError(CanonToolError):
    """At least one of the documented-safe pre-flight ops returned a
    response that doesn't match the locked baseline. State drift detected;
    no further ops on this unit until investigation."""


class WriteBudgetExhaustedError(CanonToolError):
    """The test unit has hit its EEPROM write-cycle cap (default 50).
    Requires manual review + a new test unit to continue."""


class LockfileBusyError(CanonToolError):
    """Another op is in flight (or crashed mid-op without cleanup).
    Manual lockfile inspection required."""


class EepromDumpFailedError(CanonToolError):
    """Pre-flight EEPROM dump didn't complete or checksum doesn't validate.
    No write op may proceed."""


class UsbAccessError(CanonToolError):
    """Could not open the bulk endpoint. Usually means CUPS / ipp-usb has
    the device claimed, or the udev rule + group membership isn't set up."""


class ResetNotValidatedError(CanonToolError):
    """An EEPROM-write reset was requested for execution, but the reset byte
    sequence is still `derived-unvalidated` in maintenance.yaml (recovered by
    static RE, not yet confirmed by a physical reset on the real unit).

    This is the hard gate that keeps `--execute` from writing
    statically-derived bytes to a printer before ground-truth. It clears only
    when `supported.absorber_reset.status` is promoted to `verified-captured`
    (after the physical-validation run, which itself is gated on the waste-ink
    pads being installed)."""


# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PrinterFingerprint:
    """Snapshot of a printer's identity + protocol surface, used for
    fingerprint matching against the locked `maintenance.yaml`."""

    uuid: str
    firmware_version: str
    device_id_raw: str
    cmd_set: tuple[str, ...]

    @classmethod
    def from_ipp_attributes(cls, attrs: dict[str, str]) -> PrinterFingerprint:
        """Build from a dict of IPP get-printer-attributes responses
        (e.g. parsed `ipptool -tv ... get-printer-attributes.test`)."""
        device_id = attrs.get("printer-device-id", "")
        # Parse CMD: substring from the device-id field.
        cmd_set: tuple[str, ...] = ()
        for part in device_id.split(";"):
            if part.startswith("CMD:"):
                cmd_set = tuple(part[4:].split(","))
                break
        return cls(
            uuid=attrs.get("printer-uuid", ""),
            firmware_version=attrs.get("printer-firmware-version", ""),
            device_id_raw=device_id,
            cmd_set=cmd_set,
        )


@dataclass(frozen=True, slots=True)
class TestUnit:
    """The named test unit pinned in `maintenance.yaml`. The only printer
    that may receive an EEPROM write until protocol is locked."""

    uuid: str
    mac_suffix: str
    serial_sticker: str | None
    attached_to_host: str
    initial_state: str
    acquired: str


@dataclass(frozen=True, slots=True)
class OperationOutcome:
    """Result of a maintenance op. `elapsed_ms`, `bytes_sent`, `bytes_received`
    are used by the prom-client gauges + structlog fields."""

    op_name: str
    success: bool
    elapsed_ms: int
    bytes_sent: int
    bytes_received: int
    response_summary: str = ""
    error: str | None = None


@dataclass(slots=True)
class WriteBudget:
    """Per-test-unit write-cycle budget. Persisted via
    `/var/lib/canon-tool/<serial>.writes`."""

    cap: int
    consumed: int
    refill_policy: str = "manual"

    @property
    def remaining(self) -> int:
        return self.cap - self.consumed

    @property
    def exhausted(self) -> bool:
        return self.consumed >= self.cap
