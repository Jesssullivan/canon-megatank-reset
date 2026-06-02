"""systemd entrypoint for canon-megatank.

For Phase R0/R1 (current), this is mostly a placeholder. Once protocol bytes
are captured + locked in maintenance.yaml, this hosts the small HTTP API
that the SvelteKit /maintenance route calls into.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from types import FrameType
from typing import Any

import structlog

from . import __version__
from .fingerprint import load_maintenance, locked_test_unit


def _configure_logging() -> None:
    level = os.environ.get("PRINTSTACK_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stdout)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
    )


_shutting_down = False


def _on_term(_signum: int, _frame: FrameType | None) -> None:
    global _shutting_down  # noqa: PLW0603 — signal handler legitimately needs to set the module-level flag
    _shutting_down = True


def _serve() -> int:
    """Run the long-lived service loop (the default, no-subcommand behavior)."""
    _configure_logging()
    log = structlog.get_logger(service="canon-megatank", version=__version__)

    # Verify maintenance.yaml is reachable + parseable BEFORE doing anything.
    try:
        doc = load_maintenance()
        tu = locked_test_unit()
    except Exception as exc:
        log.error("maintenance_yaml.load_failed", err=str(exc))
        return 2
    log.info(
        "service.start",
        test_unit_uuid=tu.uuid,
        locked_firmware=doc.get("protocol_fingerprint", {}).get("printer_firmware_version"),
        supported_ops=len(doc.get("supported", []) or []),
    )

    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)

    # TODO(canon-tool R1/R2): wire up an HTTP listener on a unix socket
    # (e.g. /run/canon-tool/api.sock) that the SvelteKit /maintenance
    # route can call. Operations:
    #   POST /ping              -> run the ping suite, return baseline diff
    #   POST /eeprom/dump       -> dump EEPROM + return checksum
    #   POST /op/<name>         -> guarded by fingerprint + budget + lockfile
    # Until protocol bytes are captured + locked, this loop just idles
    # so the systemd unit doesn't churn.

    log.info("service.idle", note="awaiting Phase A protocol bytes; idle loop")
    while not _shutting_down:
        signal.pause()

    log.info("service.stop")
    return 0


def cmd_read(argv: list[str]) -> int:
    """`canon-megatank read` — read the waste-ink counter over pyusb (read-only).

    Safe by construction: this only ever issues a RECV (write a 3-byte request
    header, read the reply). It does NOT write any payload and cannot reset.

    With no real hardware (or no recovered read command), it fails cleanly:
    - ``UsbAccessError`` when no claimable Canon device is on the bus, and
    - ``ReadCommandNotDerivedError`` when the absorber-counter (cmd, arg) is
      still PENDING Lane A and none is passed via --cmd/--arg.
    """
    _configure_logging()
    log = structlog.get_logger(service="canon-megatank", version=__version__, op="read")

    parser = argparse.ArgumentParser(prog="canon-megatank read")
    parser.add_argument("--product-id", type=lambda s: int(s, 0), default=0x1865)
    parser.add_argument(
        "--cmd",
        type=lambda s: int(s, 0),
        default=None,
        help="RECV command byte (PENDING Lane A; required until recovered)",
    )
    parser.add_argument(
        "--arg",
        type=lambda s: int(s, 0),
        default=None,
        help="RECV argument (u16, big-endian on the wire; PENDING Lane A)",
    )
    parser.add_argument("--timeout-ms", type=int, default=5000)
    parser.add_argument("--length", type=int, default=64)
    args = parser.parse_args(argv)

    # Imported here so the module stays importable without pyusb present.
    from .ops import read_counter  # noqa: PLC0415
    from .types import CanonToolError, PrinterFingerprint  # noqa: PLC0415
    from .usb import open_g6020  # noqa: PLC0415

    # Build the runtime fingerprint from the locked SSOT so the read goes
    # through the same UUID/firmware gate as any other op. (A production caller
    # would query IPP get-printer-attributes at runtime; that lives in the
    # future HTTP API — here we gate against the locked unit identity.)
    doc = load_maintenance()
    fp = doc["protocol_fingerprint"]
    tu = doc["test_unit"]
    runtime = PrinterFingerprint(
        uuid=tu["uuid"],
        firmware_version=fp["printer_firmware_version"],
        device_id_raw=fp.get("printer_device_id", ""),
        cmd_set=tuple(fp.get("cmd_set", ())),
    )

    try:
        with open_g6020(product_id=args.product_id) as dev:
            reading = read_counter(
                dev,
                runtime_fingerprint=runtime,
                cmd=args.cmd,
                arg=args.arg,
                timeout_ms=args.timeout_ms,
                length=args.length,
            )
    except CanonToolError as exc:
        log.error("read.failed", err_type=type(exc).__name__, err=str(exc))
        return 1

    log.info(
        "read.ok",
        cmd=reading.cmd,
        arg=reading.arg,
        bytes_received=reading.outcome.bytes_received,
        elapsed_ms=reading.outcome.elapsed_ms,
        response=reading.outcome.response_summary,
    )
    return 0


def cmd_reset(argv: list[str]) -> int:
    """`canon-megatank reset` — reset the 5B00 absorber counter. DRY-RUN by default.

    Without ``--execute`` it only prints the exact derived wire frame and exits
    (no USB write). ``--execute`` attempts the real write and passes through every
    safety gate in ``ops.reset_absorber`` + a write-budget charge + a lockfile.
    While the SSOT status is ``derived-unvalidated`` (current state — bytes are
    statically derived, not physically confirmed, pads still full) ``--execute``
    HARD-STOPS with ``ResetNotValidatedError``."""
    _configure_logging()
    log = structlog.get_logger(service="canon-megatank", version=__version__, op="reset")

    parser = argparse.ArgumentParser(prog="canon-megatank reset")
    parser.add_argument("--product-id", type=lambda s: int(s, 0), default=0x1865)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="actually write (default: dry-run print the frame only). Gated.",
    )
    parser.add_argument(
        "--checkbox",
        action="store_true",
        help="set the Service Tool checkbox bit (flags 0x01 -> 0x81)",
    )
    parser.add_argument("--timeout-ms", type=int, default=5000)
    args = parser.parse_args(argv)

    from .lockfile import charge_write, write_lock  # noqa: PLC0415
    from .ops import build_absorber_reset_spec, reset_absorber  # noqa: PLC0415
    from .protocol import derive_reset_frame  # noqa: PLC0415
    from .types import CanonToolError, PrinterFingerprint  # noqa: PLC0415

    doc = load_maintenance()
    fp = doc["protocol_fingerprint"]
    tu = doc["test_unit"]
    runtime = PrinterFingerprint(
        uuid=tu["uuid"],
        firmware_version=fp["printer_firmware_version"],
        device_id_raw=fp.get("printer_device_id", ""),
        cmd_set=tuple(fp.get("cmd_set", ())),
    )

    # Dry-run needs no hardware: show the operator the literal frame and stop.
    if not args.execute:
        frame = derive_reset_frame(build_absorber_reset_spec(checkbox=args.checkbox))
        log.info(
            "reset.dry_run",
            frame=frame.hex(),
            note="DRY-RUN — no USB write. Pass --execute to write (gated).",
            status=doc.get("supported", {}).get("absorber_reset", {}).get("status"),
        )
        return 0

    # --execute: the write budget + lockfile wrap the gated op.
    serial = tu.get("serial_sticker") or tu["uuid"]
    cap = int(doc.get("write_budget", {}).get("cap", 50))
    from .usb import open_g6020  # noqa: PLC0415

    def _charge() -> None:
        charge_write(serial, cap=cap)

    try:
        with write_lock(serial), open_g6020(product_id=args.product_id) as dev:
            plan = reset_absorber(
                dev,
                runtime_fingerprint=runtime,
                eeprom_dump_done=False,  # CLI does not yet auto-dump; gate will refuse
                execute=True,
                checkbox=args.checkbox,
                timeout_ms=args.timeout_ms,
                charge=_charge,
            )
    except CanonToolError as exc:
        log.error("reset.refused", err_type=type(exc).__name__, err=str(exc))
        return 1

    log.info("reset.ok", frame=plan.frame.hex(), executed=plan.executed)
    return 0


def cmd_replay_control(argv: list[str]) -> int:
    """`canon-megatank replay-control` — replay the captured EP0 control-transfer
    reset sequence (the WICReset service-mode transport). DRY-RUN by default.

    Without ``--execute`` it resolves the SSOT ``control_sequence`` and prints the
    exact control transfers (no USB). ``--execute`` drives them over EP0 behind
    every gate in ``ops.replay_control_sequence`` + a write-budget charge +
    lockfile. While the SSOT status is ``derived-unvalidated`` (current — the
    sequence is a placeholder) ``--execute`` HARD-STOPS with
    ``ResetNotValidatedError``; an empty ``control_sequence`` also refuses."""
    _configure_logging()
    log = structlog.get_logger(service="canon-megatank", version=__version__, op="replay-control")

    parser = argparse.ArgumentParser(prog="canon-megatank replay-control")
    parser.add_argument("--product-id", type=lambda s: int(s, 0), default=0x12FE)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="actually drive the control transfers (default: dry-run print only). Gated.",
    )
    parser.add_argument("--timeout-ms", type=int, default=5000)
    args = parser.parse_args(argv)

    from .lockfile import charge_write, write_lock  # noqa: PLC0415
    from .ops import replay_control_sequence  # noqa: PLC0415
    from .types import CanonToolError, PrinterFingerprint  # noqa: PLC0415

    doc = load_maintenance()
    fp = doc["protocol_fingerprint"]
    tu = doc["test_unit"]
    runtime = PrinterFingerprint(
        uuid=tu["uuid"],
        firmware_version=fp["printer_firmware_version"],
        device_id_raw=fp.get("printer_device_id", ""),
        cmd_set=tuple(fp.get("cmd_set", ())),
    )

    # Dry-run needs no hardware: resolve + show the steps and stop.
    if not args.execute:
        plan = replay_control_sequence(
            _NoDevice(),  # never touched on a dry-run
            runtime_fingerprint=runtime,
            eeprom_dump_done=False,
        )
        log.info(
            "replay_control.dry_run",
            steps=len(plan.steps),
            summary=plan.outcome.response_summary,
            note="DRY-RUN — no USB. Pass --execute to drive (gated).",
            status=doc.get("supported", {}).get("absorber_reset", {}).get("status"),
        )
        return 0

    serial = tu.get("serial_sticker") or tu["uuid"]
    cap = int(doc.get("write_budget", {}).get("cap", 50))
    from .usb import open_g6020  # noqa: PLC0415

    def _charge() -> None:
        charge_write(serial, cap=cap)

    try:
        with write_lock(serial), open_g6020(product_id=args.product_id, interface=None) as dev:
            plan = replay_control_sequence(
                dev,
                runtime_fingerprint=runtime,
                eeprom_dump_done=False,  # CLI does not yet auto-dump; gate will refuse
                execute=True,
                timeout_ms=args.timeout_ms,
                charge=_charge,
            )
    except CanonToolError as exc:
        log.error("replay_control.refused", err_type=type(exc).__name__, err=str(exc))
        return 1

    log.info("replay_control.ok", steps=len(plan.steps), executed=plan.executed)
    return 0


def cmd_reset_native(argv: list[str]) -> int:  # noqa: PLR0915 — gated CLI: dry-run/execute split + gate wiring
    """`canon-megatank reset-native` — the VALIDATED native libusb 5B00 clear.

    This drives the hardware-validated WICReset-derived enciphered session
    (set_session → get_keyword → set_command[10 07 7C] → set_command[0D 00 00] →
    get_command verify) over the native usbprint-derived EP0 VENDOR control
    transport (:class:`protocol.servicemode_transport.ServiceModeTransport`):
    each ``set_command`` is the corrected 23-byte ``85 00 00 || payload(20)`` frame
    pushed VERBATIM as a VENDOR_SET control-OUT (``0x41 / bRequest=0x85 /
    wValue=0``). This is the path that cleared 5B00 on real hardware 2026-06-01 —
    no WICReset, no VM, no cloud, no key.

    DRY-RUN by default: resolves + enciphers the frames and prints the literal
    wire bytes (no USB). ``--execute`` drives the real sequence behind EVERY gate
    in ``ops.reset_absorber_wicreset`` (UUID isolation, validation status / the
    ``--accept-derived`` one-run override, mandatory EEPROM dump, write budget) +
    a write-budget charge + a lockfile.

    The get_command (0x86) RECV is EMPTY by design and is NOT gated on. After the
    writes, the op + this command print the MANDATORY commit step: release the USB
    handle, then do a CLEAN POWER-BUTTON shutdown so the printhead parks and the
    cleared counter is flushed (an abrupt unplug does NOT commit)."""
    _configure_logging()
    log = structlog.get_logger(service="canon-megatank", version=__version__, op="reset-native")

    parser = argparse.ArgumentParser(prog="canon-megatank reset-native")
    parser.add_argument(
        "--product-id",
        type=lambda s: int(s, 0),
        default=0x12FE,
        help="service-mode product id (G6020 enumerates here; 0x1865 = normal)",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="actually drive the native clear (default: dry-run print only). Gated.",
    )
    parser.add_argument(
        "--accept-derived",
        action="store_true",
        help=(
            "one-run override of the validation-status gate for the dedicated "
            "debug/RE unit (UUID/EEPROM/budget/lockfile STILL enforced). Use only "
            "when driving the DERIVED-UNVALIDATED clear on the broken-5B00 unit."
        ),
    )
    parser.add_argument("--region", default="common", help="waste row (G6000 clears only 'common')")
    parser.add_argument(
        "--no-verify-readback",
        action="store_true",
        help="skip the trailing get_command(0x86) RECV (it is empty by design)",
    )
    parser.add_argument("--timeout-ms", type=int, default=5000)
    args = parser.parse_args(argv)

    from .ops import COMMIT_INSTRUCTION, reset_absorber_wicreset  # noqa: PLC0415
    from .types import CanonToolError, PrinterFingerprint  # noqa: PLC0415

    doc = load_maintenance()
    fp = doc["protocol_fingerprint"]
    tu = doc["test_unit"]
    runtime = PrinterFingerprint(
        uuid=tu["uuid"],
        firmware_version=fp["printer_firmware_version"],
        device_id_raw=fp.get("printer_device_id", ""),
        cmd_set=tuple(fp.get("cmd_set", ())),
    )

    # Dry-run needs no hardware: encipher + preview the validated frames, stop.
    if not args.execute:
        plan = reset_absorber_wicreset(
            _NoDevice(),  # never touched on a dry-run
            runtime_fingerprint=runtime,
            eeprom_dump_done=False,
            region=args.region,
            verify_readback=not args.no_verify_readback,
        )
        log.info(
            "reset_native.dry_run",
            steps=len(plan.steps),
            wire=[s.wire.hex() for s in plan.steps],
            summary=plan.outcome.response_summary,
            note="DRY-RUN — no USB. Pass --execute to drive the validated clear (gated).",
            status=doc.get("supported", {}).get("absorber_reset", {}).get("status"),
            commit_step=COMMIT_INSTRUCTION,
        )
        return 0

    serial = tu.get("serial_sticker") or tu["uuid"]
    cap = int(doc.get("write_budget", {}).get("cap", 50))
    from .lockfile import charge_write, write_lock  # noqa: PLC0415
    from .protocol.servicemode_transport import ServiceModeTransport  # noqa: PLC0415
    from .usb import open_g6020  # noqa: PLC0415

    def _charge() -> None:
        charge_write(serial, cap=cap)

    try:
        # Service mode enumerates as 0x12fe on iface 0 / alt 0 (wIndex 0x0000); the
        # native transport drives EP0 control transfers, so no bulk interface claim
        # is needed (interface=None) — ServiceModeTransport wraps cd.control_transfer.
        with (
            write_lock(serial),
            open_g6020(product_id=args.product_id, interface=None) as dev,
        ):
            transport = ServiceModeTransport(dev.control_transfer)
            plan = reset_absorber_wicreset(
                transport,
                runtime_fingerprint=runtime,
                eeprom_dump_done=False,  # CLI does not yet auto-dump; gate will refuse
                execute=True,
                accept_derived=args.accept_derived,
                region=args.region,
                verify_readback=not args.no_verify_readback,
                # The live VENDOR_GET keyword read is 3 bytes; the functor-2 SEED is
                # 4 bytes, so accept a 3-byte live read and 0x00-pad it to 4.
                keyword_min_len=3,
                keyword_pad_to=4,
                timeout_ms=args.timeout_ms,
                charge=_charge,
            )
    except CanonToolError as exc:
        log.error("reset_native.refused", err_type=type(exc).__name__, err=str(exc))
        return 1

    # The CLEAN POWER-BUTTON COMMIT is mandatory and is NOT done by the writes /
    # the empty 0x86 readback. Surface it loudly so the operator always sees it.
    log.info(
        "reset_native.ok",
        steps=len(plan.steps),
        executed=plan.executed,
        keyword=plan.device_keyword.hex(),
        summary=plan.outcome.response_summary,
        commit_step=COMMIT_INSTRUCTION,
    )
    return 0


class _NoDevice:
    """A device stand-in for the dry-run paths, which never transfer."""

    def control_transfer(self, *_a: object, **_k: object) -> bytes:  # pragma: no cover
        raise RuntimeError("dry-run must not touch the device")

    # Satisfies WicSessionDevice for the reset-native dry-run (never reached).
    def read_response(self, *_a: object, **_k: object) -> bytes:  # pragma: no cover
        raise RuntimeError("dry-run must not touch the device")

    def send_and_receive(self, *_a: object, **_k: object) -> bytes:  # pragma: no cover
        raise RuntimeError("dry-run must not touch the device")

    def send_command(self, *_a: object, **_k: object) -> int:  # pragma: no cover
        raise RuntimeError("dry-run must not touch the device")


def run(argv: list[str] | None = None) -> int:
    """Console-script entrypoint. Dispatches subcommands; no args = service loop."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "read":
        return cmd_read(args[1:])
    if args and args[0] == "reset":
        return cmd_reset(args[1:])
    if args and args[0] == "replay-control":
        return cmd_replay_control(args[1:])
    if args and args[0] == "reset-native":
        return cmd_reset_native(args[1:])
    return _serve()


def main() -> Any:  # pragma: no cover
    """Convenience for `python -m canon_megatank`."""
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
