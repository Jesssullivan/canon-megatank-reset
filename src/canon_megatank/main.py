"""systemd entrypoint for printstack-canon.

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
    log = structlog.get_logger(service="printstack-canon", version=__version__)

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
    log = structlog.get_logger(service="printstack-canon", version=__version__, op="read")

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
    from .ops import read_counter
    from .types import CanonToolError, PrinterFingerprint
    from .usb import open_g6020

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


def run(argv: list[str] | None = None) -> int:
    """Console-script entrypoint. Dispatches subcommands; no args = service loop."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "read":
        return cmd_read(args[1:])
    return _serve()


def main() -> Any:  # pragma: no cover
    """Convenience for `python -m canon_megatank`."""
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
