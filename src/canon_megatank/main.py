"""systemd entrypoint for printstack-canon.

For Phase R0/R1 (current), this is mostly a placeholder. Once protocol bytes
are captured + locked in maintenance.yaml, this hosts the small HTTP API
that the SvelteKit /maintenance route calls into.
"""

from __future__ import annotations

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
    global _shutting_down
    _shutting_down = True


def run() -> int:
    """Service entrypoint (referenced from pyproject.toml console_scripts)."""
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


def main() -> Any:  # pragma: no cover
    """Convenience for `python -m printstack_canon`."""
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
