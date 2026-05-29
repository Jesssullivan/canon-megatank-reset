"""Load the canon-g6020 maintenance SSOT (printers/canon-g6020/maintenance.yaml)
and verify the runtime printer's fingerprint against the locked values.

This is the FIRST gate before any maintenance op. A mismatch means either:
- The connected printer isn't the named test unit (uuid drift), OR
- The printer firmware was updated since we locked the fingerprint, OR
- The protocol response shape changed (cmd_set drift)

Any of those invalidates the captured byte sequences. The caller MUST refuse
to proceed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

from ruamel.yaml import YAML

from .types import (
    FingerprintMismatchError,
    PrinterFingerprint,
    TestUnit,
    UnknownPrinterError,
    WriteBudget,
)

yaml = YAML(typ="safe")


def find_maintenance_yaml(printer_id: str = "canon-g6020") -> Path:
    """Resolve the path to printers/<id>/maintenance.yaml.

    Honors PRINTSTACK_PRINTERS_DIR (set by the systemd unit) before falling
    back to a repo-relative search."""
    if env_dir := os.environ.get("PRINTSTACK_PRINTERS_DIR"):
        p = Path(env_dir) / printer_id / "maintenance.yaml"
        if p.is_file():
            return p

    # Walk up from this file until we find a sibling `printers/` dir.
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "printers" / printer_id / "maintenance.yaml"
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(
        f"could not locate printers/{printer_id}/maintenance.yaml; "
        "set PRINTSTACK_PRINTERS_DIR to its parent directory"
    )


def load_maintenance(printer_id: str = "canon-g6020") -> dict[str, Any]:
    """Load + return the maintenance.yaml document for a printer."""
    path = find_maintenance_yaml(printer_id)
    with path.open("r", encoding="utf-8") as f:
        return cast("dict[str, Any]", yaml.load(f))


def locked_test_unit(printer_id: str = "canon-g6020") -> TestUnit:
    """Return the locked TestUnit from maintenance.yaml."""
    doc = load_maintenance(printer_id)
    tu = doc["test_unit"]
    return TestUnit(
        uuid=tu["uuid"],
        mac_suffix=tu.get("mac_suffix", ""),
        serial_sticker=tu.get("serial_sticker"),
        attached_to_host=tu.get("attached_to_host", ""),
        initial_state=tu.get("initial_state", ""),
        acquired=tu.get("acquired", ""),
    )


def locked_write_budget(printer_id: str = "canon-g6020") -> WriteBudget:
    """Return the locked WriteBudget from maintenance.yaml."""
    doc = load_maintenance(printer_id)
    wb = doc.get("write_budget", {})
    return WriteBudget(
        cap=int(wb.get("cap", 50)),
        consumed=int(wb.get("consumed", 0)),
        refill_policy=wb.get("refill_policy", "manual"),
    )


def verify_fingerprint_matches(
    runtime: PrinterFingerprint,
    printer_id: str = "canon-g6020",
) -> None:
    """Assert that the runtime printer's fingerprint matches the locked
    values. Raises FingerprintMismatchError or UnknownPrinterError on
    any drift.

    This is the gate every maintenance op MUST pass through before touching
    USB. No exceptions, no override flags in code.
    """
    doc = load_maintenance(printer_id)

    test_unit = doc["test_unit"]
    if runtime.uuid != test_unit["uuid"]:
        raise UnknownPrinterError(
            f"runtime printer uuid {runtime.uuid!r} is not the named "
            f"test_unit {test_unit['uuid']!r}; refusing to proceed"
        )

    fp = doc["protocol_fingerprint"]
    if runtime.firmware_version != fp["printer_firmware_version"]:
        raise FingerprintMismatchError(
            f"firmware drift: runtime={runtime.firmware_version!r} "
            f"locked={fp['printer_firmware_version']!r}; captured byte "
            "sequences may be invalid"
        )

    locked_cmd_set = tuple(fp.get("cmd_set", ()))
    if runtime.cmd_set != locked_cmd_set:
        raise FingerprintMismatchError(
            f"cmd_set drift: runtime={runtime.cmd_set!r} "
            f"locked={locked_cmd_set!r}"
        )

    # device_id_raw is informational, not enforced — it includes a
    # status code (STA:) that legitimately changes between captures.
