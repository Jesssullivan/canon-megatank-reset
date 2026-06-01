#!/usr/bin/env python3
"""Extract + annotate USB control/bulk transfers from a usbmon pcapng.

Lane C analysis pipeline, step 1. Given a Linux ``usbmon`` capture of a real
WICReset (or Service Tool) absorber-reset session, pull EVERY control transfer
to/from the G6020-in-service-mode device and print a clean, ordered, annotated
sequence — plus any bulk frames. This is the turnkey extractor that runs the
moment a real working reset is captured.

The G6020 enumerates as **04a9:1865** in normal mode and **04a9:12fe**
("Printer in service mode") once service mode is entered. WICReset talks to it
over EP0 CONTROL transfers; the reset itself is a single vendor control-OUT::

    bmRequestType=0x40  bRequest=0x85  wValue=0x0000  wIndex=0x0000
    data=[00 03 01 03 07]

This script does NOT touch hardware. It is a thin, dependency-free wrapper around
``tshark`` (Wireshark's USB dissectors are the gold standard). Default device
filter is the service-mode pid 0x12fe; override with ``--product-id`` or
``--device-address`` for captures where the address is more convenient.

Field mapping (verified against tshark 4.4.2 on mbp-13 usbmon captures):

    usb.bmRequestType    -> bmRequestType   (direction|type|recipient byte)
    usb.setup.bRequest   -> bRequest        (decimal; we print hex too)
    usb.setup.wValue     -> wValue
    usb.setup.wIndex     -> wIndex
    usb.setup.wLength    -> wLength (host-requested length)
    usb.data_fragment    -> OUT control data + undissected response payloads
                            (the reset bytes 0003010307 land here)
    usb.capdata          -> bulk payloads
    usbprinter.device_id -> dissected IEEE-1284 device-id text (class GET_DEVICE_ID)
    usb.urb_status       -> URB completion status (0 = success, -32 EPIPE/STALL, ...)
    usb.urb_type         -> 'S' submit / 'C' complete

Usage::

    # on the capture host (tshark required):
    python3 scripts/parse-wicreset-capture.py captures/ctrl-reset-XXXX.pcapng
    python3 scripts/parse-wicreset-capture.py cap.pcapng --product-id 0x12fe
    python3 scripts/parse-wicreset-capture.py cap.pcapng --json    # machine-readable
    python3 scripts/parse-wicreset-capture.py cap.pcapng --replay-snippet
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from shutil import which

# Service-mode product id the G6020 presents on EP0 once service mode is entered.
SERVICE_MODE_PID = 0x12FE
NORMAL_MODE_PID = 0x1865

# usb.transfer_type values (tshark prints these as 0x.. hex strings).
TT_CONTROL = 0x02
TT_BULK = 0x03

# Maintenance bulk endpoints (interface 4) on the G6020.
MAINT_BULK_OUT_EP = 0x03
MAINT_BULK_IN_EP = 0x86

# How much of a payload to show inline before truncating with an ellipsis.
HEX_PREVIEW_CHARS = 48
TEXT_PREVIEW_CHARS = 44

# Nibble width of a u16 setup field (wValue/wIndex) when rendered as 0x....
U16_FIELD_WIDTH = 4


def _truncate(hex_str: str, limit: int = HEX_PREVIEW_CHARS) -> str:
    return hex_str[:limit] + ("…" if len(hex_str) > limit else "")

# The reset we expect to find (for annotation, not assertion).
KNOWN_RESET = {
    "bmRequestType": 0x40,
    "bRequest": 0x85,
    "wValue": 0x0000,
    "wIndex": 0x0000,
    "data_hex": "0003010307",
}


@dataclass
class ControlTransfer:
    """One USB control transfer (SETUP + its COMPLETE), coalesced."""

    frame: int
    ts: float
    bmRequestType: int | None
    bRequest: int | None
    wValue: int | None
    wIndex: int | None
    wLength: int | None
    direction: str  # 'OUT' (host->dev) | 'IN' (dev->host)
    req_type: str  # 'standard' | 'class' | 'vendor' | 'reserved'
    recipient: str  # 'device' | 'interface' | 'endpoint' | 'other'
    setup_data_hex: str  # data sent in an OUT control transfer
    response_hex: str  # data returned in an IN control transfer (raw or dissected)
    response_text: str  # human text for dissected responses (1284 device id, etc.)
    urb_status: int | None
    note: str = ""


@dataclass
class BulkFrame:
    """One bulk transfer with payload."""

    frame: int
    ts: float
    endpoint: int
    direction: str
    data_hex: str
    urb_status: int | None
    note: str = ""


@dataclass
class ParseResult:
    pcap: str
    device_filter: str
    control: list[ControlTransfer] = field(default_factory=list)
    bulk: list[BulkFrame] = field(default_factory=list)


class TsharkUnavailable(RuntimeError):
    pass


def _tshark() -> str:
    path = which("tshark")
    if path is None:
        raise TsharkUnavailable(
            "tshark not on PATH. Install wireshark-cli (Rocky/RHEL), "
            "`brew install wireshark` (macOS), or `apt install tshark`. On the "
            "lab box mbp-13 it ships via the canon_tool_dev ansible role."
        )
    return path


def _decode_bmrequesttype(bm: int | None) -> tuple[str, str, str]:
    """(direction, type, recipient) from the bmRequestType byte."""
    if bm is None:
        return ("?", "?", "?")
    direction = "IN" if (bm & 0x80) else "OUT"
    type_map = {0x00: "standard", 0x20: "class", 0x40: "vendor", 0x60: "reserved"}
    req_type = type_map.get(bm & 0x60, "?")
    recip_map = {0x00: "device", 0x01: "interface", 0x02: "endpoint", 0x03: "other"}
    recipient = recip_map.get(bm & 0x1F, "other")
    return (direction, req_type, recipient)


def _int(val: str | None) -> int | None:
    if not val:
        return None
    try:
        return int(val, 0)
    except ValueError:
        try:
            return int(val)
        except ValueError:
            return None


def _build_filter(product_id: int | None, device_address: int | None) -> str:
    clauses: list[str] = []
    if device_address is not None:
        clauses.append(f"usb.device_address == {device_address}")
    if product_id is not None:
        # idProduct only appears in the device descriptor; to filter the whole
        # session by it we instead let usbmon device_address do the work. We keep
        # product_id only for reporting unless an address is unknown.
        pass
    return " && ".join(clauses)


def _run_tshark_fields(pcap: Path, display_filter: str) -> list[dict[str, str]]:
    """Run tshark once, pulling every field we need as TSV. One row per packet."""
    fields = [
        "frame.number",
        "frame.time_relative",
        "usb.transfer_type",
        "usb.urb_type",
        "usb.device_address",
        "usb.endpoint_address",
        "usb.bmRequestType",
        "usb.setup.bRequest",
        "usb.setup.wValue",
        "usb.setup.wIndex",
        "usb.setup.wLength",
        "usb.data_fragment",
        "usb.capdata",
        "usbprinter.device_id",
        "usbprinter.bRequest",
        "usbprinter.max_len",
        "usb.urb_status",
    ]
    cmd = [_tshark(), "-r", str(pcap), "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "occurrence=f"]
    if display_filter:
        cmd += ["-Y", display_filter]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed (rc={proc.returncode}): {proc.stderr.strip()}")
    rows: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        cols = line.split("\t")
        # pad to len(fields)
        cols += [""] * (len(fields) - len(cols))
        rows.append(dict(zip(fields, cols, strict=False)))
    return rows


def _hex_text(device_id: str) -> tuple[str, str]:
    """A dissected 1284 device-id is shown as text; render both forms."""
    if not device_id:
        return ("", "")
    text = device_id.strip()
    raw = text.encode("latin-1", "replace").hex()
    return (raw, text)


def parse(pcap: Path, product_id: int | None, device_address: int | None) -> ParseResult:
    display_filter = _build_filter(product_id, device_address)
    rows = _run_tshark_fields(pcap, display_filter)

    result = ParseResult(
        pcap=str(pcap),
        device_filter=display_filter or f"(all devices; report pid={product_id:#06x})"
        if product_id
        else "(all devices)",
    )

    # Coalesce control SUBMIT (carries setup) with its COMPLETE (carries response).
    pending: dict[int, ControlTransfer] = {}  # keyed by frame number of SUBMIT

    for r in rows:
        ttype = _int(r["usb.transfer_type"])
        urb_type = r["usb.urb_type"].strip().strip("'")
        frame = _int(r["frame.number"]) or 0
        ts = float(r["frame.time_relative"] or 0.0)
        status = _int(r["usb.urb_status"])
        data_frag = (r["usb.data_fragment"] or "").replace(":", "").lower()
        capdata = (r["usb.capdata"] or "").replace(":", "").lower()
        dev_id_raw, dev_id_text = _hex_text(r["usbprinter.device_id"])

        if ttype == TT_CONTROL:
            if urb_type == "S":  # SUBMIT: has the setup packet
                bm = _int(r["usb.bmRequestType"])
                direction, req_type, recipient = _decode_bmrequesttype(bm)
                # Class printer requests put bRequest/max-length under the
                # usbprinter dissector, not usb.setup.*; fall back to those.
                breq = _int(r["usb.setup.bRequest"])
                if breq is None:
                    breq = _int(r["usbprinter.bRequest"])
                wlen = _int(r["usb.setup.wLength"])
                if wlen is None:
                    wlen = _int(r["usbprinter.max_len"])
                ct = ControlTransfer(
                    frame=frame,
                    ts=ts,
                    bmRequestType=bm,
                    bRequest=breq,
                    wValue=_int(r["usb.setup.wValue"]),
                    wIndex=_int(r["usb.setup.wIndex"]),
                    wLength=wlen,
                    direction=direction,
                    req_type=req_type,
                    recipient=recipient,
                    setup_data_hex=data_frag if direction == "OUT" else "",
                    response_hex="",
                    response_text="",
                    urb_status=None,
                )
                ct.note = _annotate_control(ct)
                result.control.append(ct)
                pending[frame] = ct
            elif urb_type == "C":  # COMPLETE: response data lands here
                # The COMPLETE shares the SUBMIT's request; attach response to the
                # most recent pending control transfer (same URB id ordering).
                resp = data_frag or capdata or dev_id_raw
                if result.control:
                    last = result.control[-1]
                    if last.direction == "IN" and not last.response_hex:
                        last.response_hex = resp
                        last.response_text = dev_id_text
                        last.urb_status = status
                        # refine annotation now that response is known
                        last.note = _annotate_control(last)

        elif ttype == TT_BULK:
            payload = capdata or data_frag
            if not payload:
                continue
            ep = _int(r["usb.endpoint_address"]) or 0
            direction = "IN" if (ep & 0x80) else "OUT"
            bf = BulkFrame(
                frame=frame,
                ts=ts,
                endpoint=ep,
                direction=direction,
                data_hex=payload,
                urb_status=status,
            )
            bf.note = _annotate_bulk(bf)
            result.bulk.append(bf)

    return result


def _annotate_control(ct: ControlTransfer) -> str:
    notes: list[str] = []
    if (
        ct.bmRequestType == KNOWN_RESET["bmRequestType"]
        and ct.bRequest == KNOWN_RESET["bRequest"]
    ):
        if ct.setup_data_hex == KNOWN_RESET["data_hex"]:
            notes.append("*** ABSORBER RESET (matches known [00 03 01 03 07]) ***")
        else:
            notes.append("vendor OUT bRequest=0x85 (reset-family; data differs)")
    elif ct.req_type == "vendor" and ct.direction == "OUT":
        notes.append("vendor control-OUT (candidate write/command)")
    elif ct.req_type == "vendor" and ct.direction == "IN":
        notes.append("vendor control-IN (candidate read)")
    if ct.req_type == "class" and ct.bRequest == 0x00:
        notes.append("class GET_DEVICE_ID (IEEE-1284 id read)")
    if ct.req_type == "class" and ct.bRequest == 0x01:
        notes.append("class GET_PORT_STATUS")
    if ct.urb_status is not None and ct.urb_status not in (0, None):
        notes.append(f"URB status={ct.urb_status} (non-zero — STALL/error?)")
    return "; ".join(notes)


def _annotate_bulk(bf: BulkFrame) -> str:
    if bf.endpoint in (0x0C, 0x0E, 0x8D, 0x8F):
        return "IPP-over-USB lane (noise for maintenance analysis)"
    if bf.endpoint == MAINT_BULK_OUT_EP:
        return "maintenance bulk-OUT (interface 4)"
    if bf.endpoint == MAINT_BULK_IN_EP:
        return "maintenance bulk-IN (interface 4)"
    return ""


# ─── Rendering ────────────────────────────────────────────────────────────────


def _fmt_hex16(v: int | None, width: int = 2) -> str:
    return "----" if v is None else f"0x{v:0{width}x}"


def render_text(result: ParseResult) -> str:
    lines: list[str] = []
    lines.append(f"pcap:   {result.pcap}")
    lines.append(f"filter: {result.device_filter}")
    lines.append(f"control transfers: {len(result.control)}")
    lines.append(f"bulk frames:       {len(result.bulk)}")
    lines.append("")
    lines.append("=== CONTROL TRANSFERS (EP0, in capture order) ===")
    lines.append(
        "  frame   t(s)    dir  type     bmReq bReq   wValue wIndex wLen "
        "data/response"
    )
    for ct in result.control:
        payload = ct.setup_data_hex if ct.direction == "OUT" else ct.response_hex
        payload_disp = _truncate(payload)
        if not payload_disp and ct.response_text:
            payload_disp = f'"{ct.response_text[:TEXT_PREVIEW_CHARS]}"'
        lines.append(
            f"  {ct.frame:5d} {ct.ts:7.3f}  {ct.direction:3s}  "
            f"{ct.req_type:8s} {_fmt_hex16(ct.bmRequestType):4s} "
            f"{_fmt_hex16(ct.bRequest):5s} {_fmt_hex16(ct.wValue, U16_FIELD_WIDTH):6s} "
            f"{_fmt_hex16(ct.wIndex, U16_FIELD_WIDTH):6s} "
            f"{(ct.wLength if ct.wLength is not None else 0):4d} {payload_disp}"
        )
        if ct.note:
            lines.append(f"          └─ {ct.note}")
    lines.append("")
    lines.append("=== BULK FRAMES (in capture order) ===")
    if not result.bulk:
        lines.append("  (none)")
    for bf in result.bulk:
        disp = _truncate(bf.data_hex)
        line = (
            f"  {bf.frame:5d} {bf.ts:7.3f}  {bf.direction:3s}  "
            f"ep={_fmt_hex16(bf.endpoint):4s} len={len(bf.data_hex)//2:4d}  {disp}"
        )
        if bf.note:
            line += f"   [{bf.note}]"
        lines.append(line)
    return "\n".join(lines)


def render_replay_snippet(result: ParseResult) -> str:
    """Emit a Python list of (bmRequestType,bRequest,wValue,wIndex,data) tuples
    for the vendor/class control transfers — ready to paste into the SSOT or
    the ops.py control-transfer replay path."""
    lines = [
        "# Captured control-transfer sequence — paste into",
        "# printers/canon-g6020/maintenance.yaml::supported.absorber_reset",
        "#   .control_sequence  (and cross-check against ops.replay_control_sequence).",
        "# Each entry: (bmRequestType, bRequest, wValue, wIndex, data_hex)",
        "CONTROL_SEQUENCE = [",
    ]
    def _py(v: int | None, width: int = 2) -> str:
        # Valid Python literal: hex int, or a zero literal for an unfilled field.
        if v is None:
            return f"0x{0:0{width}x}"
        return f"0x{v:0{width}x}"

    for ct in result.control:
        if ct.req_type not in ("vendor", "class"):
            continue
        data = ct.setup_data_hex if ct.direction == "OUT" else ""
        lines.append(
            f"    ({_py(ct.bmRequestType)}, {_py(ct.bRequest)}, "
            f"{_py(ct.wValue, U16_FIELD_WIDTH)}, {_py(ct.wIndex, U16_FIELD_WIDTH)}, "
            f'"{data}"),  # {ct.direction} {ct.note or ct.req_type}'
        )
    lines.append("]")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("pcap", type=Path, help="usbmon .pcapng[.gz] to parse")
    p.add_argument(
        "--product-id",
        type=lambda s: int(s, 0),
        default=SERVICE_MODE_PID,
        help=f"reported device pid (default {SERVICE_MODE_PID:#06x} = service mode)",
    )
    p.add_argument(
        "--device-address",
        type=lambda s: int(s, 0),
        default=None,
        help="usbmon device address to filter on (e.g. 42). Recommended for clean output.",
    )
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p.add_argument(
        "--replay-snippet",
        action="store_true",
        help="emit a CONTROL_SEQUENCE Python list for the SSOT / ops.py replay path",
    )
    args = p.parse_args(argv)

    pcap = args.pcap.expanduser()
    if not pcap.is_file():
        gz = pcap.with_suffix(pcap.suffix + ".gz")
        if gz.is_file():
            pcap = gz
        else:
            print(f"error: no such file: {pcap}", file=sys.stderr)
            return 2

    try:
        result = parse(pcap, args.product_id, args.device_address)
    except TsharkUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(
            json.dumps(
                {
                    "pcap": result.pcap,
                    "device_filter": result.device_filter,
                    "control": [asdict(c) for c in result.control],
                    "bulk": [asdict(b) for b in result.bulk],
                },
                indent=2,
            )
        )
    elif args.replay_snippet:
        print(render_replay_snippet(result))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
