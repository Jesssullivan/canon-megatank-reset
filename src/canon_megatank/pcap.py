"""pcap summary + USB bulk transfer extraction.

Thin wrapper around `tshark` (installed via the canon_tool_dev role on
mbp-13, and typically available on dev workstations via nixpkgs or brew).
Tshark is the gold standard for USB pcap parsing — Wireshark's own
dissectors get every detail right. We extract the parts we care about
and present them as typed dataclasses ready for pinning in
`printers/canon-g6020/maintenance.yaml`.

Run via `just canon-analyze <pcap>` or import as
`from printstack_canon.pcap import summarize`.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from shutil import which

from .types import CanonToolError


class TsharkUnavailableError(CanonToolError):
    """tshark binary not found on PATH. Install wireshark-cli (Rocky) or
    `brew install wireshark` (macOS) or run the canon_tool_dev role."""


# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class UsbTransfer:
    """A single USB transfer extracted from the pcap."""

    timestamp: float                  # seconds from capture start
    transfer_type: str                # 'CONTROL', 'BULK', 'INTERRUPT', 'ISOCHRONOUS'
    direction: str                    # 'OUT' (host->device) or 'IN' (device->host)
    endpoint: int                     # endpoint address (raw, includes direction bit)
    payload_hex: str                  # data bytes as lowercase hex (may be '' for control)
    payload_length: int

    @property
    def is_bulk_out(self) -> bool:
        return self.transfer_type == "BULK" and self.direction == "OUT"

    @property
    def is_bulk_in(self) -> bool:
        return self.transfer_type == "BULK" and self.direction == "IN"


@dataclass(slots=True)
class PcapSummary:
    """Top-level summary of a captured pcap."""

    path: Path
    total_packets: int
    duration_seconds: float
    bulk_out: list[UsbTransfer] = field(default_factory=list)
    bulk_in: list[UsbTransfer] = field(default_factory=list)
    control: list[UsbTransfer] = field(default_factory=list)
    other: list[UsbTransfer] = field(default_factory=list)

    def bulk_out_hex_sequence(self) -> list[str]:
        """List of bulk-OUT payload hex strings in capture order. This is
        the candidate command sequence the Service Tool sent to the printer.
        """
        return [t.payload_hex for t in self.bulk_out if t.payload_hex]

    def bulk_in_hex_sequence(self) -> list[str]:
        """List of bulk-IN payload hex strings in capture order. This is
        the printer's response sequence."""
        return [t.payload_hex for t in self.bulk_in if t.payload_hex]

    def identify_canon_headers(self) -> list[tuple[int, str, str]]:
        """Walk the bulk-OUT sequence and identify likely Canon protocol
        headers. Returns [(transfer_index, protocol_family, first_8_bytes), ...].

        Heuristics (based on documented Canon BJ command shapes + the
        observed CMD set BJRaster3/NCCe/IVEC/URF):

        - 1B 5B 4B   = "ESC [ K" — common Canon BJ/PDL service-mode prefix
        - 40 02      = some IVEC packet framings
        - 40 03      = ditto
        - 1B 28 47   = BJL (legacy BJ Language) — likely BJRaster3 carrier
        """
        out: list[tuple[int, str, str]] = []
        for i, t in enumerate(self.bulk_out):
            head = t.payload_hex[:16]   # first 8 bytes as hex
            if head.startswith("1b5b4b"):
                out.append((i, "Canon BJ ESC-mode (likely NCCe/service)", head))
            elif head.startswith("1b2847"):
                out.append((i, "BJL (BJRaster3 carrier)", head))
            elif head.startswith("4002") or head.startswith("4003"):
                out.append((i, "IVEC framing", head))
            elif head.startswith("404"):
                out.append((i, "IVEC framing (extended)", head))
        return out


# ─── Tshark invocation ────────────────────────────────────────────────────────


def _check_tshark() -> str:
    """Locate tshark or raise."""
    path = which("tshark")
    if path is None:
        raise TsharkUnavailableError(
            "tshark not on PATH. Install via wireshark-cli (Rocky/RHEL), "
            "`brew install wireshark` (macOS), or apt install tshark."
        )
    return path


def summarize(pcap_path: Path | str) -> PcapSummary:
    """Read a pcapng + return a PcapSummary with bulk transfers grouped.

    Tshark is invoked twice:
    1) `-T json -e frame.number -e _ws.col.Time -e usb.transfer_type
       -e usb.endpoint_address.direction -e usb.endpoint_address.number
       -e usb.capdata` — extract all USB transfers as structured JSON.
    2) `-q -z io,stat,0` — total packet count + duration.

    For typical canon-tool captures (< 1000 packets), this is fast (< 200ms).
    """
    pcap = Path(pcap_path).expanduser().resolve()
    if not pcap.is_file():
        # Convenience: if user passed `foo.pcapng` but only `foo.pcapng.gz`
        # exists (because we gzip captures by convention), use the .gz.
        # tshark reads gzipped pcapng files transparently.
        gz_variant = pcap.with_suffix(pcap.suffix + ".gz")
        if gz_variant.is_file():
            pcap = gz_variant
        else:
            raise FileNotFoundError(pcap)
    tshark = _check_tshark()

    # 1) Extract per-packet USB transfer data as ek-json (one packet per line).
    cmd = [
        tshark,
        "-r", str(pcap),
        "-T", "ek",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "usb.transfer_type",
        "-e", "usb.endpoint_address.direction",
        "-e", "usb.endpoint_address.number",
        "-e", "usb.capdata",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise CanonToolError(f"tshark failed (rc={proc.returncode}): {proc.stderr.strip()}")

    summary = PcapSummary(
        path=pcap,
        total_packets=0,
        duration_seconds=0.0,
    )
    max_ts = 0.0

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        # ek-json wraps fields in layers/<field>; pull what we need.
        layers = doc.get("layers", {})
        if "usb_transfer_type" not in layers:
            continue
        summary.total_packets += 1

        ts = float((layers.get("frame_time_relative") or [0])[0]) if layers.get("frame_time_relative") else 0.0
        max_ts = max(max_ts, ts)

        ttype_raw = (layers.get("usb_transfer_type") or ["?"])[0]
        # Tshark prints transfer types as hex like "0x03" (BULK).
        ttype_map = {"0x00": "ISOCHRONOUS", "0x01": "INTERRUPT", "0x02": "CONTROL", "0x03": "BULK"}
        ttype = ttype_map.get(ttype_raw, ttype_raw)

        dir_raw = (layers.get("usb_endpoint_address_direction") or ["?"])[0]
        # 0 = OUT (host->device), 1 = IN (device->host).
        direction = "OUT" if dir_raw in ("0", "0x0") else "IN"

        ep_raw = (layers.get("usb_endpoint_address_number") or ["0"])[0]
        try:
            endpoint = int(ep_raw, 0)
        except ValueError:
            endpoint = 0

        capdata = (layers.get("usb_capdata") or [""])[0]
        # Tshark formats USB data as colon-separated hex: "1b:5b:4b:02:..."
        payload_hex = capdata.replace(":", "").lower()
        payload_length = len(payload_hex) // 2

        transfer = UsbTransfer(
            timestamp=ts,
            transfer_type=ttype,
            direction=direction,
            endpoint=endpoint,
            payload_hex=payload_hex,
            payload_length=payload_length,
        )

        if transfer.is_bulk_out:
            summary.bulk_out.append(transfer)
        elif transfer.is_bulk_in:
            summary.bulk_in.append(transfer)
        elif ttype == "CONTROL":
            summary.control.append(transfer)
        else:
            summary.other.append(transfer)

    summary.duration_seconds = max_ts
    return summary


# ─── CLI entrypoint ──────────────────────────────────────────────────────────


def main() -> int:
    """`python -m printstack_canon.pcap <pcap>` — print a human summary."""
    import argparse

    parser = argparse.ArgumentParser(description="Summarize a canon-tool USB pcap.")
    parser.add_argument("pcap", type=Path, help="Path to .pcapng[.gz]")
    parser.add_argument("--hex-only", action="store_true",
                        help="Print only the bulk-OUT hex sequence (one transfer per line).")
    args = parser.parse_args()

    summary = summarize(args.pcap)

    if args.hex_only:
        for h in summary.bulk_out_hex_sequence():
            print(h)
        return 0

    print(f"pcap:     {summary.path}")
    print(f"packets:  {summary.total_packets}")
    print(f"duration: {summary.duration_seconds:.3f}s")
    print(f"bulk-OUT: {len(summary.bulk_out)} transfers  "
          f"({sum(t.payload_length for t in summary.bulk_out)} bytes total)")
    print(f"bulk-IN:  {len(summary.bulk_in)} transfers  "
          f"({sum(t.payload_length for t in summary.bulk_in)} bytes total)")
    print(f"control:  {len(summary.control)} transfers")
    print(f"other:    {len(summary.other)} transfers")
    print()

    headers = summary.identify_canon_headers()
    if headers:
        print("Canon protocol headers identified in bulk-OUT:")
        for idx, family, head_hex in headers:
            print(f"  [bulk-OUT #{idx}]  {family}")
            print(f"                   first 8 bytes: {head_hex}")
        print()

    print("=== bulk-OUT sequence (commands sent to printer) ===")
    for i, t in enumerate(summary.bulk_out):
        if not t.payload_hex:
            continue
        head = t.payload_hex[:40]
        suffix = "..." if t.payload_length * 2 > 40 else ""
        print(f"  [{i:3d}] t={t.timestamp:7.3f}s  ep=0x{t.endpoint:02x}  "
              f"len={t.payload_length:4d}  {head}{suffix}")
    print()

    print("=== bulk-IN sequence (responses from printer) ===")
    for i, t in enumerate(summary.bulk_in):
        if not t.payload_hex:
            continue
        head = t.payload_hex[:40]
        suffix = "..." if t.payload_length * 2 > 40 else ""
        print(f"  [{i:3d}] t={t.timestamp:7.3f}s  ep=0x{t.endpoint:02x}  "
              f"len={t.payload_length:4d}  {head}{suffix}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys
    sys.exit(main())
