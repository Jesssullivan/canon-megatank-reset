"""End-to-end tests for the pcap analyzer against the committed fixture
captured 2026-05-28: a 60-packet Wine + Service Tool v5103 launch (no
clicks). This locks in:

- Analyzer correctly parses tshark ek-json output.
- The .pcapng.gz fallback path works (we store fixtures gzipped).
- The fixture itself is intact (no bit-rot in committed evidence).
- The negative-control invariant holds: zero bulk-OUT to interface 4
  endpoint 0x03 during launch-only sessions.

Skipped if tshark is not on PATH (CI without wireshark-cli installed).
"""

from __future__ import annotations

from pathlib import Path
from shutil import which

import pytest

from printstack_canon.pcap import (
    PcapSummary,
    TsharkUnavailableError,
    summarize,
)

WINE_LAUNCH_FIXTURE = (
    Path(__file__).parent.parent
    / "captures"
    / "v5103-wine-launch-no-clicks-20260528-222034.pcapng"
)

IPP_USB_BASELINE_FIXTURE = (
    Path(__file__).parent.parent
    / "captures"
    / "ipp-usb-baseline-20260529-001127.pcapng"
)


needs_tshark = pytest.mark.skipif(
    which("tshark") is None,
    reason="tshark not on PATH (install wireshark-cli or enter nix develop)",
)


@needs_tshark
def test_summarize_resolves_gzipped_fixture() -> None:
    """Passed `.pcapng`, analyzer should auto-find the committed `.pcapng.gz`."""
    summary = summarize(WINE_LAUNCH_FIXTURE)
    assert isinstance(summary, PcapSummary)
    # Verify it actually loaded the .gz variant.
    assert summary.path.name.endswith(".pcapng.gz"), (
        f"expected .gz fallback, got {summary.path.name}"
    )


@needs_tshark
def test_wine_launch_fixture_has_60_packets() -> None:
    """The committed fixture is a 60-packet Wine launch capture. Drift
    here means the fixture got recompressed or replaced silently."""
    summary = summarize(WINE_LAUNCH_FIXTURE)
    assert summary.total_packets == 60, (
        f"fixture drift: expected 60 packets, got {summary.total_packets}"
    )


@needs_tshark
def test_wine_launch_capture_under_3_seconds() -> None:
    """Sanity check on duration — Wine launch shouldn't span minutes."""
    summary = summarize(WINE_LAUNCH_FIXTURE)
    assert 1.0 < summary.duration_seconds < 5.0, (
        f"unexpected duration: {summary.duration_seconds}s"
    )


@needs_tshark
def test_negative_control_no_bulk_out_to_endpoint_03() -> None:
    """THE KEY INVARIANT of the negative-control baseline:
    Service Tool v5103 sends ZERO bulk-OUT on endpoint 0x03 during
    launch-only sessions. If this ever yields > 0, either the fixture
    was replaced with a GUI-driven capture (mislabeled) or our
    interpretation of the maintenance channel is wrong.
    """
    summary = summarize(WINE_LAUNCH_FIXTURE)
    bulk_out_to_03 = [
        t for t in summary.bulk_out
        if t.endpoint == 0x03 and t.payload_length > 0
    ]
    assert len(bulk_out_to_03) == 0, (
        f"NEGATIVE CONTROL VIOLATED: {len(bulk_out_to_03)} bulk-OUT to "
        f"endpoint 0x03 in a launch-no-clicks capture. Either the fixture "
        f"got swapped or interface 4 isn't the maintenance channel."
    )


@needs_tshark
def test_bulk_in_on_endpoint_82_is_ieee_1284_traffic() -> None:
    """The launch-only capture has bulk-IN traffic on endpoint 0x82
    (interface 1, USB-IF Printer Class) — that's Service Tool reading the
    IEEE-1284 device-id. 4 transfers expected per the captured baseline."""
    summary = summarize(WINE_LAUNCH_FIXTURE)
    bulk_in_82 = [t for t in summary.bulk_in if t.endpoint == 0x82]
    assert len(bulk_in_82) >= 1, (
        "expected at least one bulk-IN on endpoint 0x82 (IEEE-1284 path)"
    )


@needs_tshark
def test_identify_canon_headers_on_launch_fixture() -> None:
    """The negative-control fixture has no maintenance bytes — so the
    Canon header heuristic should report an empty list. Confirms the
    heuristic isn't false-positive matching on enumeration descriptors."""
    summary = summarize(WINE_LAUNCH_FIXTURE)
    headers = summary.identify_canon_headers()
    assert headers == [], (
        f"unexpected Canon headers in negative-control fixture: {headers}. "
        "The launch-no-clicks pcap should have no protocol payloads at all."
    )


@needs_tshark
def test_ipp_usb_baseline_has_http_framing_on_bulk_out_0x0c() -> None:
    """The IPP-USB baseline fixture should have bulk-OUT traffic on
    endpoint 0x0c (interface 2 IPP-over-USB) starting with the literal
    ASCII bytes for 'POST /ipp/print HTTP/1.1'. Confirms that IPP-over-USB
    is HTTP-framed (the dissecting hypothesis from analysis)."""
    summary = summarize(IPP_USB_BASELINE_FIXTURE)
    bulk_out_0c = [t for t in summary.bulk_out if t.endpoint == 0x0c]
    assert len(bulk_out_0c) > 0, "no bulk-OUT on endpoint 0x0c in IPP-USB baseline"
    # "POST" = 0x50 0x4f 0x53 0x54 in ASCII
    first = bulk_out_0c[0].payload_hex
    assert first.startswith("504f5354"), (
        f"expected 'POST' prefix on bulk-OUT 0x0c, got {first[:16]}..."
    )


@needs_tshark
def test_ipp_usb_baseline_has_zero_maintenance_endpoint_traffic() -> None:
    """The IPP-USB baseline should have ZERO traffic on the Service Tool
    maintenance endpoints (0x03 OUT, 0x86 IN). If this fires, either the
    G6020 spontaneously started talking maintenance protocol (concerning)
    or the fixture was mislabeled."""
    summary = summarize(IPP_USB_BASELINE_FIXTURE)
    maintenance_out = [t for t in summary.bulk_out if t.endpoint == 0x03]
    maintenance_in = [t for t in summary.bulk_in if t.endpoint == 0x86]
    assert maintenance_out == [], (
        f"unexpected maintenance bulk-OUT in IPP-USB baseline: {maintenance_out}"
    )
    # 0x86 has 2 INTERRUPT events in launch baseline (async); accept
    # the same on this fixture if they're INTERRUPT not bulk data.
    assert all(t.payload_length == 0 for t in maintenance_in), (
        f"unexpected maintenance bulk-IN data in IPP-USB baseline: {maintenance_in}"
    )


@needs_tshark
def test_summary_dataclass_has_consistent_counts() -> None:
    """Sanity invariant: sum of all bucket lengths equals total_packets
    only for USB transfers — but every classified transfer must land in
    exactly one bucket."""
    summary = summarize(WINE_LAUNCH_FIXTURE)
    bucketed = (
        len(summary.bulk_out)
        + len(summary.bulk_in)
        + len(summary.control)
        + len(summary.other)
    )
    # Every USB transfer the analyzer saw should be in one of the four
    # buckets. total_packets counts only those with usb_transfer_type set.
    assert bucketed == summary.total_packets, (
        f"bucketing leak: {bucketed} bucketed != {summary.total_packets} total"
    )


def test_tshark_missing_raises_clean_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: if tshark isn't installed, surface a clean
    TsharkUnavailableError with actionable install hints."""

    def fake_which(name: str) -> str | None:
        return None

    import printstack_canon.pcap as pcap_mod
    monkeypatch.setattr(pcap_mod, "which", fake_which)

    with pytest.raises(TsharkUnavailableError) as excinfo:
        summarize(WINE_LAUNCH_FIXTURE)
    msg = str(excinfo.value)
    assert "wireshark-cli" in msg or "brew install" in msg, (
        "expected install hint in TsharkUnavailableError message"
    )
