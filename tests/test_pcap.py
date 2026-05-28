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
