#!/usr/bin/env bash
# wicreset-capture.sh — usbmon-capture a WICReset session against the G6020.
#
# WICReset (wic.support) is a known-good commercial absorber-counter resetter.
# Capturing it over usbmon recovers the VERIFIED real reset bytes for our unit
# (vs the v5103/G3010-mode hypothesis). See:
#   docs/runbook/canon-tool-wicreset-capture.md
#
# Same capture machinery as r1-capture.sh (pre-flight fw 1.070 → stop ipp-usb →
# tshark usbmon1 → operator drives the GUI → ENTER → gzip + summary). The only
# difference is the operator runs native WICReset instead of Wine+ServiceTool.
#
# Usage (on mbp-13, as root):
#   sudo ./wicreset-capture.sh wicreset-read-1        # Phase 1: FREE read (no key)
#   sudo ./wicreset-capture.sh wicreset-reset-real    # Phase 2: reset (spends key)
#
# ⚠ Phase 2 spends the SINGLE-USE key and lets the printer print again — only
#   run it AFTER the new waste-ink pads/kit are physically installed, and only
#   after a Phase-1 read capture has PROVEN the pipeline records bulk 0x03/0x86.

set -euo pipefail

if [ "${1:-}" = "" ]; then
  echo "usage: $0 <label>   (e.g. wicreset-read-1 | wicreset-reset-real)" >&2
  exit 2
fi
LABEL="$1"
CAPTURE_USER="${SUDO_USER:-$USER}"
STAGING="/home/${CAPTURE_USER}/canon-tool-staging"
CAPTURES="${STAGING}/captures"
TS=$(date -u +%Y%m%d-%H%M%S)
PCAP_TMP="/tmp/canon-wicreset-${LABEL}-${TS}.pcapng"
PCAP_DEST="${CAPTURES}/${LABEL}-${TS}.pcapng"

if [ "$(id -u)" -ne 0 ]; then
  echo "error: must run with sudo (tshark needs root for usbmon)" >&2
  exit 3
fi

mkdir -p "$CAPTURES"
chown "$CAPTURE_USER:$CAPTURE_USER" "$CAPTURES"

# ─── Verify G6020 present + still fw 1.070 (protects the locked fingerprint) ──
if ! lsusb -d 04a9:1865 >/dev/null 2>&1; then
  echo "error: Canon G6020 (04a9:1865) not on USB. Powered on + connected?" >&2
  exit 4
fi
FW=$(/usr/bin/ipptool -tv ipp://localhost:60001/ipp/print get-printer-attributes.test 2>/dev/null \
  | grep -oE "printer-firmware-version.*= [0-9.]+" | grep -oE "[0-9.]+\$" || echo "")
if [ -z "$FW" ]; then
  echo "warning: could not read firmware via IPP — ipp-usb may already be down"
elif [ "$FW" != "1.070" ]; then
  echo "error: firmware drift (got '$FW', expected '1.070'). Re-pin fingerprint first." >&2
  exit 5
fi
echo "pre-flight: G6020 detected, firmware ${FW:-?} ✓"

# ─── Stop ipp-usb so WICReset (libusb) can claim the device ──────────────────
echo
echo "step 1: stopping ipp-usb (CUPS office queue offline during capture) ..."
systemctl stop ipp-usb
sleep 1

# ─── Start tshark ────────────────────────────────────────────────────────────
echo "step 2: loading usbmon + starting tshark on usbmon1 ..."
modprobe usbmon 2>/dev/null || true
nohup tshark -i usbmon1 -w "$PCAP_TMP" -F pcapng >/tmp/tshark-${TS}.log 2>&1 &
TSHARK_PID=$!
sleep 2
if ! kill -0 "$TSHARK_PID" 2>/dev/null; then
  echo "error: tshark exited before capture. see /tmp/tshark-${TS}.log" >&2
  systemctl start ipp-usb
  exit 6
fi
echo "step 3: tshark capturing → $PCAP_TMP (pid=$TSHARK_PID)"

# ─── Operator interaction ─────────────────────────────────────────────────────
case "$LABEL" in
  *reset*) ACTION_BLOCK='║  Enter your WICReset key, click "Reset". Wait ~2 min for it to finish.  ║
║  ⚠ THIS SPENDS THE SINGLE-USE KEY. Only proceed if the new waste-ink     ║
║    pads/kit are installed and a Phase-1 read capture already worked.     ║' ;;
  *)       ACTION_BLOCK='║  Click "Read waste counters" ONLY. Do NOT enter a key or reset — this   ║
║  is the free, no-key, no-reset dry run that proves the capture works.    ║' ;;
esac

cat <<MSG

╔════════════════════════════════════════════════════════════════════════╗
║  READY — tshark is capturing.                                          ║
║                                                                        ║
║  In the WICReset GUI on this host (separate terminal / display):       ║
║    1. Select the Canon G6020 via USB connection                        ║
${ACTION_BLOCK}
║                                                                        ║
║  When the WICReset operation has fully completed, return here and       ║
║  press ENTER to stop the capture.                                      ║
╚════════════════════════════════════════════════════════════════════════╝

MSG
read -r -p "Press ENTER when the WICReset operation is done and you want to stop tshark: " _

# ─── Stop tshark + restore ipp-usb ────────────────────────────────────────────
echo
echo "step 4: stopping tshark (pid=$TSHARK_PID) ..."
kill -INT "$TSHARK_PID" 2>/dev/null || true
sleep 2
wait "$TSHARK_PID" 2>/dev/null || true

if [ ! -s "$PCAP_TMP" ]; then
  echo "error: pcap empty/missing at $PCAP_TMP" >&2
  systemctl start ipp-usb
  exit 7
fi

echo "step 5: chown + move → $PCAP_DEST ..."
chown "$CAPTURE_USER:$CAPTURE_USER" "$PCAP_TMP"
mv "$PCAP_TMP" "$PCAP_DEST"
echo "step 6: gzip -9 ..."
gzip -9 "$PCAP_DEST"
PCAP_DEST="${PCAP_DEST}.gz"

echo "step 7: restarting ipp-usb ..."
systemctl start ipp-usb
sleep 2
systemctl is-active --quiet ipp-usb && echo "       ipp-usb active ✓" \
  || echo "       warning: ipp-usb NOT active — sudo systemctl status ipp-usb"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════"
echo "capture complete: $PCAP_DEST"
echo "  size: $(stat -c %s "$PCAP_DEST") bytes (gzipped)"
echo
echo "next: rsync to neo, then  just canon-analyze <pcap>"
echo "  Success = bulk-OUT 0x03 + bulk-IN 0x86 present (baseline had ZERO 0x03)."
echo "  For a read capture: re-run 2-3x; identical transactions ⇒ deterministic."
echo "════════════════════════════════════════════════════════════════"
