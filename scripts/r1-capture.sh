#!/usr/bin/env bash
# r1-capture.sh — orchestrate a Wine + Service Tool USB capture session
# against the named test unit. Run on mbp-13 (the host that has the G6020
# physically connected + the canon_tool_dev role applied).
#
# This script:
#   1. Pre-flight: verify G6020 is connected + firmware fingerprint matches
#   2. Stop ipp-usb so Wine can claim the device
#   3. Start tshark capturing usbmon1 -> /home/<user>/canon-tool-staging/captures/
#   4. Echo READY → operator launches Wine + Service Tool in another terminal,
#      drives the GUI to the desired operation, exits Service Tool
#   5. Operator hits ENTER here → script stops tshark, restores ipp-usb,
#      gzip-compresses the pcap, prints summary
#
# Usage:
#   sudo ./r1-capture.sh <label>      # e.g. v5103-g3010mode-attempt-1
#
# The label appears in the resulting pcap filename:
#   ~/canon-tool-staging/captures/<label>-<YYYYmmdd-HHMMSS>.pcapng.gz
#
# Requires: tshark, ipp-usb systemd unit, /dev/usbmon1, sudo.

set -euo pipefail

# ─── Pre-flight ──────────────────────────────────────────────────────────────

if [ "${1:-}" = "" ]; then
  echo "usage: $0 <label>" >&2
  echo "  label examples: v5103-g3010mode-attempt-1 / v5302-g6020mode-real / etc." >&2
  exit 2
fi
LABEL="$1"
CAPTURE_USER="${SUDO_USER:-$USER}"
STAGING="/home/${CAPTURE_USER}/canon-tool-staging"
CAPTURES="${STAGING}/captures"
TS=$(date -u +%Y%m%d-%H%M%S)
PCAP_TMP="/tmp/canon-r1-${LABEL}-${TS}.pcapng"
PCAP_DEST="${CAPTURES}/${LABEL}-${TS}.pcapng"

if [ "$(id -u)" -ne 0 ]; then
  echo "error: this script must be run with sudo (tshark needs root for usbmon)" >&2
  exit 3
fi

mkdir -p "$CAPTURES"
chown "$CAPTURE_USER:$CAPTURE_USER" "$CAPTURES"

# ─── Verify G6020 is present + still on fw 1.070 ─────────────────────────────

if ! lsusb -d 04a9:1865 >/dev/null 2>&1; then
  echo "error: Canon G6020 (04a9:1865) not found on USB. Is it powered on + connected?" >&2
  exit 4
fi

FW=$(/usr/bin/ipptool -tv ipp://localhost:60001/ipp/print get-printer-attributes.test 2>/dev/null \
  | grep -oE "printer-firmware-version.*= [0-9.]+" \
  | grep -oE "[0-9.]+\$" || echo "")

if [ -z "$FW" ]; then
  echo "warning: could not read firmware version via IPP — ipp-usb may already be down"
elif [ "$FW" != "1.070" ]; then
  echo "error: firmware drift detected (got '$FW', expected '1.070')" >&2
  echo "       captured byte sequences may no longer be valid for this printer." >&2
  echo "       Re-capture the protocol_fingerprint in maintenance.yaml before proceeding." >&2
  exit 5
fi
echo "pre-flight: G6020 detected on bus 001, firmware $FW ✓"

# ─── Stop ipp-usb so Wine can claim the device ───────────────────────────────

echo
echo "step 1: stopping ipp-usb (CUPS office queue will be offline during capture) ..."
systemctl stop ipp-usb
sleep 1

# ─── Start tshark ──────────────────────────────────────────────────────────────

echo "step 2: loading usbmon module + starting tshark capture ..."
modprobe usbmon 2>/dev/null || true
nohup tshark -i usbmon1 -w "$PCAP_TMP" -F pcapng >/tmp/tshark-${TS}.log 2>&1 &
TSHARK_PID=$!

# Wait briefly + confirm tshark actually got the file open.
sleep 2
if ! kill -0 "$TSHARK_PID" 2>/dev/null; then
  echo "error: tshark exited before capture started. see /tmp/tshark-${TS}.log" >&2
  systemctl start ipp-usb
  exit 6
fi
echo "step 3: tshark capturing to $PCAP_TMP (pid=$TSHARK_PID)"

# ─── Operator interaction ─────────────────────────────────────────────────────

cat <<MSG

╔════════════════════════════════════════════════════════════════════════╗
║                                                                        ║
║  READY — tshark is capturing.                                          ║
║                                                                        ║
║  In a SEPARATE terminal (or ssh -X) on this host, run:                 ║
║                                                                        ║
║    wine ~/canon-tool-staging/extracted/ServiceTool_v5103/ServiceTool_v5103.exe                                                                       ║
║                                                                        ║
║  Click through:                                                        ║
║    1. Model: G3010 series (or G6020 if using v5302+)                   ║
║    2. Function: Maintenance  →  Ink Absorber Counter                   ║
║    3. Click "Set" to send the reset command                            ║
║                                                                        ║
║  When you've completed the operation AND closed Service Tool,          ║
║  return to this terminal and press ENTER to stop capture.              ║
║                                                                        ║
╚════════════════════════════════════════════════════════════════════════╝

MSG

read -r -p "Press ENTER when Service Tool is closed and you want to stop tshark: " _

# ─── Stop tshark + restore ipp-usb ────────────────────────────────────────────

echo
echo "step 4: stopping tshark (pid=$TSHARK_PID) ..."
kill -INT "$TSHARK_PID" 2>/dev/null || true
sleep 2

# tshark may need an extra moment to flush the pcap.
wait "$TSHARK_PID" 2>/dev/null || true

if [ ! -s "$PCAP_TMP" ]; then
  echo "error: pcap is empty or missing at $PCAP_TMP" >&2
  systemctl start ipp-usb
  exit 7
fi

echo "step 5: chown + move pcap to $PCAP_DEST ..."
chown "$CAPTURE_USER:$CAPTURE_USER" "$PCAP_TMP"
mv "$PCAP_TMP" "$PCAP_DEST"

echo "step 6: gzip-compressing ..."
gzip -9 "$PCAP_DEST"
PCAP_DEST="${PCAP_DEST}.gz"

echo "step 7: restarting ipp-usb (restores CUPS office queue) ..."
systemctl start ipp-usb
sleep 2
if systemctl is-active --quiet ipp-usb; then
  echo "       ipp-usb is active ✓"
else
  echo "       warning: ipp-usb did NOT come back active. Run: sudo systemctl status ipp-usb"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo
echo "════════════════════════════════════════════════════════════════"
echo "capture complete:"
echo "  $PCAP_DEST"
echo "  size: $(stat -c %s "$PCAP_DEST") bytes (gzipped)"
echo "  packets: $(zcat "$PCAP_DEST" 2>/dev/null | tshark -r - 2>/dev/null | wc -l || echo "?")"
echo
echo "next steps:"
echo "  1. rsync to neo:"
echo "     rsync $(hostname):$PCAP_DEST \\"
echo "       ~/git/canon-megatank-reset/captures/"
echo
echo "  2. analyze:"
echo "     just analyze captures/$(basename "$PCAP_DEST")"
echo
echo "  3. write a .meta.yaml sidecar — see example.meta.yaml for the schema"
echo "════════════════════════════════════════════════════════════════"
