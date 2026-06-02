#!/usr/bin/env bash
# wicreset-capture.sh — usbmon-capture a WICReset session against the G6020.
#
# WICReset (wic.support) is a known-good commercial absorber-counter resetter.
# Capturing it over usbmon recovers the VERIFIED real reset bytes for our unit
# (vs the v5103/G3010-mode hypothesis). See:
#   docs/research/canon-service-mode-field-guide.md
#
# RUNS UNPRIVILEGED. tshark reads /dev/usbmonN via the `usbmon` group +
# dumpcap's file-capabilities; the only privileged op is toggling ipp-usb,
# granted scoped-NOPASSWD by the canon_tool_dev role
# (/etc/sudoers.d/canon-capture). So this whole script is headless-safe:
# drive it over ssh, stop it with ENTER (TTY) or SIGTERM (headless/CI).
#
# Usage (on mbp-13, as the capture user — NOT root):
#   ./wicreset-capture.sh wicreset-read-1        # Phase 1: FREE read (no key)
#   ./wicreset-capture.sh wicreset-reset-real    # Phase 2: reset (spends key)
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
USBMON_IF="${USBMON_IF:-usbmon1}"           # G6020 enumerated on bus 001
STAGING="$HOME/canon-tool-staging"
CAPTURES="$STAGING/captures"
TS=$(date -u +%Y%m%d-%H%M%S)
PCAP_TMP="$STAGING/.${LABEL}-${TS}.pcapng"
PCAP_DEST="$CAPTURES/${LABEL}-${TS}.pcapng"
PIDFILE="$STAGING/.wicreset-capture-${LABEL}.pid"

if [ "$(id -u)" -eq 0 ]; then
  echo "error: run as the capture user, NOT root. Capture is unprivileged" >&2
  echo "       (usbmon group + dumpcap caps); only ipp-usb toggle uses sudo." >&2
  exit 3
fi
mkdir -p "$CAPTURES"

# ─── Pre-flight: G6020 present, on fw 1.070, usbmon readable ─────────────────
if ! lsusb -d 04a9:1865 >/dev/null 2>&1; then
  echo "error: Canon G6020 (04a9:1865) not on USB. Powered on + connected?" >&2
  exit 4
fi
if [ ! -r "/dev/${USBMON_IF}" ]; then
  echo "error: /dev/${USBMON_IF} not readable. In the usbmon group?" >&2
  echo "       'id' should list usbmon; if just added, re-login or 'newgrp usbmon'." >&2
  echo "       (usbmon autoloads at boot via canon_tool_dev modules-load.d.)" >&2
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
echo "pre-flight: G6020 detected, firmware ${FW:-?}, /dev/${USBMON_IF} readable ✓"

# ─── Stop ipp-usb so Wine/WICReset can claim the device (scoped sudo) ────────
echo
echo "step 1: stopping ipp-usb (scoped NOPASSWD) ..."
sudo -n systemctl stop ipp-usb
sleep 1

# ─── Start tshark UNPRIVILEGED (usbmon group + dumpcap caps) ─────────────────
echo "step 2: starting tshark on ${USBMON_IF} (unprivileged) ..."
nohup tshark -i "$USBMON_IF" -w "$PCAP_TMP" -F pcapng >"$STAGING/.tshark-${TS}.log" 2>&1 &
TSHARK_PID=$!
sleep 2
if ! kill -0 "$TSHARK_PID" 2>/dev/null; then
  echo "error: tshark exited before capture. see $STAGING/.tshark-${TS}.log" >&2
  sudo -n systemctl start ipp-usb
  exit 6
fi
echo "step 3: tshark capturing → $PCAP_TMP (pid=$TSHARK_PID)"

# ─── finalize: stop tshark, restart ipp-usb, package + summarize (once) ──────
# Triggered by ENTER (TTY/human) or SIGTERM/SIGINT (headless/agent/CI).
FINALIZED=""
finalize() {
  [ -n "$FINALIZED" ] && return 0
  FINALIZED=1
  trap - TERM INT
  echo
  echo "step 4: stopping tshark (pid=$TSHARK_PID) ..."
  kill -INT "$TSHARK_PID" 2>/dev/null || true
  sleep 2
  wait "$TSHARK_PID" 2>/dev/null || true
  rm -f "$PIDFILE"

  if [ ! -s "$PCAP_TMP" ]; then
    echo "error: pcap empty/missing at $PCAP_TMP" >&2
    sudo -n systemctl start ipp-usb
    exit 7
  fi

  echo "step 5: move → $PCAP_DEST + gzip -9 ..."
  mv "$PCAP_TMP" "$PCAP_DEST"
  gzip -9 "$PCAP_DEST"
  PCAP_DEST="${PCAP_DEST}.gz"

  echo "step 6: restarting ipp-usb ..."
  sudo -n systemctl start ipp-usb
  sleep 2
  systemctl is-active --quiet ipp-usb && echo "       ipp-usb active ✓" \
    || echo "       warning: ipp-usb NOT active — check: systemctl status ipp-usb"

  echo
  echo "════════════════════════════════════════════════════════════════"
  echo "capture complete: $PCAP_DEST"
  echo "  size: $(stat -c %s "$PCAP_DEST") bytes (gzipped)"
  echo
  echo "next: rsync to neo, then  just canon-analyze <pcap>"
  echo "  Success = bulk-OUT 0x03 + bulk-IN 0x86 present (baseline had ZERO 0x03)."
  echo "  For a read capture: re-run 2-3x; identical transactions ⇒ deterministic."
  echo "════════════════════════════════════════════════════════════════"
  exit 0
}
trap 'finalize' TERM INT
echo $$ > "$PIDFILE"

# NB: match the explicit "-reset" token, NOT "*reset*" — the tool name
# "wicreset" contains "reset", so a read label like wicreset-read-1 would
# otherwise wrongly show the key-spending banner. Safe default = read.
case "$LABEL" in
  *-reset*) ACTION_BLOCK='║  Enter your WICReset key, click "Reset". Wait ~2 min for it to finish.  ║
║  ⚠ THIS SPENDS THE SINGLE-USE KEY. Only proceed if the new waste-ink     ║
║    pads/kit are installed and a Phase-1 read capture already worked.     ║' ;;
  *)       ACTION_BLOCK='║  Click "Read waste counters" ONLY. Do NOT enter a key or reset — this   ║
║  is the free, no-key, no-reset dry run that proves the capture works.    ║' ;;
esac

cat <<MSG

╔════════════════════════════════════════════════════════════════════════╗
║  READY — tshark is capturing.                                          ║
║                                                                        ║
║  Launch WICReset under Wine (separate terminal w/ display or ssh -X):   ║
║    wine ~/canon-tool-staging/wicreset/PrinterPotty_WICReset.exe          ║
║    1. Select the Canon G6020 via USB connection                        ║
${ACTION_BLOCK}
╚════════════════════════════════════════════════════════════════════════╝

MSG

# Stop on ENTER at a TTY; otherwise wait for a signal so the same artifact can
# be driven headless: kill -TERM \$(cat "$PIDFILE")
if [ -t 0 ]; then
  read -r -p "Press ENTER when the WICReset operation is done, to stop tshark: " _
  finalize
else
  echo "[headless] capturing. stop with:  kill -TERM \$(cat $PIDFILE)   (pid $$)"
  while true; do sleep 1; done
fi
