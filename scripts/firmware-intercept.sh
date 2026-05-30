#!/usr/bin/env bash
# Intercept the G6020's panel-initiated firmware download (Lane C / approach A).
#
# The G6020 has no host-side updater and 404s the legacy ijdupdate index, but it
# downloads its own firmware over PLAIN HTTP from gdlp01.c-wss.com. With macOS
# Internet Sharing (Wi-Fi -> Ethernet) the printer's HTTP GET crosses bridge100
# in cleartext, where tshark sees it. We capture the URL, then curl the blob
# directly (no install). See docs/runbook/firmware-panel-intercept.md.
#
# Unprivileged where possible; tshark needs BPF access (ChmodBPF / admin on macOS).
# This script does NOT touch the printer — the operator drives the panel.
set -euo pipefail

STAGING="${CANON_STAGING:-$HOME/canon-tool-staging}"
CAPTURE_DIR="$STAGING/captures"
LABEL="${1:-firmware-intercept}"
TS="$(date -u +%Y%m%d-%H%M%S)"
IFACE="${INTERCEPT_IFACE:-bridge100}"          # macOS Internet Sharing bridge
OUT="$CAPTURE_DIR/${LABEL}-${TS}.pcapng"

mkdir -p "$CAPTURE_DIR"

echo "== firmware-intercept =="
echo "interface : $IFACE  (override with INTERCEPT_IFACE=)"
echo "output    : $OUT"

# 1) Sanity: the bridge interface must exist (Internet Sharing enabled).
if ! ifconfig "$IFACE" >/dev/null 2>&1; then
  cat >&2 <<EOF
ERROR: interface '$IFACE' not found.
Enable macOS Internet Sharing (System Settings > General > Sharing):
  share Wi-Fi -> to Ethernet. That brings up bridge100. Then plug the G6020
  into that Ethernet and confirm it pulls a 192.168.2.x lease.
See docs/runbook/firmware-panel-intercept.md.
EOF
  exit 1
fi

# 2) Try to discover the printer IP on the shared subnet (best-effort hint).
PRINTER_IP="${PRINTER_IP:-}"
if [[ -z "$PRINTER_IP" ]]; then
  PRINTER_IP="$(arp -an 2>/dev/null | awk '/192\.168\.2\./{gsub(/[()]/,"",$2); print $2; exit}')" || true
fi
[[ -n "$PRINTER_IP" ]] && echo "printer ip : $PRINTER_IP (auto)" \
                       || echo "printer ip : (unknown — capturing all bridge HTTP; set PRINTER_IP= to narrow)"

# 3) Capture filter: HTTP on the firmware CDN host family. Canon serves the blob
#    from gdlp01.c-wss.com (and *.c-wss.com); we keep it broad to also catch the
#    version-check redirect, then extract the .bin GET afterwards.
FILTER="tcp port 80"
[[ -n "$PRINTER_IP" ]] && FILTER="host $PRINTER_IP and tcp port 80"

echo
echo ">>> Starting capture. Now on the PRINTER PANEL:"
echo "      Setup > Device settings > Firmware update > Check for update"
echo "    If an update is offered, start the DOWNLOAD and watch below."
echo "    *** CANCEL BEFORE 'Install' *** once the blob URL appears."
echo "    Stop the capture with Ctrl-C (or it auto-stops after \$DURATION secs)."
echo

DURATION="${DURATION:-180}"

cleanup() { echo; echo "== capture stopped =="; }
trap cleanup EXIT INT TERM

# 4) Run tshark. -a duration bounds the run; live-print any URL with .bin.
#    (tshark from the nix devShell: `just`/direnv provides it.)
tshark -i "$IFACE" -f "$FILTER" -w "$OUT" -a "duration:$DURATION" \
       -P -Y 'http.request' \
       -T fields -e ip.dst -e http.host -e http.request.full_uri 2>/dev/null \
  | tee "$CAPTURE_DIR/${LABEL}-${TS}.requests.txt" || true

echo
echo "== extracting firmware blob URL(s) =="
# 5) Pull any AN.bin GET out of the captured requests.
BLOB_URL="$(grep -Eo 'https?://[^[:space:]]+V[0-9]+AN\.bin' \
            "$CAPTURE_DIR/${LABEL}-${TS}.requests.txt" 2>/dev/null | head -1 || true)"

if [[ -n "$BLOB_URL" ]]; then
  echo "FOUND blob URL: $BLOB_URL"
  echo
  echo "Next (does NOT install — printer flow can be cancelled):"
  echo "  curl -fSL -o $STAGING/fw/\$(basename '$BLOB_URL') '$BLOB_URL'"
  echo "  shasum -a 256 $STAGING/fw/\$(basename '$BLOB_URL')   # then SHA-pin in maintenance.yaml (do NOT commit the .bin)"
else
  cat <<EOF
No '*AN.bin' GET seen. Possible reasons:
  - The unit is already current (1.070 latest) -> panel downloaded nothing.
  - The version check is TLS-only and no download started.
  - Wrong interface / printer not on the shared subnet.
Re-check the panel reported an available update, confirm PRINTER_IP, retry.
Full request log: $CAPTURE_DIR/${LABEL}-${TS}.requests.txt
pcap: $OUT
EOF
fi
