#!/usr/bin/env bash
# Lane B — Win11 capture VM lifecycle for the Canon reset-handshake capture.
# Session-mode libvirt (qemu:///session) — runs as the capture user, NO root.
#
# The goal: run the Windows Service Tool / WICReset against the passed-through
# real G6020, while a HOST-SIDE usbmon capture records the full
# open->preamble->payload reset exchange. Replaying that verbatim (or
# cross-checking Lane A's static handshake) gives a working native reset.
#
# Subcommands:
#   setup      create the qcow2 + per-VM NVRAM, substitute $HOME, define the domain
#   install    start the VM with the Win11 ISO attached (drive the GUI via SPICE)
#   snapshot   snapshot the qcow2 (do this once Win + driver + tool are installed)
#   capture    HOST-side usbmon capture wrapping a guest reset (see README step 5)
#   start|stop|status|detach   VM power + hand the G6020 back to the host
#
# See host/vm-capture/README.md for the end-to-end runbook.
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo ~/git/canon-megatank-reset)"
STG="${CANON_STAGING:-$HOME/canon-tool-staging}"
XML_SRC="$ROOT/host/vm-capture/canon-capture-win11.xml"
XML_RUN="$STG/canon-capture-win11.xml"
DISK="$STG/canon-capture-win11.qcow2"
VM="canon-capture-win11"
VIRSH="virsh --connect qemu:///session"
USBMON_IF="${USBMON_IF:-usbmon1}"   # G6020 enumerates on bus 001

cmd="${1:-help}"; shift || true

case "$cmd" in
setup)
  mkdir -p "$STG/captures"
  [ -f "$DISK" ] || { echo "create 64G qcow2 -> $DISK"; qemu-img create -f qcow2 "$DISK" 64G; }
  # per-VM writable NVRAM copy (OVMF_VARS template is read-only)
  [ -f "$STG/canon-capture-win11_VARS.fd" ] || cp /usr/share/edk2/ovmf/OVMF_VARS.fd "$STG/canon-capture-win11_VARS.fd"
  # substitute the absolute home into the XML (libvirt needs absolute paths)
  sed "s#HOME_ABS#$HOME#g" "$XML_SRC" > "$XML_RUN"
  echo "defining domain from $XML_RUN"
  $VIRSH define "$XML_RUN"
  echo "OK. Next: $0 install"
  ;;
install)
  echo "starting $VM (Win11 ISO attached). Connect a SPICE viewer to install."
  $VIRSH start "$VM" || true
  echo "SPICE display:"; $VIRSH domdisplay "$VM" || true
  cat <<'NEXT'
Install Win11 (Shift+F10 -> OOBE\BYPASSNRO to skip MS account if needed).
After install:
  1. Install the Canon G6020 Windows driver (so the tool sees the printer).
  2. Copy in the Service Tool (or WICReset) — via SPICE clipboard / shared dir.
  3. Install USBPcap (desowin.org/usbpcap) for in-guest capture (optional;
     host-side usbmon via `vm-capture.sh capture` is the primary path).
Then snapshot:  vm-capture.sh snapshot clean-installed
NEXT
  ;;
snapshot)
  name="${1:-snap-$(date -u +%Y%m%d-%H%M%S)}"
  $VIRSH snapshot-create-as "$VM" "$name" --disk-only --atomic 2>/dev/null \
    || $VIRSH snapshot-create-as "$VM" "$name"
  echo "snapshot: $name"
  ;;
capture)
  # HOST-side usbmon capture around a guest-driven reset. The G6020 is passed
  # through to the guest, but usbmon on the host still sees the bus traffic.
  label="${1:-reset-handshake}"
  ts="$(date -u +%Y%m%d-%H%M%S)"
  out="$STG/captures/${label}-${ts}.pcapng"
  echo "capturing $USBMON_IF -> $out"
  echo ">>> NOW: in the guest, run ONE full reset in the Service Tool/WICReset."
  echo ">>> Stop this capture with Ctrl-C when the reset completes."
  dumpcap -i "$USBMON_IF" -w "$out" -q
  echo "capture: $out"
  echo "extract bulk frames: tshark -r '$out' -Y 'usb.transfer_type==0x03' -T fields -e usb.endpoint_address -e usb.capdata"
  ;;
start)  $VIRSH start "$VM" ;;
stop)   $VIRSH shutdown "$VM" || $VIRSH destroy "$VM" ;;
status) $VIRSH list --all | grep -i "$VM" || echo "not defined"; $VIRSH domdisplay "$VM" 2>/dev/null || true ;;
detach)
  # hand the G6020 back to the host (CUPS/ipp-usb) when done
  echo "detaching G6020 from $VM (managed hostdev auto-reattaches on VM stop too)"
  $VIRSH shutdown "$VM" 2>/dev/null || $VIRSH destroy "$VM" 2>/dev/null || true
  ;;
*)
  sed -n '2,40p' "$0"
  ;;
esac
