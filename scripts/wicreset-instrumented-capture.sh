#!/usr/bin/env bash
# wicreset-instrumented-capture.sh — 3-layer instrumented capture of the REAL
# Canon G6020 waste-ink (5B00) reset, driven by WICReset in the Win11 capture VM.
#
# Layers (all on ONE successful reset, one VM session):
#   1. WIRE   — host usbmon (dumpcap on usbmon1) over the passed-through 04a9:12fe.
#   2. APP    — Frida in the guest hooking DeviceIoControl/WinUSB (the command frame
#               + runtime-sourced bytes the wire shows only as opaque payload).
#   3. NET    — a guest packet capture (pktmon, built into Win10/11) to answer the
#               make-or-break question: does WICReset phone home at reset time
#               (cloud-validated) or is the device command purely local (replayable)?
#   + a wall-clock ANCHOR (host epoch at reset-click + the guest's launch anchor) so
#     all three streams correlate to the exact transfer before the EEPROM commit.
#
# The operator drives the GUI over VNC (enters the single-use OctoInkjet key, clicks
# reset) so the human controls the key. This script only instruments + captures, and
# pulls artifacts. After the success window the operator power-BUTTONS the printer
# off→on per OctoInkjet's protocol — do NOT read the counter before that or the key
# burns. usbmon + Frida + pktmon run from BEFORE the key entry through the success
# window; we stop capture right at/after the success window, before the power-cycle.
#
# Subcommands:
#   preflight       check substrate (usbmon, dumpcap caps, VM up, 12fe attached, frida staged)
#   stage           push the hook + launcher into the guest, run frida -Setup
#   rehearse        dry-run with NO key: prove the rig fires (usbmon+frida+pktmon all log),
#                   using a benign action (printer detect / device-id read), no reset
#   capture         the real run: start all 3 layers, log anchor, hand off to operator,
#                   wait for the operator to signal done, stop + pull artifacts
#   anchor          just print + log a wall-clock anchor (operator calls at reset-click)
#   stop            stop all captures + pull artifacts
set -uo pipefail

VM="canon-capture-win11-headless"
VIRSH="virsh --connect qemu:///session"
HOSTDEV_SVC="/tmp/hd-svc.xml"          # 04a9:12fe service-mode hostdev
STG="${CANON_STAGING:-$HOME/canon-tool-staging}"
CAPDIR="$STG/captures"
USBMON_IF="${USBMON_IF:-usbmon1}"
ANSVENV="$HOME/canon-tool-staging/ansvenv/bin"
REPO_GUESTWIN="host/vm-capture/win"    # relative to the repo on neo (pushed via scp)
TS() { date -u +%Y%m%d-%H%M%S; }
ANCHOR_LOG="$CAPDIR/anchors.log"

# Run a PowerShell command in the guest over WinRM (ntlm). $1 = powershell string.
win() {
  ( cd "$HOME/git/canon-megatank-reset" 2>/dev/null && \
    PATH="$ANSVENV:$PATH" ansible canon-win11 -i host/vm-capture/ansible/inventory.yml \
      -m ansible.windows.win_shell -a "$1" 2>&1 )
}
wincopy() { # $1 = local guest-win file (on neo? no — on mbp-13 repo), $2 = dest in guest
  ( cd "$HOME/git/canon-megatank-reset" 2>/dev/null && \
    PATH="$ANSVENV:$PATH" ansible canon-win11 -i host/vm-capture/ansible/inventory.yml \
      -m ansible.windows.win_copy -a "src=$1 dest=$2" 2>&1 )
}

cmd="${1:-help}"; shift || true
mkdir -p "$CAPDIR"

case "$cmd" in
preflight)
  echo "== usbmon module =="; /usr/sbin/lsmod | grep -q usbmon && echo loaded || echo "NOT loaded (capture will modprobe)"
  echo "== dumpcap caps =="; /usr/sbin/getcap "$(command -v dumpcap)"
  echo "== VM =="; $VIRSH list --all | grep -i "$VM" || echo "VM not defined"
  echo "== printer on host =="; lsusb | grep -i 04a9 || echo "NO Canon on bus"
  echo "== 12fe attached to VM? =="; $VIRSH dumpxml "$VM" 2>/dev/null | grep -q "0x12fe" && echo yes || echo "no (run: $VIRSH attach-device $VM $HOSTDEV_SVC --live)"
  echo "== frida staged in guest? =="; win 'Test-Path C:\canon\frida.exe; Test-Path C:\canon\frida-wicreset-hook.js' | tail -3
  ;;

stage)
  # NOTE: win_copy DEST must use FORWARD SLASHES — a backslash before f/n/t/etc.
  # (C:\canon\frida-inject.exe) is parsed as a string escape → "Illegal characters
  # in path". And a single win_shell arg has a ~8KB limit, so big text files are
  # pushed base64-chunked. These are the methods that actually work on this guest.
  R="$HOME/git/canon-megatank-reset/$REPO_GUESTWIN"
  INV="host/vm-capture/ansible/inventory.yml"
  pushtext() { # $1 local file, $2 guest backslash-path (we write via [IO.File], slashes ok)
    local b64; b64=$(base64 -w0 "$1"); local len=${#b64}; local chunk=6000 i=0
    ( cd "$HOME/git/canon-megatank-reset" && PATH="$ANSVENV:$PATH" ansible canon-win11 -i "$INV" \
        -m ansible.windows.win_shell -a "Remove-Item '$2.b64' -EA SilentlyContinue; 'ok'" >/dev/null 2>&1 )
    while [ $i -lt $len ]; do
      ( cd "$HOME/git/canon-megatank-reset" && PATH="$ANSVENV:$PATH" ansible canon-win11 -i "$INV" \
          -m ansible.windows.win_shell -a "Add-Content -Path '$2.b64' -Value '${b64:$i:$chunk}' -NoNewline" >/dev/null 2>&1 )
      i=$((i+chunk))
    done
    ( cd "$HOME/git/canon-megatank-reset" && PATH="$ANSVENV:$PATH" ansible canon-win11 -i "$INV" \
        -m ansible.windows.win_shell -a "\$b=[IO.File]::ReadAllText('$2.b64'); [IO.File]::WriteAllBytes('$2',[Convert]::FromBase64String(\$b)); (Get-Item '$2').Length" 2>&1 | tail -1 )
  }
  echo "pushing hook (base64-chunked) ..."
  pushtext "$R/frida-wicreset-hook.js" 'C:\canon\frida-wicreset-hook.js'
  echo "pushing launcher ..."
  pushtext "$R/run-frida-capture.ps1" 'C:\canon\run-frida-capture.ps1'
  echo "staging frida-inject.exe (host-fetch if absent, win_copy fwd-slash dest) ..."
  FI="$HOME/canon-tool-staging/frida-inject.exe"
  if [ ! -f "$FI" ]; then
    FV="${FRIDA_VER:-17.10.0}"
    curl -fsSL "https://github.com/frida/frida/releases/download/$FV/frida-inject-$FV-windows-x86_64.exe.xz" -o "$FI.xz" && xz -d -f "$FI.xz"
  fi
  ( cd "$HOME/git/canon-megatank-reset" && PATH="$ANSVENV:$PATH" ansible canon-win11 -i "$INV" \
      -m ansible.windows.win_copy -a "src=$FI dest=C:/canon/frida-inject.exe force=yes" 2>&1 | grep -iE "size|changed|failed" | head -2 )
  echo "verify:"
  win 'Write-Output ("frida-inject="+(Test-Path C:/canon/frida-inject.exe)); Write-Output ("hook="+(Test-Path C:\canon\frida-wicreset-hook.js)); Write-Output ("launcher="+(Test-Path C:\canon\run-frida-capture.ps1))' | tail -4
  ;;

anchor)
  EPOCH=$(date +%s.%N)
  echo "ANCHOR_HOST epoch=$EPOCH iso=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) note=${1:-reset-click}" | tee -a "$ANCHOR_LOG"
  ;;

rehearse)
  ts="$(TS)"; label="rehearse-$ts"
  echo "REHEARSAL (no key, no reset) — proving all 3 layers fire."
  /usr/sbin/modprobe usbmon 2>/dev/null || sudo -n /usr/sbin/modprobe usbmon 2>/dev/null || echo "(modprobe usbmon may need the capture sudo)"
  WIRE="$CAPDIR/$label-wire.pcapng"
  setsid dumpcap -i "$USBMON_IF" -w "$WIRE" -q >/tmp/dc-$label.log 2>&1 & echo $! >/tmp/dcpid-$label
  sleep 1.5
  # guest pktmon (built-in) — start a trace
  win 'pktmon start --capture --pkt-size 0 --file-name C:\canon\rehearse-net.etl 2>&1 | Out-String' | tail -3 || true
  # guest frida launch on the staged WICReset (it will spawn the installer/app; we just
  # confirm the hook loads + DeviceIoControl/CreateFile fire on a benign detect)
  win 'powershell -ExecutionPolicy Bypass -File C:\canon\run-frida-capture.ps1 -Launch' | tail -8 || true
  echo ">>> drive a BENIGN action over VNC now (let WICReset detect the printer / read device id). NO key, NO reset. <<<"
  echo ">>> press ENTER here when the benign action is done to stop the rehearsal <<<"
  read -r _
  win 'pktmon stop 2>&1 | Out-String' | tail -2 || true
  kill -INT "$(cat /tmp/dcpid-$label 2>/dev/null)" 2>/dev/null
  sleep 1
  win 'Get-Content C:\canon\frida-events.log -Tail 40 2>$null' | tail -45
  echo "WIRE pcap: $WIRE ($(stat -c%s "$WIRE" 2>/dev/null) bytes)"
  echo "Rehearsal check: frida-events.log should show HOOK_LOADED + DeviceIoControl/CreateFile (or WinUsb_*) lines; the pcap should have URBs to 12fe; pktmon etl should exist."
  ;;

capture)
  ts="$(TS)"; label="wicreset-real-$ts"
  echo "=== REAL INSTRUMENTED CAPTURE ($label) ==="
  echo "Pre-req: printer in SERVICE mode (12fe) + attached to VM; operator has the key ready."
  $VIRSH dumpxml "$VM" 2>/dev/null | grep -q "0x12fe" || { echo "ERROR: 12fe not attached to VM. Attach + retry."; exit 1; }
  /usr/sbin/modprobe usbmon 2>/dev/null || sudo -n /usr/sbin/modprobe usbmon 2>/dev/null || true
  WIRE="$CAPDIR/$label-wire.pcapng"
  echo "[1/3] WIRE: usbmon -> $WIRE"
  setsid dumpcap -i "$USBMON_IF" -w "$WIRE" -q >/tmp/dc-$label.log 2>&1 & echo $! >/tmp/dcpid-$label
  sleep 1.5
  echo "[3/3] NET: guest pktmon -> C:\\canon\\$label-net.etl"
  win "pktmon start --capture --pkt-size 0 --file-name C:\\canon\\$label-net.etl 2>&1 | Out-String" | tail -2 || true
  echo "[2/3] APP: guest frida -> C:\\canon\\frida-events.log"
  win 'powershell -ExecutionPolicy Bypass -File C:\canon\run-frida-capture.ps1 -Launch' | tail -6 || true
  echo
  echo "############################################################"
  echo "# OPERATOR: drive WICReset over VNC now."
  echo "#  1. select the Canon G6020 / service-mode printer"
  echo "#  2. enter the OctoInkjet key, start the reset"
  echo "#  3. JUST BEFORE clicking the final reset, in ANOTHER terminal run:"
  echo "#        scripts/wicreset-instrumented-capture.sh anchor reset-click"
  echo "#  4. WAIT for the SUCCESS window. Do NOT read counter / print / check ink."
  echo "#  5. come back here and press ENTER to stop capture."
  echo "#  6. THEN power-BUTTON the printer off, wait 10s, power on (NOT unplug)."
  echo "############################################################"
  echo ">>> press ENTER after the SUCCESS window (before the power-cycle) <<<"
  read -r _
  echo "stopping captures ..."
  win 'pktmon stop 2>&1 | Out-String' | tail -2 || true
  kill -INT "$(cat /tmp/dcpid-$label 2>/dev/null)" 2>/dev/null
  sleep 1
  "$0" stop "$label"
  ;;

stop)
  label="${1:-}"
  [ -z "$label" ] && { echo "usage: $0 stop <label>"; exit 1; }
  echo "=== pulling artifacts for $label ==="
  # frida events + anchor
  win "Copy-Item C:\\canon\\frida-events.log C:\\canon\\$label-frida.log -Force; Copy-Item C:\\canon\\capture-anchor.txt C:\\canon\\$label-anchor.txt -Force -ErrorAction SilentlyContinue" >/dev/null 2>&1 || true
  # convert pktmon etl -> pcapng in guest (pktmon pcapng built into Win11)
  win "pktmon etl2pcap C:\\canon\\$label-net.etl --out C:\\canon\\$label-net.pcapng 2>&1 | Out-String" | tail -2 || true
  # fetch into the guest's working dir, then win_copy out via fetch
  for f in "$label-frida.log" "$label-anchor.txt" "$label-net.pcapng" "$label-net.etl"; do
    ( cd "$HOME/git/canon-megatank-reset" 2>/dev/null && \
      PATH="$ANSVENV:$PATH" ansible canon-win11 -i host/vm-capture/ansible/inventory.yml \
        -m fetch -a "src=C:\\canon\\$f dest=$CAPDIR/ flat=yes" 2>&1 | tail -1 ) || true
  done
  echo "artifacts in $CAPDIR:"; ls -la "$CAPDIR"/$label* 2>/dev/null
  echo
  echo "NEXT: parse — wire URBs to 12fe (tshark), frida DeviceIoControl/WinUsb lines,"
  echo "and the net pcap for any cloud call around the anchor timestamp. Then the"
  echo "OFFLINE-REPLAY test: replay only the USB control transfers with net unplugged."
  ;;

*) sed -n '2,40p' "$0" ;;
esac
