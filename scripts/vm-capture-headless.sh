#!/usr/bin/env bash
# Lane B headless orchestration — fully-unattended Win11 capture VM.
# Layers: (1) autounattend ISO installs Win + enables WinRM; (2) Ansible/WinRM
# provisions driver+tool; (3) PowerShell UIAutomation drives the reset; host-side
# usbmon captures the handshake. See host/vm-capture/README.md.
#
# Subcommands:
#   build-iso   assemble the autounattend ISO (xorriso) from host/vm-capture/unattend
#   define      define a HEADLESS domain (no graphics) with the unattend CD + a
#               WinRM hostfwd (host 55985 -> guest 5985)
#   install     start headless; Win installs unattended + enables WinRM (~15-25m)
#   wait-winrm  block until guest WinRM answers on 127.0.0.1:55985
#   provision   ansible-playbook over WinRM (driver + tool + reset script)
#   capture     host-side usbmon + drive ONE reset in the guest via Ansible/PS
#   all         build-iso -> define -> install -> wait-winrm -> provision  (then `capture`)
#   status|destroy
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo ~/git/canon-megatank-reset)"
STG="${CANON_STAGING:-$HOME/canon-tool-staging}"
VMDIR="$ROOT/host/vm-capture"
VM="canon-capture-win11-headless"
VIRSH="virsh --connect qemu:///session"
DISK="$STG/${VM}.qcow2"
UNATTEND_ISO="$STG/iso/autounattend.iso"
WIN_ISO="$STG/iso/Win11_25H2_English_x64_v2.iso"
WINRM_HOST_PORT="${WINRM_HOST_PORT:-55985}"
USBMON_IF="${USBMON_IF:-usbmon1}"

cmd="${1:-help}"; shift || true

case "$cmd" in
build-iso)
  mkdir -p "$STG/iso"
  echo "building autounattend ISO -> $UNATTEND_ISO"
  # Label OEMDRV-style so Windows setup auto-finds autounattend.xml at the root.
  xorriso -as mkisofs -J -r -V CANONUNATTEND -o "$UNATTEND_ISO" "$VMDIR/unattend/"
  echo "OK"
  ;;
define)
  mkdir -p "$STG/captures"
  [ -f "$DISK" ] || qemu-img create -f qcow2 "$DISK" 64G
  [ -f "$STG/${VM}_VARS.fd" ] || cp /usr/share/edk2/ovmf/OVMF_VARS.fd "$STG/${VM}_VARS.fd"
  # Build a headless variant of the domain XML: no <graphics>/<video>, add the
  # unattend CD as a 2nd cdrom, and a qemu commandline hostfwd for WinRM.
  python3 - "$VMDIR/canon-capture-win11.xml" "$STG/${VM}.xml" "$HOME" "$VM" \
            "$UNATTEND_ISO" "$WINRM_HOST_PORT" <<'PY'
import sys, xml.etree.ElementTree as ET
src,dst,home,name,unattend,winrm = sys.argv[1:7]
ns='http://libvirt.org/schemas/domain/qemu/1.0'
# libvirt REQUIRES the 'qemu:' prefix (not ElementTree's default ns0:).
ET.register_namespace('qemu', ns)
raw = open(src).read().replace("HOME_ABS", home)
t = ET.ElementTree(ET.fromstring(raw)); r = t.getroot()
r.find('name').text = name
# point disk + nvram at the headless VM's files
for d in r.iter('disk'):
    s = d.find('source')
    if s is not None and s.get('file','').endswith('canon-capture-win11.qcow2'):
        s.set('file', f"{home}/canon-tool-staging/{name}.qcow2")
nv = r.find('./os/nvram');
if nv is not None: nv.text = f"{home}/canon-tool-staging/{name}_VARS.fd"
dev = r.find('devices')
# drop graphics/video + any spice-dependent channels (headless: no spice)
for tag in ('graphics','video'):
    for e in dev.findall(tag): dev.remove(e)
for ch in dev.findall('channel'):
    tgt = ch.find('target')
    if ch.get('type') == 'spicevmc' or (tgt is not None and 'spice' in (tgt.get('name') or '')):
        dev.remove(ch)
# add unattend CD as a 2nd cdrom (sdb)
cd = ET.SubElement(dev,'disk',{'type':'file','device':'cdrom'})
ET.SubElement(cd,'driver',{'name':'qemu','type':'raw'})
ET.SubElement(cd,'source',{'file':unattend})
ET.SubElement(cd,'target',{'dev':'sdb','bus':'sata'})
ET.SubElement(cd,'readonly')
# WinRM port-forward: host:WINRM -> guest:5985. Use libvirt's NATIVE
# <portForward> on the EXISTING user interface (NOT a 2nd raw -netdev, which qemu
# rejects as a duplicate and crashes the monitor). libvirt 11.5 supports this.
iface = dev.find("interface[@type='user']")
pf = ET.SubElement(iface, 'portForward', {'proto':'tcp'})
ET.SubElement(pf, 'range', {'start':str(winrm), 'to':'5985'})
t.write(dst, xml_declaration=True, encoding='unicode')
print("wrote", dst)
PY
  $VIRSH define "$STG/${VM}.xml"
  echo "defined $VM (headless). Next: $0 install"
  ;;
install)
  echo "starting $VM headless — Win11 installs unattended (~15-25m), then WinRM."
  $VIRSH start "$VM"
  echo "watch progress: $0 wait-winrm"
  ;;
wait-winrm)
  echo "waiting for guest WinRM on 127.0.0.1:${WINRM_HOST_PORT} (up to ~40m)..."
  for i in $(seq 1 160); do
    if (exec 3<>/dev/tcp/127.0.0.1/${WINRM_HOST_PORT}) 2>/dev/null; then
      exec 3>&- 3<&-; echo "WinRM port open ✓ (attempt $i)"; exit 0
    fi
    sleep 15
  done
  echo "timed out waiting for WinRM"; exit 1
  ;;
provision)
  cd "$VMDIR/ansible"
  echo "ansible provision over WinRM ..."
  ansible-galaxy collection install ansible.windows community.windows pywinrm 2>/dev/null || true
  ansible-playbook -i inventory.yml provision.yml
  ;;
capture)
  label="${1:-reset-handshake}"; ts="$(date -u +%Y%m%d-%H%M%S)"
  out="$STG/captures/${label}-${ts}.pcapng"
  echo "host usbmon capture -> $out ; then driving reset in guest via Ansible"
  dumpcap -i "$USBMON_IF" -w "$out" -q & CAP=$!
  sleep 2
  cd "$VMDIR/ansible"
  ansible canon-win11 -i inventory.yml -m ansible.windows.win_shell \
    -a 'powershell -ExecutionPolicy Bypass -File C:\canon\drive-reset.ps1 -Tool servicetool' || true
  sleep 3; kill "$CAP" 2>/dev/null || true; wait "$CAP" 2>/dev/null || true
  echo "capture: $out"
  ;;
all)
  "$0" build-iso && "$0" define && "$0" install && "$0" wait-winrm && "$0" provision
  echo "provisioned. Run: $0 capture   (and pull/parse the pcap)"
  ;;
status) $VIRSH list --all | grep -i "$VM" || echo "not defined" ;;
destroy) $VIRSH destroy "$VM" 2>/dev/null || true; $VIRSH undefine "$VM" --nvram 2>/dev/null || true ;;
*) sed -n '2,20p' "$0" ;;
esac
