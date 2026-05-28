# Runbook — canon-tool R2 QEMU+Win11 spike (parallel to R1)

The R2 spike runs Canon Service Tool inside a **real Windows 11 VM** on
mbp-13 (qemu-kvm + libvirt), with the G6020 USB device **passed through**
to the guest. This is the cleanest possible USB trace — Canon's actual
Windows driver stack interpreting the protocol natively, with USBPcap
capturing inside the guest.

R2 is **run in parallel with R1** (the Wine spike). Whichever yields a
cleaner trace becomes the primary evidence source; the other is the
differential cross-check. Don't choose one over the other up front.

## When to use R2 over R1

- R1 (Wine) is failing: Service Tool crashes, USB doesn't enumerate, or
  the trace looks corrupted/incomplete.
- The hypothesis we're testing requires Windows-native behavior we can't
  simulate (DRM-wrapped binaries like v6310, ABI-sensitive features).
- We want differential cross-check evidence to confirm a captured
  sequence isn't a Wine artifact.

## Prerequisites (already in place from canon_tool_dev role)

- ✅ qemu-kvm + libvirt-daemon-kvm + virt-install + virt-manager installed
- ✅ libvirtd service running
- ✅ /dev/kvm present + accessible
- ✅ edk2-ovmf installed (for Win11 UEFI boot)
- ✅ G6020 enumerated at USB `04a9:1865` on bus 001

## Setup (one-time, ~1 hour with downloads)

### Step 1 — Stage Win11 ISO on mbp-13

The Win11 ISO lives on mbp-13 (moved from neo on 2026-05-28 to free
neo disk space — neo was at 99%). Current path:

```
mbp-13:~/canon-tool-staging/iso/Win11_25H2_English_x64_v2.iso
```

If the ISO is missing (e.g. wiped during a /home rebuild), re-acquire
from `https://www.microsoft.com/software-download/windows11` and stash
back into the same path. SHA256 is pinned in
`printers/canon-g6020/maintenance.yaml::win11_iso.sha256`.

### Step 2 — Create the libvirt domain XML

`libvirt-daemon-kvm` ships `virt-install` which scripts most of this.
But for USB passthrough we need explicit `<hostdev>` config. Template:

```xml
<!-- ~/canon-tool-staging/canon-tool-win11.xml -->
<domain type='kvm'>
  <name>canon-tool-win11</name>
  <memory unit='GiB'>8</memory>
  <vcpu>4</vcpu>
  <os firmware='efi'>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
    <boot dev='cdrom'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <hyperv><relaxed state='on'/><vapic state='on'/></hyperv>
    <vmport state='off'/>
    <smm state='on'/>     <!-- required for UEFI -->
  </features>
  <cpu mode='host-passthrough'/>
  <devices>
    <emulator>/usr/libexec/qemu-kvm</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/home/jess/canon-tool-staging/canon-tool-win11.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/home/jess/canon-tool-staging/iso/Win11_24H2_English_x64.iso'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <graphics type='spice' autoport='yes'/>
    <video><model type='qxl'/></video>
    <!-- CANON G6020 PASSTHROUGH — this is the whole point of R2 -->
    <hostdev mode='subsystem' type='usb' managed='yes'>
      <source>
        <vendor id='0x04a9'/>
        <product id='0x1865'/>
      </source>
    </hostdev>
  </devices>
</domain>
```

Then:

```sh
ssh mbp-13
cd ~/canon-tool-staging
sudo qemu-img create -f qcow2 canon-tool-win11.qcow2 60G
virsh --connect qemu:///system define canon-tool-win11.xml
virsh --connect qemu:///system start canon-tool-win11
virt-viewer canon-tool-win11    # opens SPICE viewer
```

### Step 3 — Install Win11 (Spice viewer, ~30 min)

Standard Win11 setup. Key things:

- During OOBE, when prompted for a Microsoft account: hit Shift+F10 to
  open a cmd prompt, run `OOBE\BYPASSNRO`, reboot, then choose "I don't
  have internet" to skip the account.
- After install, eject the ISO from `virsh` so it doesn't reboot from CD:
  `virsh --connect qemu:///system change-media canon-tool-win11 sda --eject`
- Install spice-guest-tools inside the VM for smoother SPICE redirection.
- Skip Windows Updates for now — we want a deterministic baseline.

### Step 4 — Install Canon driver + Service Tool inside the guest

1. Download Canon's official G6020 Windows driver (`G6000-series-...-MAS.exe`)
   from `https://www.usa.canon.com/support/p/pixma-g6020` — that gives you
   the proper driver stack so the Service Tool actually recognizes the
   printer.
2. Transfer `ServiceTool_v5103.exe` (or v6310 if we trust it; see ADR 0007)
   into the VM via shared folder OR copy/paste through SPICE.
3. Install **USBPcap** from `desowin.org/usbpcap/` — captures USB inside
   Windows, exports pcapng.

### Step 5 — Confirm G6020 passthrough works

In the Win11 guest:

- Device Manager → should show the Canon G6020 under "Printers" or "USB".
- Canon's driver should bind to it.
- The CUPS / ipp-usb path on the host is REPLACED while the VM holds the
  device — `ipp-usb` on the host will fail to bind. That's expected. The
  print queue `office` will be temporarily unavailable. Restore by
  detaching from the VM:

  ```sh
  # When done with R2 work, hand the device back to the host:
  virsh --connect qemu:///system detach-device canon-tool-win11 \
    /dev/stdin <<<'<hostdev mode="subsystem" type="usb"><source><vendor id="0x04a9"/><product id="0x1865"/></source></hostdev>'
  ```

## R2 capture sequence

### Step 1 — Start USBPcap inside the Win11 guest

```cmd
# Open elevated Command Prompt
"C:\Program Files\USBPcap\USBPcapCMD.exe" -d \\.\USBPcap1 -o C:\Users\jess\v5605-attempt-1.pcap
```

USBPcap monitor numbers depend on enumeration order. Use `USBPcapCMD.exe -d` (no args)
to list available USB roots; the one with the G6020 attached is the right one.

### Step 2 — Launch Service Tool in the guest

The version matters:

- **v5103** — what we have. Same hypothesis as R1 (G3010 mode).
- **v5302+** — if you have a clean source (or accept the DRM-wrapped
  v6310-datvietcomputer with caveats). Explicit G6020 support.

Open Service Tool → select G6020 (if v5302+) or G3010 (if v5103) →
maintenance → Ink Absorber Counter Clear → Set.

### Step 3 — Stop USBPcap + export

Ctrl-C the USBPcapCMD. The `.pcap` lands in `C:\Users\jess\`. Move it to
the shared folder or copy/paste via SPICE back to the host.

### Step 4 — Cross-check with R1

If both R1 and R2 yielded a successful absorber reset:

```sh
# Diff the bulk-OUT packet byte sequences
ssh mbp-13 'tshark -r ~/canon-tool-staging/captures/v5103-g3010-mode-r1.pcapng \
  -Y "usb.transfer_type == 0x03 and usb.endpoint_address.direction == 0" \
  -T fields -e data > /tmp/r1-bulk-out.hex'
ssh mbp-13 'tshark -r ~/canon-tool-staging/captures/v5103-g3010-mode-r2.pcapng \
  -Y "usb.transfer_type == 0x03 and usb.endpoint_address.direction == 0" \
  -T fields -e data > /tmp/r2-bulk-out.hex'
ssh mbp-13 'diff /tmp/r1-bulk-out.hex /tmp/r2-bulk-out.hex'
```

If R1 and R2 byte streams match exactly → Wine isn't artifacting; the
sequence we captured is the genuine Canon protocol. **Lock it.**

If they diverge → R2's byte stream is canonical (Windows-native is the
reference); R1 may have Wine-specific artifacts (USB endpoint mapping,
timing) we need to account for in the Python replay.

## State management

- The Win11 VM persists between sessions. After R2 captures, shut it
  down to free the G6020 back to the host (so CUPS + ipp-usb work).
- The qcow2 disk image is in `~/canon-tool-staging/canon-tool-win11.qcow2`.
  Snapshot before any Service Tool experiment:

  ```sh
  virsh --connect qemu:///system snapshot-create-as canon-tool-win11 \
    pre-attempt-$(date -u +%Y%m%d-%H%M%S)
  ```

  Roll back if needed:

  ```sh
  virsh --connect qemu:///system snapshot-revert canon-tool-win11 <name>
  ```

## Risks / rollback

- **USB passthrough acquisition contention:** While the VM holds the
  G6020, the host can't print to it. Plan around the office CUPS queue
  being down for the duration of R2 sessions. Detach when done.
- **VM crashes during write:** A crash mid-EEPROM-write could corrupt
  the printer EEPROM. Take a printer EEPROM dump BEFORE any write
  attempt (Phase A `eeprom.py` once we have it). Until then, accept the
  test unit risk per the canon-tool sub-initiative plan.
- **Win11 reboots itself:** Disable Windows Updates inside the guest to
  avoid mid-capture reboots. Set "active hours" to 24h.
