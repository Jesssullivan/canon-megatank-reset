# VM capture lane — ground-truth the Canon reset handshake (Lane B)

**Why:** our native tool's group-7 payload SEND was ACKed by the real G6020 but
5B00 persisted — the reset needs the **session-open handshake** the Windows
Service Tool runs first (open → init → 6-byte preamble → payload; see
`docs/runbook/live-reset-write-2026-05-31.md`). Static RE (Lane A) is
reconstructing it; this lane **captures it from the wire** — definitive
ground-truth we replay verbatim, and a cross-check against Lane A.

**Why a VM (not Wine):** Wine cannot surface USB to the Windows tool (T1 finding,
`docs/research/wicreset-wine-passthrough.md`). A real Win11 guest with
**`<hostdev>` USB passthrough** drives the printer natively — exactly what Wine
couldn't. Host-side `usbmon` still sees the bus traffic, so we capture without
needing in-guest USBPcap (though that works too).

## Host facts (mbp-13, verified 2026-05-31)
- `qemu:///session` libvirt works **without root** (system mode needs polkit);
  emulator `/usr/libexec/qemu-kvm`, libvirt 11.5.0.
- OVMF UEFI present: `/usr/share/edk2/ovmf/OVMF_CODE.fd` + `OVMF_VARS.fd`.
- `/dev/kvm` present; `/home` has 767G free (staging lives here — NOT neo's
  99%-full root).
- Win11 ISO staged: `~/canon-tool-staging/iso/Win11_25H2_English_x64_v2.iso`.
- G6020 `04a9:1865` on bus 001; usbmon + dumpcap available (canon_tool_dev role).

## One-time setup (~1 hr, interactive — the only hands-on part)
```sh
# on mbp-13, in the repo:
scripts/vm-capture.sh setup      # create qcow2 + NVRAM, define the session domain
scripts/vm-capture.sh install    # boot with the ISO; connect SPICE + install Win11
# in the guest: install the Canon G6020 Windows driver, then copy in the
# Service Tool (ServiceTool_v5302+ that supports G6020) OR WICReset.
scripts/vm-capture.sh snapshot clean-installed
```
USB-passthrough note: the managed `<hostdev>` grabs the G6020 from the host when
the VM starts and hands it back on stop. While the VM holds it, host CUPS/ipp-usb
can't use it — expected; `detach`/stop restores it.

If Win setup can't see the virtio disk, drop `virtio-win.iso` into `iso/` and
attach it (see the XML comment), or temporarily switch the disk bus to `sata`.

## The capture (the payoff)
```sh
# host-side usbmon capture wrapping ONE guest-driven reset:
scripts/vm-capture.sh capture reset-handshake
#   -> in the guest, run a single full reset in the Service Tool / WICReset
#   -> Ctrl-C when it completes
# extract the bulk-OUT/IN frames in order:
tshark -r ~/canon-tool-staging/captures/reset-handshake-*.pcapng \
  -Y 'usb.transfer_type==0x03 and usb.endpoint_address in {0x03 0x86}' \
  -T fields -e frame.number -e usb.endpoint_address -e usb.capdata
```
That ordered list IS the handshake: every `0x03` (OUT) frame from session-open
through the `[85 00 00][00 03 01 03 07]` payload, plus any `0x86` (IN) replies.

## After capture
1. Pull the pcap to neo: `just capture-sync` (or scp). Parse with `just analyze`.
2. Encode the recovered sequence into the native tool's reset path (prepend the
   open/preamble frames before the payload SEND in `ops.reset_absorber`).
3. **Cross-check vs Lane A** (`servicetool-v5103-reset-handshake.md`): agreement
   ⇒ high confidence; divergence ⇒ Lane A reconstruction had a gap (the capture
   wins — it's ground truth).
4. Re-run the live reset (`just reset --execute --accept-derived`) with the full
   sequence; power-cycle; confirm 5B00 clears → promote SSOT
   `derived-unvalidated → verified-captured`.

## Scope / safety
- WICReset reset spends the single-use key — prefer the **Service Tool** for the
  capture if it supports G6020 (no key). Either way it's the dedicated debug unit.
- Captures are gitignored (our own bytes). The Win11 qcow2/ISO stay on mbp-13
  (not committed).
