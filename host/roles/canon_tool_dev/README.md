# role: canon_tool_dev

Capture + reverse-engineering environment for the `canon-tool` sub-initiative
(see `docs/adr/0007-canon-tool-reverse-engineering.md`). Installs everything
needed to run a Canon Service Tool EXE under Wine on `mbp-13`, capture USB
traffic via `tshark` + `usbmon`, and (optionally) run a Windows VM in
QEMU/KVM for the parallel R2 capture path.

This role is **dev-only**. It does not run on production hosts and is not
part of `site.yml`. Invoke via `host/playbooks/canon-tool-dev.yml`.

## What it installs

| Layer | Packages | Repo |
| --- | --- | --- |
| QEMU/KVM (R2 capture path) | `qemu-kvm`, `qemu-img`, `libvirt-daemon-kvm`, `libvirt-client`, `virt-install`, `virt-manager`, `edk2-ovmf` | AppStream / CRB |
| USB capture (R1+R2) | `wireshark`, `wireshark-cli` (tshark), `libpcap` | AppStream |
| Python USB client (Phase A) | `python3-pyusb`, `libusb1-devel`, `libusb-compat-0.1` | AppStream / EPEL |
| Archive handling | `p7zip`, `p7zip-plugins` (Service Tool ZIPs use AES) | EPEL |
| Wine (R1 capture path) | `wine` (or `wine-staging` via param) | Winehq third-party repo (added by this role) |

## What it configures

- **Tailscale GPG key import** — bypasses the interactive prompt that was
  blocking `dnf` queries (see ADR 0007 for the saga).
- **Winehq repo** — adds `/etc/yum.repos.d/winehq.repo` pointing to
  CentOS 9 (RHEL-9 ABI; Rocky 10 compatible). Configurable via
  `canon_tool_dev_wine_repo_centos_version`.
- **`usbmon` kernel module** — autoload via `/etc/modules-load.d/usbmon.conf`,
  required for `tshark -i usbmonN` capture.
- **udev rule** for Canon G-series — `/etc/udev/rules.d/50-canon-g6020.rules`
  grants `MODE=0660 GROUP=printstack` to USB devices matching
  `idVendor=04a9`, so a non-root service can open the bulk endpoint.
- **`printstack` group** — created if missing; user added with supplementary GID.
- **`wireshark` group** — required for non-root `tshark` capture; user added.
- **`libvirt` service** — enabled + started (for R2 only; idempotent).

## What it does NOT do

- Does not install Canon Service Tool EXEs (acquire separately; SHA-pinned in
  `printers/canon-g6020/maintenance.yaml`).
- Does not install Ghidra (user has it via Nix Home Manager on `neo`).
- Does not configure the actual `canon-tool` Python service — that's a
  separate role (`canon_tool`, to be created once protocol bytes are captured).

## Invocation

```sh
# Standalone (preferred during R1/R2 dev):
cd host
ansible-playbook -i inventory/hosts.yml playbooks/canon-tool-dev.yml

# Or via the Justfile (canon-tool branch):
just canon-dev-setup
```

The role is idempotent and safe to re-run.

## Verification

```sh
# On the target host after a successful run:
which wine                                       # /usr/bin/wine
modprobe -n -v usbmon                            # insmod /lib/modules/.../usbmon.ko
ls /dev/usbmon*                                  # /dev/usbmon0 ... /dev/usbmonN
groups jess | tr ' ' '\n' | grep -E 'wireshark|printstack'
ls -la /etc/udev/rules.d/50-canon-g6020.rules
sudo udevadm trigger && sleep 1
ls -la /dev/bus/usb/001/$(lsusb -d 04a9: | awk '{print $4}' | tr -d :)  # mode 0660, group printstack
```

When all green, the R1 cheap-spike is ready to run.
