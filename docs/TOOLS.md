# TOOLS — the RE trifecta that cracked the Canon G6020 5B00 reset

This is the complete, reproducible enumeration of the **reverse-engineering
tooling** used to recover the Canon MegaTank G6020 waste-ink ("5B00 ink absorber
full") reset protocol. It is the *workbench* inventory — the capture rig, the
decompiler rig, the instrumentation, and the offline analysis utilities — kept
deliberately **separate from the shippable native tool**.

## The two halves of this repo (read this first)

| Half | What it is | Where it lives | Ships? |
|---|---|---|---|
| **Native reset tool** | Linux-first pyusb resetter + safety gates + fleet Ansible | `src/canon_megatank/`, `printers/`, `host/roles/canon_tool_reset/` | **Yes** — this is the product |
| **RE / reference rig** | The trifecta + utils below — captures, decompiles, instruments, analyzes the proprietary oracles | `host/vm-capture/`, `scripts/`, `ghidra/`, `host/roles/canon_tool_dev/` | **No** — RE oracle / reproducibility only |

The proprietary tools (Canon Service Tool, WICReset/PrinterPotty, Canon firmware)
are **RE oracles only** — never redistributed, never a production dependency (see
`AGENTS.md` and `docs/adr/0007-canon-tool-reverse-engineering.md`). Every binary
and capture they touch is gitignored; only the *scripts that drive them* and the
*curated findings* (`docs/research/`) are tracked.

> **The validated result.** The write cipher reproduces WICReset's genuine reset
> frame **23/23 byte-exact**, the reset is **cloud-independent**, and it **cleared
> 5B00 on real hardware** (`docs/runbook/g6020-native-reset.md`,
> `docs/runbook/live-reset-write-2026-05-31.md`). The trifecta below is how that
> ground truth was obtained and cross-checked.

---

## The TRIFECTA at a glance

Three **independent** evidence sources, cross-correlated by wall-clock timestamp
and the deterministic 20-byte payload envelope. No single lane is sufficient;
each anchors the others. The loop is drawn in
[`docs/diagrams/methodology-trifecta.mmd`](diagrams/methodology-trifecta.mmd)
(render with `just diagrams`).

```
  LANE 1 — usbmon        LANE 2 — Frida              LANE 3 — Ghidra
  (host wire truth)      (Win11 VM IOCTL/DRM)        (offline decompile)
  dumpcap -i usbmonN     hook DeviceIoControl,       usbprint.sys IOCTL→URB,
  over 04a9:12fe         patch 3 cloud-DRM gates,    printerpotty.exe netfree
  passthrough            read live keyword           proof, devices.xml cipher
        │                       │                            │
        └──────────────► CORRELATE by timestamp ◄────────────┘
                    + deterministic 20-byte envelope
                                 │
                    VALIDATED NATIVE RESET (pyusb)
```

The substrate under all three lanes is the **Win11 capture VM** with **real USB
passthrough** of the printer, plus the **analysis utilities** that turn raw
captures and decompiles into the verified protocol. Both are enumerated below.

---

## 0. Substrate — the Win11 capture VM (libvirt / qemu IaC)

**What it is.** A throwaway Win11 guest under **session-mode libvirt**
(`qemu:///session`, **no root**) on the capture host **mbp-13** (Rocky Linux 10).
Its entire reason to exist is the `<hostdev>` USB passthrough: Wine cannot surface
USB to the closed Windows tools (`docs/research/wicreset-wine-passthrough.md`), so
a real Win11 guest drives the printer natively while host-side `usbmon` records
the bus. Three IaC layers make it the Windows equivalent of cloud-init.

**Where it lives.** `host/vm-capture/` (see its
[`README.md`](../host/vm-capture/README.md) for the operator walk-through).

| Layer | File(s) | Role |
|---|---|---|
| Domain (interactive/SPICE) | `host/vm-capture/canon-capture-win11.xml` | q35 + OVMF UEFI; `<hostdev>` passes `04a9:1865`/`04a9:12fe` to the guest; SPICE for hand-driving. `HOME_ABS` is substituted to the capture-user home at define time. |
| 1 · Unattended install | `host/vm-capture/unattend/autounattend.xml` | Zero-click Win11 install: TPM/SecureBoot bypass, disk, local admin `cap`, **autologon** (`LogonCount 99`). |
| 1 · WinRM bootstrap | `host/vm-capture/unattend/SetupComplete.cmd` → `ConfigureRemotingForAnsible.ps1` | Enables WinRM in **SYSTEM context before first logon** (the FirstLogon attempt ran on the Public NAT profile and never opened 5985). |
| 2 · Provision (cloud-init) | `host/vm-capture/ansible/provision.yml` + `inventory.yml` | Ansible over **WinRM/NTLM** installs the Canon driver + maintenance tool + stages the reset driver. NTLM seals WS-Man so plain HTTP:5985 works without `AllowUnencrypted`. |
| 3 · Reset driver | `host/vm-capture/win/drive-reset.ps1` | UIAutomation drives the reset GUI **by control name** (discovery-first: `-Dump` prints the control tree), not by pixel. |

**How it is invoked.** All via the Justfile (the single entrypoint):

```sh
just vm-capture-headless all      # build-iso → define → install → wait-winrm → provision
just vm-capture-headless capture  # host usbmon + drive ONE reset via Ansible/PS
# interactive/SPICE fallback:
just vm-capture setup|install|snapshot|capture|start|stop|status|detach
```

The driver scripts: `scripts/vm-capture-headless.sh` (headless: `xorriso`
autounattend ISO → headless domain with a WinRM `hostfwd` 55985→5985 → unattended
install → WinRM wait → `ansible-playbook`) and `scripts/vm-capture.sh`
(SPICE lifecycle). The headless define-step rewrites the domain XML in place
(drops `<graphics>`/`<video>`, adds the unattend CD + the `qemu:commandline`
hostfwd) so one source XML serves both modes.

**Reproduce from scratch (on mbp-13).** Host prerequisites are provisioned by the
`canon_tool_dev` role (§5); the manual one-time gates are documented in the
vm-capture README:

1. `sudo setenforce 0` + persist `SELINUX=permissive` — the **passt** WinRM
   port-forward is blocked by SELinux Enforcing on EL10 (exit 126); permissive
   keeps AVC logging and also clears the USB-passthrough path.
2. Stage (never committed) under `~/canon-tool-staging/`: the Win11 ISO at
   `iso/Win11_25H2_English_x64_v2.iso`, and the Windows payload under
   `win-payload/` (Canon G6020 driver EXE + ServiceTool/WICReset).
3. `just vm-capture-headless all` then `... capture`.

> The managed `<hostdev>` grabs the G6020 from the host when the VM starts and
> hands it back on stop; while held, host CUPS/ipp-usb cannot use it (expected).

Background on why a VM and not Wine, and the spike history:
`docs/runbook/canon-tool-r2-qemu-spike.md`, `docs/runbook/canon-tool-r1-cheap-spike.md`.

---

## 1. Wire capture — usbmon / dumpcap / tshark (Lane 1, host wire ground truth)

**What it is.** The host-side USB bus tap. The Linux `usbmon` kernel module
exposes `/dev/usbmonN`; `dumpcap` records it to `.pcapng`; `tshark`'s USB
dissectors decode URBs. This is the **ground truth** — opaque to no claim, the
arbiter when the static model and the wire disagree (the wire wins).

**Where it lives.**
- Kernel + access: provisioned by `canon_tool_dev` — `usbmon` autoload
  (`host/roles/canon_tool_dev/files/usbmon.modules.conf`), the `usbmon`/`wireshark`
  groups + the udev rule (`files/50-canon-g6020.rules`), and `dumpcap`
  file-capabilities so capture is **unprivileged**.
- Orchestration scripts: `scripts/wicreset-capture.sh` (free read, no key),
  `scripts/r1-capture.sh` (Wine + Service Tool capture with ipp-usb toggle),
  and the wire layer of `scripts/wicreset-instrumented-capture.sh` (the 3-layer
  run; §6 below).

**How it is invoked.**

```sh
just capture-read [label]     # free WICReset "Read waste counters" on mbp-13 (no key)
just capture-sync             # rsync the capture-host pcaps into ./captures/incoming/
# under the hood, on mbp-13:
dumpcap -i usbmon1 -w captures/<label>.pcapng -q
tshark -r captures/<label>.pcapng \
  -Y 'usb.transfer_type==0x03 and usb.endpoint_address in {0x03 0x86}' \
  -T fields -e frame.number -e usb.endpoint_address -e usb.capdata
```

**Device identities to filter on:** `04a9:1865` (normal mode), `04a9:12fe`
("Printer in service mode"). The maintenance transport is **usbprint VENDOR
control on EP0** (`VENDOR_SET` IOCTL `0x220038` = `bmRequestType 0x41` OUT;
`VENDOR_GET` `0x22003c` = `0xC1` IN) — see
[`docs/research/usbprint-vendor-urb-mapping.md`](research/usbprint-vendor-urb-mapping.md)
and the analysis-pipeline runbook
[`docs/runbook/wicreset-capture-analysis-pipeline.md`](runbook/wicreset-capture-analysis-pipeline.md).

**Reproduce.** Apply `just host-apply` (the `canon_tool_dev` role) to mbp-13, log
out/in for group membership, then run a capture script. There is also a
**guest-side** pktmon layer (`pktmon start --capture` → `etl2pcap`) used only to
answer the local-vs-cloud question — see §6.

---

## 2. Decompile rig — Ghidra + pyghidra (Lane 3, offline static RE)

**What it is.** Static reverse engineering of the proprietary binaries to recover
structure the wire can never show: the IOCTL→URB field map, the net-free proof of
the reset subtree, and the write cipher tables. Two engines are used:
**Ghidra `analyzeHeadless`** (Jython 2.7 post-scripts) and **pyghidra** (CPython
driving a saved, analyzed project headless on newer Ghidra).

**Where it lives.** Tracked scripts in `ghidra/` (see its
[`README.md`](../ghidra/README.md)); the binaries + project DB are **gitignored**
under `.ghidra-work/` (no redistribution). Curated findings:
[`docs/research/canon-tool-ghidra-notes.md`](research/canon-tool-ghidra-notes.md)
and the per-topic `docs/research/servicetool-*` / `docs/research/wicreset-*` notes.

**The scripts (what each does):**

| Family | Scripts | Purpose |
|---|---|---|
| Jython post-scripts (Service Tool) | `dump_canon.py`, `dump_strings.py`, `trace_usb.py`, `trace_callers.py`, `vtable_probe.py`, `dump_named_vtable.py`, `find_and_decomp.py`, `parse_dialogs.py`, `find_msgmap.py`, `peek_obj.py` | metadata/RTTI/string dumps; rank+decompile I/O-touching funcs; resolve C++ vtables (defeat virtual dispatch); RT_DIALOG control-ID → MFC `AFX_MSGMAP_ENTRY` handler → wire (the button→wire recipe). |
| v5103 deep-dives | `v5103_servicemode_probe.py`, `v5103_absorber_extract.py`, `v5103_wireresolve.py`, `v5103_read_extract.py`, `v5103_readbody_extract.py`, `v5103_writers.py`, `v5103_innerchain.py`, `v5103_*` | reconstruct the Service Tool service-mode reset handshake + readback codec. |
| pyghidra (CPython) | `pyghidra_xref_decompile.py`, `pyghidra_decompile_xrefs.py`, and the standalone runners under `.ghidra-work/` (`decomp_standalone.py`, `ioctl_scan.py`, `lane2_*`) | byte-search exact strings in the **stripped** `printerpotty.exe`, resolve referencing functions, decompile — recovers `clearCounters`, the cipher chain, the IOCTL sites. |
| WICReset / APP.BIN | `wicreset_resetflow.py`, `wicreset_netmap.py`, `wicreset_decrypt_trace.py`, `wicreset_template_*`, `wicreset_tmplsrc_*`, `wicreset_archive_des.py`, `appbin_extract.py`, `appbin_entropy.py` | trace the reset orchestrator + cloud gates, the APP.BIN decrypt/mount chain, and the embedded `devices.xml` template DB (the cipher tables). |

**How it is invoked.**

```sh
# Ghidra headless harness (binary + project DB gitignored under .ghidra-work/):
WORK=.ghidra-work
HEADLESS=$(dirname $(readlink -f $(which ghidra)))/support/analyzeHeadless
"$HEADLESS" "$WORK/project" canon-servicetool-v5103 \
  -process ServiceTool_v5103.exe -noanalysis \
  -scriptPath ghidra -postScript dump_canon.py "$WORK/out/v5103-report.md"

# pyghidra standalone (reuses the saved analyzed program — analyze=False):
GHIDRA_INSTALL_DIR=<ghidra> CMR_PROJ=.ghidra-work/project \
  CMR_PROG_NAME=printerpotty.exe \
  uv run --no-project --with pyghidra python ghidra/pyghidra_xref_decompile.py out.c "clearCounters,service.sendcmd"
```

The Justfile placeholder `just ghidra <script> <args>` points at this harness
(`ghidra/README.md`); the harness intentionally lives outside `nix develop`
(Ghidra 11.4.2 + JDK 21 + Wine are capture-host tooling, not the dev devShell).

**Reproduce.** Install Ghidra (nix, JDK 21), `rsync` the never-committed binary
from `mbp-13:canon-tool-staging/extracted/`, one-time `-import` for full
auto-analysis (PE + RTTI + decompiler param-id), then re-run any script with
`-process … -noanalysis` against the saved program. Jython 2.7 gotchas (utf-8
header, `getDefinedData` walk) are in `ghidra/README.md`.

---

## 3. Dynamic instrumentation — Frida (Lane 2, Win11 VM IOCTL + DRM)

**What it is.** Runtime hooking of the Windows tools inside the capture VM, to see
the **plaintext** command frame *before* it hits the wire, read the live 3-byte
keyword, and (for the ground-truth capture) force WICReset to emit its **own
genuine reset** with the cloud licensing gates neutralized. Frida bridges what the
static decompile predicts and what the wire records.

**Where it lives.** `host/vm-capture/win/` (the hooks + launchers).

**The tool.** **frida-inject** — the standalone PyInstaller-frozen CLI, **no guest
Python needed**. The proven pin is **`frida-inject-x86-16.exe` v16.5.9** (32-bit,
matching the 32-bit `printerpotty.exe`; image base `0x400000`); the headless
staging script also fetches `frida-inject` 17.x for the 1284/session hooks. Launch
pattern (from the runbooks + script headers):

```
frida-inject-x86-16.exe -f "C:\PROGRA~2\PRINTE~1\PRINTE~1.EXE" \
    -s C:\canon\<hook>.js -R v8 > C:\canon\<log>.log 2>&1
# v16: do NOT use -o; do NOT combine -e with stdout redirect.
# -p <pid> to attach; -R qjs|v8 runtime; -e eternalize (keep script after injector exits).
```

Session-0 vs session-1 matters: WinRM is session 0, but Frida's agent bootstrap
stalls there, so the target is spawned in **interactive session 1** via a
Scheduled Task running as the autologon `cap` user (see `sess1-appbin-dump.ps1`).

**The hooks (`host/vm-capture/win/`):**

| Hook | What it does |
|---|---|
| `frida-1284clamp-hook.js` | **clamp** `nOutBufferSize` 5000→4096 for IOCTL `0x220034` (`GET_1284_ID`). Root cause: `usbprint.sys` (Win11 26100.8328) caps the GET_1284_ID OUT buffer at one page; WICReset's deep read asks 5000 → `ERROR_CRC`. Pure app→kernel arg fix, no driver bind, no key. |
| `frida-session-capture-hook.js` | **session-capture** — merges the clamp (extended to `0x22003c VENDOR_GET`) + a **full** in/out hex trace of every `DeviceIoControl` (raised cap for the tiny vendor frames `0x220038/0x22003c/0x16000c`). Captures the **encrypted series-name read** *before* the key field. **NO key spent.** |
| `frida-drm-reset-hook.js` | **DRM-bypass** — patch 3 cloud gates `JZ(0x74)→JMP(0xEB)` (`0x44012d` RESET_GUID, `0x44054a` QUERY_KEYS, `0x440563` valid-bit; exact for sha256 `a199447db…564b3e8`, with a `0x74` guard that aborts on version drift) so net-free `clearCounters` runs; also `connect()`-replace for instant cloud fast-fail + full VENDOR IOCTL trace. |
| `frida-usbprint-driver.js` | **usbprint-driver** — open the `{28d78fad}` `GUID_DEVINTERFACE_USBPRINT` handle ourselves and issue our **derived functor-3 frames** straight through `VENDOR_SET`/`VENDOR_GET`, bypassing WICReset entirely. usbmon records the exact URB for the native Linux tool to replicate. |
| `frida-wicreset-hook.js` | base app-layer capture: `CreateFile`/`DeviceIoControl` (minidriver path) + `WinUsb_*` (if a build talks WinUSB directly) + `wininet/winhttp/ws2_32` connect tracing (corroborate local-vs-cloud). |
| `appbin-dump.js` | in-memory **cleartext** dump of `printerpotty.exe`'s APP.BIN decrypt/mount/inflate path (hooks the decrypt orchestrator, header-strip, buffer-append, inflate, dotted-path accessor) → raw `.bin` via the Frida File API. NO key, NO device, NO cloud. |

**Launchers / orchestration:** `run-frida-capture.ps1` (guest-side `-Setup`
stage / `-Launch` spawn-under-Frida, writes a wall-clock anchor for pcap
correlation; observational only — the operator enters the key over VNC) and
`sess1-appbin-dump.ps1` (the session-1 Scheduled-Task launcher for the appbin
dump).

**Reproduce.** Bring up the VM (§0), stage `frida-inject` + the hook (the
instrumented-capture script base64-chunks files into the guest over WinRM), then
launch per the pattern above. Evidence trail:
[`docs/runbook/g6020-session-capture.md`](runbook/g6020-session-capture.md),
[`docs/research/wicreset-drm-bypass.md`](research/wicreset-drm-bypass.md),
[`docs/research/wicreset-appbin-container.md`](research/wicreset-appbin-container.md).

---

## 4. GUI drive — VNC + UIAutomation (the human-in-the-loop click)

**What it is.** The reset *click* (and key entry, when WICReset is used) is driven
by the operator, deliberately, so the human controls the single-use key. Two
mechanisms:

- **UIAutomation** (`host/vm-capture/win/drive-reset.ps1`) — invokes controls by
  Name/AutomationId (robust, scriptable). Discovery-first: `-Dump` prints the live
  control tree so selectors can be pinned for the closed-source GUI.
- **VNC / SPICE** — interactive fallback for the one click that UIAutomation can't
  yet pin, and for entering the OctoInkjet key during a WICReset ground-truth run.
  The interactive domain (`canon-capture-win11.xml`) exposes SPICE on `127.0.0.1`;
  on mbp-13 the capture host's headless GUI tooling (`Xvfb`, `xdotool`, `scrot`,
  installed by the `canon_tool_dev` role into the nix profile) supports
  screenshot/automation of the Wine GUI for the free-read path.

This lane is intentionally **the smallest** — Frida is purely observational and
never enters the key; the human does, once, over VNC.

---

## 5. Host provisioning — Ansible role `canon_tool_dev` (the capture/RE env)

**What it is.** The idempotent Ansible role that turns a bare mbp-13 into the
capture + RE workbench. It is **not** the fleet-deploy role (that is
`canon_tool_reset`, which installs the *shippable* native tool — kept separate).

**Where it lives.** `host/roles/canon_tool_dev/` (tasks, defaults, files,
templates, handlers, `README.md`); driven by `host/playbooks/canon-tool-dev.yml`.

**What it provisions:** Wireshark/`libpcap` + `python3-pyusb`/`libusb`; QEMU +
libvirt + `edk2-ovmf` (the VM substrate); **Wine via Flatpak** with `--device=all`
USB + staging-dir access (WinHQ dropped EL RPMs); `usbmon` autoload + the Canon
udev rule; the `printstack`/`wireshark`/`usbmon` group membership + `dumpcap`
caps that make capture unprivileged; a **scoped NOPASSWD sudoers** drop-in
(`ipp-usb` toggle only); and `Xvfb`/`xdotool`/`scrot` into the nix profile for
headless GUI automation.

**How it is invoked.**

```sh
just host-check                 # ansible-playbook --syntax-check (no host contact)
just host-dry                   # --check --diff (shows changes, applies nothing)
just host-apply ['--tags sudo,groups']   # apply to mbp-13 (become pw via $BECOME_PASSWORD_FILE)
```

**Reproduce.** `just host-apply` against mbp-13, then log out/in (or
`newgrp wireshark; newgrp printstack`) for group membership.

---

## 6. Analysis utilities (turn raw captures + decompiles into the verified protocol)

These are **offline, hardware-free** Python utilities (in the dev devShell / a
local `.venv`) that consume the trifecta's raw output and produce the verified
protocol. Each cites its ground truth in `docs/research/`.

| Util | What it does | Ground truth |
|---|---|---|
| `scripts/appbin_decrypt.py` | Decrypt `printerpotty.exe`'s `APP.BIN` container: strip 4-byte footer → **3DES-EDE3-CBC** (zero key, zero IV — empty-wxString construction) → strip PKCS pad → zlib inflate → the `devices.xml` template DB. Self-contained DES (no OpenSSL dep). | `docs/research/wicreset-appbin-cipher.md`, `docs/research/wicreset-appbin-container.md` |
| `scripts/appbin_oracle.py` | Validation oracle + container model for APP.BIN (PE resource offset/size, entropy, block-alignment, the `FUN_00530ae0` mount pipeline). Confirms the decrypt against the static model. | `docs/research/wicreset-appbin-container.md` |
| `scripts/canon_sr5_cipher.py` | The **CANON-SR5** reference cipher + encoder — reproduces the maintenance command-frame transform for the G6000/G6020 family. Reads all substitution tables **directly from the decrypted `devices.xml`** (never hard-codes them); functor-2/3 with the validated SUBJECT/SEED role swap that yields the 23-byte `set_command`. | `docs/research/wicreset-g6020-reset-template.md`, `docs/research/g6020-genuine-setcommand-decode.md` |
| `scripts/g6020_wire_codec_crack.py` | Offline crack of the service-mode **readback** wire codec from a 40-session dataset: `0x84` fully recovered (XOR stream over a constant 20-byte plaintext with a fixed keyword-byte selection table; 40/40 byte-exact); `0x8c` documented as an open nonlinear item. NO device touched. | `docs/research/g6020-wire-codec-crack.md` |
| `scripts/parse-wicreset-capture.py` | The turnkey pcap extractor: pull EVERY EP0 control transfer to/from the service-mode device (`bmRequestType`/`bRequest`/`wValue`/`wIndex`/data + responses) + bulk frames, flag the absorber-reset frame, emit ordered/annotated/`--json`/`--replay-snippet`. Thin wrapper around `tshark`. | `docs/runbook/wicreset-capture-analysis-pipeline.md` |
| `scripts/safe-ping-probe.py` | Read documented-safe baseline (IEEE-1284 device-id, USB descriptors) and emit YAML for `maintenance.yaml::ping_suite_baseline`. No bulk-OUT, no vendor commands, no EEPROM. | `scripts/AGENTS.md` |
| `scripts/experiment-handshake-reset.py` | **Live discriminator** (debug unit only) for Lane A's recovered handshake — sends the candidate session-open→preamble→payload with a few GUESSED runtime bytes. Not production code. | `docs/research/servicetool-v5103-reset-handshake.md` |

**The 3-layer instrumented capture** that fuses the lanes is
`scripts/wicreset-instrumented-capture.sh` (`preflight | stage | rehearse |
capture | anchor | stop`): WIRE (host `usbmon`/`dumpcap`) + APP (guest Frida) +
NET (guest `pktmon`) on **one** reset, with a shared wall-clock anchor so all
three streams correlate to the exact transfer before the EEPROM commit. The
operator drives the key over VNC; the script only instruments, captures, and
pulls artifacts.

**How they are invoked.**

```sh
just analyze <pcap>                  # canon_megatank.pcap model over a capture
just parse-capture <pcap> [--json]   # the annotated control-transfer extractor
just model                           # the formal protocol model + Hypothesis property tests
# offline cipher utils run directly (no hardware), e.g.:
python3 scripts/appbin_decrypt.py <APP.BIN> ; python3 scripts/canon_sr5_cipher.py
```

**Reproduce.** `just setup` (the dev devShell via `direnv`/`nix develop`), then run
the utils; only the pcap extractor (`parse-wicreset-capture.py`) and the live
experiment need the capture host (`tshark` / the printer).

---

## Cross-references

- **RE findings (per protocol claim):** `docs/research/` — start with
  `usbprint-vendor-urb-mapping.md` (transport), `wicreset-g6020-reset-template.md`
  + `g6020-genuine-setcommand-decode.md` (write cipher), `wicreset-drm-bypass.md`
  (cloud-independence), `g6020-wire-codec-crack.md` (readback codec),
  `canon-tool-ghidra-notes.md` (the button→wire decompile recipe).
- **Runbooks (operational evidence):** `docs/runbook/` — `g6020-native-reset.md`
  (the validated native reset, 23/23 byte-exact), `live-reset-write-2026-05-31.md`
  (the hardware clear), `wicreset-capture-analysis-pipeline.md` (capture→encode),
  `g6020-session-capture.md` (the encrypted-session capture, no key),
  `canon-tool-r1-cheap-spike.md` / `canon-tool-r2-qemu-spike.md` (rig spikes).
- **Formal protocol:** `docs/spec/megatank-maintenance-protocol.md` +
  `src/canon_megatank/protocol/model.py` (run `just model`).
- **Diagrams:** `docs/diagrams/` — `methodology-trifecta.mmd` (this loop),
  `exploit-dataflow.dot`, `drm-bypass-controlflow.dot`, `lifecycle.mmd`,
  `maintenance-state-machine.mmd`.
- **Operating contract / ethics:** `AGENTS.md`,
  `docs/adr/0007-canon-tool-reverse-engineering.md`, `ETHICS/`, `INTEROP.md`.
- **Capture-host provisioning:** `host/roles/canon_tool_dev/README.md`;
  **VM rig:** `host/vm-capture/README.md`.
