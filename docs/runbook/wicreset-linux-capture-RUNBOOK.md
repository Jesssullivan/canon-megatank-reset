# WICReset Linux-native capture — INTEGRATED RUNBOOK (G6020 5B00 reset)

**Status:** rig BUILT + verified key-free on all three layers. **NOT turnkey for a
key spend right now** — there is one hard blocker (no way to drive the WICReset GUI
headlessly) and one architectural ceiling (Wine cannot carry the USB transfer at
all). See **§6 Blockers**. This runbook ties the three Linux-native build lanes
into one procedure and states exactly what is automated vs operator-driven.

**Scope.** This is the Linux-native lane. It lives *alongside* (does not replace)
the VM/Frida lane (`scripts/wicreset-instrumented-capture.sh`,
`docs/runbook/wicreset-instrumented-capture-plan.md`). The decisive keyed capture
may run on **either** lane; this doc makes the Linux lane explicit and honest about
its ceiling so the operator picks the right one.

**Goal (unchanged across lanes).** Capture the EXACT USB sequence a real, successful
WICReset reset sends to clear the G6020 absorber (5B00), and answer the make-or-break
question: **is the device-side reset a replayable LOCAL control transfer, or is it
cloud-nonce-gated per reset?**

---

## 0. Lane map — the three build lanes this runbook integrates

| Lane | Artifact (in repo, installed on mbp-13) | Role here |
|---|---|---|
| **A. Wine rig** | `WINEPREFIX=/home/jess/canon-tool-staging/wine-wicreset` (win32), `printerpotty.exe` | launches WICReset GUI; runs its real USBPRINT discovery. **Cannot reach USB** (see §6.A). |
| **B. Linux instrumentation** | `scripts/wicreset-linux-capture.sh` (orchestrator), `docs/runbook/wicreset-linux-instrumentation.md` | the 3-layer capture: usbmon WIRE + strace/ltrace APP + dumpcap NET, single host clock anchor |
| **C. Analysis + encode** | `scripts/parse-wicreset-capture.py`, `src/canon_megatank/ops.py::replay_control_sequence`, `printers/canon-g6020/maintenance.yaml`, `just {parse-capture,read,replay-control}` | pcap → bytes → local-vs-cloud verdict → gated native reset |

**The single orchestrator command for the whole capture is one script with
subcommands** (Lane B):
`scripts/wicreset-linux-capture.sh {preflight | bind | rehearse | anchor | capture | stop}`.
Analysis is `scripts/parse-wicreset-capture.py` (Lane C) +
`just {read,replay-control}`.

---

## 1. Transport recap (what we are capturing — from static RE)

Device in **service mode = `04a9:12fe`** (normal mode `04a9:1865`), single
printer-class iface 0, EP `0x01` OUT / `0x82` IN. The maintenance transport, per
`docs/research/servicetool-v5103-servicemode-reset-re.md`:

| transfer | bmRequestType | bRequest | wValue | wIndex | data | meaning |
|---|---|---|---|---|---|---|
| reset (OUT) | `0x40` vendor | `0x85` | `0x0000` | `0x0000` | `00 03 01 03 07` | absorber reset, idx 0x07 = Main |
| 1284-id (IN) | `0xa1` class | `0x00` | `0x0000` | `0x0000` | — | GET_DEVICE_ID |
| status (IN) | `0xa1` class | `0x01` | `0x0000` | `0x0000` | — | GET_PORT_STATUS |

Framed wire bytes for the reset SEND: **`85 00 00 00 03 01 03 07`** on EP `0x01`,
optionally preceded by a 6-byte preamble `P0 P1 00 00 00 00` whose `P0/P1` are
`00 00` at rest (config-sourced only if the GUI ran `FUN_00412870` earlier — a
real-capture-only unknown). The v5103-derived **bulk** path sends the same payload
but is firmware-GATED (5B00 persists); WICReset uses the **control** path. Whether
that control path is locally replayable or cloud-gated is what the keyed capture
settles.

---

## 2. PRE-FLIGHT (no key, no reset, no hardware touch)

All commands run from **neo** over ssh to **mbp-13**. The HARD RULE for any
non-trivial body: Write it to a local `/tmp/*.sh`, `scp` to mbp-13, run with one
fish-clean call `ssh mbp-13 'bash -lc "bash /tmp/x.sh"'`. The orchestrator
subcommands below are single tokens and are fish-safe to invoke directly.

### 2.1 Substrate check — AUTOMATED

```bash
ssh mbp-13 'bash -lc "bash /home/jess/git/canon-megatank-reset/scripts/wicreset-linux-capture.sh preflight"'
```

Verifies: usbmon interfaces present (builtin — `usbmon0/1/2` already enumerate via
`dumpcap -D`), `dumpcap` caps (`cap_net_admin,cap_net_raw=ep` — **no sudo for
capture**), `04a9:12fe` on the host bus, usblp binding state, wine present
(`wine-10.0`), strace/ltrace, the WICReset binary, egress iface, and Xvfb.

### 2.2 Detach + unbind so a libusb claimant can reach the device — OPERATOR (root via sops)

The device is currently **attached to the libvirt VM** *or* held by **usblp**
(`/dev/usb/lp0`). For ANY libusb-based sender (Lane B strace target, or the Lane C
native replay) to claim iface 0, usblp must be unbound. The `bind` subcommand
detaches from the VM and unbinds usblp; the unbind needs root:

```bash
# From neo (BECOME password via sops; $BECOME_PASSWORD_FILE is set in your shell):
cat "$BECOME_PASSWORD_FILE" | ssh mbp-13 'bash -lc "sudo -S -p \"\" bash /home/jess/git/canon-megatank-reset/scripts/wicreset-linux-capture.sh bind"'
```

Detach is non-root (`virsh --connect qemu:///session detach-device
canon-capture-win11-headless /tmp/hd-svc.xml --live`); the usblp unbind
(`echo -n 1-1:1.0 > /sys/bus/usb/drivers/usblp/unbind`) is the part needing root.
Re-run `preflight` to confirm "usblp not bound". **Printer stays in service mode
(`12fe`); no power-cycle, no physical touch.**

### 2.3 Wine prefix readiness — VERIFIED, but MIND THE PREFIX

WICReset (`printerpotty.exe`) is **PE32 / 32-bit x86**, so it needs a **win32**
prefix. The verified, WICReset-launching prefix is:

```
WINEPREFIX=/home/jess/canon-tool-staging/wine-wicreset   (#arch=win32, wineboot --init done)
```

> **TRAP — do not use the orchestrator's default prefix.** The script defaults to
> `WINEPREFIX=$HOME/.wine-canon-capture`, which on this box is **win64** and will
> not run the 32-bit app correctly. You MUST override `WINEPREFIX` (and the
> matching `WINE`) when invoking `rehearse`/`capture`. See §3.

Launch command proven to start WICReset and drive its real USBPRINT discovery
(headless under Xvfb):

```bash
WINEPREFIX=/home/jess/canon-tool-staging/wine-wicreset WINEARCH=win32 DISPLAY=:101 \
  wine /home/jess/canon-tool-staging/wicreset/printerpotty.exe
# (start Xvfb on a FREE display first: Xvfb :101 -screen 0 1280x1024x24 -nolisten tcp &)
# Add WINEDEBUG=+setupapi,+winebus,+winusb to observe the discovery path.
```

### 2.4 "Does WICReset see the device under Wine?" — **NO (verified), and it cannot**

This is the architectural ceiling, established by live Wine traces. With
`WINEDEBUG=+setupapi`, WICReset runs the exact RE'd discovery path
(`SetupDiGetClassDevsExW {GUID_DEVINTERFACE_USBPRINT}` → enumerate → **zero device
interfaces**) and reaches its "no service mode printer" state. Wine 10.0 has **no
generic USB passthrough** for printer-class/USBPRINT/WinUSB apps: `winebus.sys`
enumerates HID-class only, `winusb.dll` is stubs, and there is **no
`usbprint.sys`** in the store. Confirmed empirically: **zero `VID_04A9` keys** in
`system.reg` after a run. This is not a config/permission miss — **WICReset under
this Wine cannot carry the USB transfer at all.** (Contrast: the device is fully
reachable natively — `cat /sys/bus/usb/devices/1-1/1-1:1.0/ieee1284_id` returns the
Canon 1284 ID right now.)

**Consequence for the keyed capture (critical):** you cannot capture a *real
WICReset USB reset under Wine on this build*, because no USB ever leaves Wine.
WICReset under Wine is useful only to (a) reach the key-entry UI and (b) observe
whether it phones home (the NET layer still works — Wine's network is native). The
**USB reset bytes** must come from one of:
  - the **VM/Frida lane** (`scripts/wicreset-instrumented-capture.sh`) — WICReset in
    a real Windows guest with `04a9:12fe` passed through (USB transfer real), **or**
  - a **Linux-native libusb replay** of the statically-derived control sequence
    (Lane C `just replay-control`) — no WICReset, just the bytes.

The Wine+strace APP layer of Lane B is therefore an instrument for *whatever libusb
traffic Wine does emit*; on this build that is none for the printer. The strace/
ltrace recipes are validated and ready, but they will only have USB content if a
future Wine gains a usbredir/usbprint shim. **Use Lane B's WIRE (usbmon) + NET
(dumpcap) layers, which are transport-agnostic and DO capture, plus the VM lane or
native replay for the actual reset transfer.**

---

## 3. THE INSTRUMENTED CAPTURE

### 3.1 What's AUTOMATED vs OPERATOR

| Step | Who | Detail |
|---|---|---|
| Start usbmon WIRE (`dumpcap -i usbmon1`) | **automated** | `capture` subcommand, no sudo (dumpcap caps) |
| Start egress NET (`dumpcap -i wlp3s0`, DNS+SYN BPF) | **automated** | `capture` subcommand |
| Start Xvfb headless display | **automated** | `capture` subcommand (`:91` default — override to a free one) |
| Launch WICReset under `strace -f` | **automated** | `capture` subcommand |
| **Attach a viewer + drive the GUI** | **OPERATOR** | **BLOCKED — no VNC on host, see §6.B** |
| Select service-mode G6020 in WICReset | **OPERATOR** | needs a visible GUI |
| Enter the OctoInkjet key, begin reset | **OPERATOR** | human controls the key, always |
| Anchor at reset-click | **OPERATOR** | `... anchor reset-click` in another terminal |
| Wait for SUCCESS window (do NOT read counter/print) | **OPERATOR** | per OctoInkjet; reading early burns the key |
| Press ENTER → stop all layers + pull artifacts | **automated** (`stop`) | operator presses ENTER |
| Power-BUTTON off → wait 10s → on (NOT unplug) | **OPERATOR** | the only physical touch, AFTER capture stops |

### 3.2 Rehearse (NO key, NO reset) — prove the rig fires

Run with the **correct win32 prefix overridden in** (the env override is the fix
for the §2.3 trap):

```bash
ssh mbp-13 'bash -lc "WINEPREFIX=/home/jess/canon-tool-staging/wine-wicreset WINE=/home/jess/.nix-profile/bin/wine XVFB_DISP=:101 bash /home/jess/git/canon-megatank-reset/scripts/wicreset-linux-capture.sh rehearse"'
```

Operator drives a BENIGN printer-detect (NO key, NO reset). Pass criteria: WIRE pcap
has URBs to the `12fe` address; NET pcap has DNS/SYNs if WICReset checks in; strace
shows the wine process tree (USB content only if Wine ever opens the device fd — on
this build it does not, per §2.4, which is itself the rehearsal's honest result).
**Already proven benign-positive on each layer independently** (12 URBs to addr 46;
DNS to wic-reset.com/octoinkjet.com + SYN to 85.92.66.218:443;
`libusb_control_transfer` GET_DESCRIPTOR via a pyusb probe).

### 3.3 The real capture (spends one OctoInkjet key — operator-gated)

Pre: printer in **service mode** (`12fe`), detached to host + usblp unbound (§2.2),
operator holds the key, **a working GUI viewer is attached** (§6.B must be fixed
first).

```bash
ssh mbp-13 'bash -lc "WINEPREFIX=/home/jess/canon-tool-staging/wine-wicreset WINE=/home/jess/.nix-profile/bin/wine XVFB_DISP=:101 bash /home/jess/git/canon-megatank-reset/scripts/wicreset-linux-capture.sh capture"'
```

> If WICReset under Wine shows "no service mode printer" (expected on this build,
> §2.4), the keyed USB reset cannot happen under Wine. Switch to the VM lane for the
> USB transfer (`scripts/wicreset-instrumented-capture.sh capture`) — the WIRE+NET
> layers and the analysis pipeline below are identical regardless of which lane
> emits the transfer (single host clock; usbmon sees the VM passthrough too).

Operator steps inside the run are printed by the script (select printer → enter key
→ `anchor reset-click` in another terminal → wait for success → ENTER to stop →
power-button cycle). Anchor command:

```bash
ssh mbp-13 'bash -lc "bash /home/jess/git/canon-megatank-reset/scripts/wicreset-linux-capture.sh anchor reset-click"'
```

All three streams share **one host UTC epoch clock** (no VM/guest skew on the Linux
lane), so correlation is exact: WIRE/NET via `frame.time_epoch`, strace/ltrace via
`-ttt`. The anchor appends `ANCHOR_HOST epoch=… note=reset-click` to
`$CAPDIR/anchors.log`; window each stream `±2 s` around that epoch.

---

## 4. ANALYSIS (Lane C — touches no hardware)

### 4.1 Parse the pcap — AUTOMATED

```bash
# device-address from the GET_DESCRIPTOR enumeration in the capture (e.g. 46):
ssh mbp-13 'bash -lc "cd /home/jess/git/canon-megatank-reset && python3 scripts/parse-wicreset-capture.py captures/<label>-wire.pcapng --device-address 46"'
# machine-readable / replay snippet:
#   ... --json            (for diffing across runs to spot a nonce)
#   ... --replay-snippet  (emits a valid CONTROL_SEQUENCE for the SSOT)
# or: just parse-capture captures/<label>-wire.pcapng --device-address 46
```

Extracts every EP0 control transfer (bmRequestType decoded, bRequest, wValue,
wIndex, wLength, OUT data hex, IN response / 1284 text), flags the
`85 … 00 03 01 03 07` reset frame, and lists bulk frames. Validated on mbp-13
(tshark 4.4.2) against committed fixture
`captures/ctrl-reset-sample-20260601.pcapng.gz`.

### 4.2 Local-vs-cloud — the decisive offline-replay test — OPERATOR-DRIVEN

Run only **after** a real clearing capture is parsed and its sequence pinned in
`maintenance.yaml::absorber_reset.control_sequence`. Full protocol in
`docs/runbook/wicreset-capture-analysis-pipeline.md` §2. Skeleton:

```bash
# 0. baseline:        just read --cmd 0x86 --arg 0x0000
# 1. CUT NETWORK:     sudo nmcli networking off ; sudo tailscale down ; verify ip route empty + ping fails
# 2. REPLAY OFFLINE:  just replay-control            (dry-run, writes nothing)
#                     just replay-control --execute  (gated EP0 control-OUT, NO WICReset)
# 3. OPERATOR:        power-cycle the printer (off, 10s, on)
# 4. READ BACK:       just read --cmd 0x86 --arg 0x0000   (+ eeprom read-back) vs baseline
```

**Verdict:** offline replay clears 5B00 → **LOCAL** (ship native key-free tool).
Offline fails but online WICReset clears → **CLOUD-NONCE-GATED** (diff the vendor
control-OUT across two WICReset `--json` runs via `jq` to locate the variable
nonce). A byte-identical reset OUT across two runs corroborates LOCAL.

### 4.3 Encode into ops — AUTOMATED (gated)

`ops.replay_control_sequence` is implemented and wired (sibling of
`reset_absorber`), behind the **same unchanged gate ladder in order**: UUID
isolation → status must be `verified-captured` (else `ResetNotValidatedError`; also
refuses empty `control_sequence`) → `eeprom_dump_done` → write-budget `charge()` →
caller lockfile. Dry-run is default. Promotion (after a LOCAL verdict): paste
`--replay-snippet` into `maintenance.yaml::control_sequence`, set
`control_sequence_captured_at` + `control_sequence_offline_verified: true`, promote
`status: verified-captured`, `just test` (87 passed / 11 tshark-skipped on neo),
then `just replay-control --execute` passes against the locked unit.

---

## 5. SINGLE ORCHESTRATOR COMMAND(S) — quick reference

```bash
# one script, all capture phases (override WINEPREFIX/WINE/XVFB_DISP as in §3):
scripts/wicreset-linux-capture.sh preflight        # substrate (automated)
scripts/wicreset-linux-capture.sh bind             # detach+unbind (operator, root via sops)
scripts/wicreset-linux-capture.sh rehearse         # no-key dry run (automated + operator detect)
scripts/wicreset-linux-capture.sh capture          # real run (automated layers + operator key/reset)
scripts/wicreset-linux-capture.sh anchor reset-click   # operator, at the click
scripts/wicreset-linux-capture.sh stop <label>     # stop + pull (automated)

# analysis (Lane C):
scripts/parse-wicreset-capture.py captures/<label>-wire.pcapng --device-address <N>
just read --cmd 0x86 --arg 0x0000                  # baseline / read-back
just replay-control [--execute]                    # offline replay (gated)
```

---

## 6. CRITICAL ASSESSMENT — is this turnkey for a key spend NOW? **NO.**

The rig is **built and verified key-free** on every layer that can be proven without
a key. It is **not turnkey for a keyed reset right now** for two reasons — one
architectural ceiling and one fixable blocker — plus housekeeping items.

### A. ARCHITECTURAL CEILING (not a blocker to fix — a lane choice)
**Wine on this build cannot carry the USB reset transfer.** Wine 10.0 has no
USBPRINT/WinUSB passthrough; WICReset reaches discovery and finds zero devices
(verified: zero `VID_04A9` in `system.reg`, no `usbprint.sys`). So a *real WICReset
USB reset under Wine* is impossible here. This is by design of the build, confirmed
live, and **not patchable by config**. **FIX / DECISION:** drive the actual keyed
USB transfer via **either** the VM/Frida lane (real Windows guest, `12fe` passed
through) **or** the Linux-native libusb replay (`just replay-control`, no WICReset).
The Wine lane contributes the NET (phone-home) signal and the GUI/key-entry surface
only. **This is the single most important thing to understand before spending a
key on the Linux lane: the Linux lane's "WICReset drives the reset" step does not
work; its capture/analysis layers do.**

### B. HARD BLOCKER (fixable) — no way to drive the headless GUI
The operator must *see and click* WICReset to select the printer, enter the key, and
click reset. The script starts **Xvfb (headless, invisible)** but the host has **no
VNC server** (`x11vnc`, `Xvnc`, `vncdo` all absent) and no attached display.
**Right now there is no path for the operator to interact with the GUI**, so the
key-entry/reset step cannot be performed on the Linux lane at all.
**FIX (pick one):**
  - install `x11vnc` and point it at the Xvfb display, then VNC in over the tailnet
    (`x11vnc -display :101 -localhost -rfbport 5900 &` + ssh tunnel), or
  - run wine against a **real X display** the operator can already reach (replace
    `Xvfb`/`DISPLAY` with the operator's session), or
  - use the **VM lane**, which already has a documented VNC drive path
    (`vncdo -s 127.0.0.1:0` + USB tablet) and a real USB transport — the recommended
    route for the keyed capture today.

### C. WINEPREFIX MISMATCH (fixable now, in this doc)
The orchestrator defaults to `WINEPREFIX=$HOME/.wine-canon-capture` which is
**win64**; WICReset is 32-bit and needs the **win32** prefix at
`/home/jess/canon-tool-staging/wine-wicreset`. **FIX:** always invoke
`rehearse`/`capture` with `WINEPREFIX=/home/jess/canon-tool-staging/wine-wicreset
WINE=/home/jess/.nix-profile/bin/wine` overridden (shown in §3). A follow-up should
change the script defaults to the verified win32 prefix.

### D. USB PERMS / usblp (fixable, root via sops)
The device is held by **usblp** (`/dev/usb/lp0`) right now; a libusb claimant
(native replay, or a future Wine with passthrough) needs it unbound. The raw usbfs
node is already group-accessible to `jess` (no sudo for the *read* probes), but the
**unbind needs root** — run `bind` via the sops BECOME password (§2.2). Not a
blocker for usbmon WIRE or NET capture (those need no claim), only for any
interface-claiming sender.

### E. DISPLAY NUMBER COLLISION (minor)
`:99` was taken in a prior session and the script default `:91` may collide.
**FIX:** pass `XVFB_DISP=:101` (free, used in the verified launch) as in §3.

### Bottom line
- **Build lanes: DONE and verified, no key spent.** usbmon WIRE, dumpcap NET, and
  strace/ltrace APP recipes all proven against the live `04a9:12fe`; parser, ops
  encoder, and offline-replay test all wired and green; printer untouched and still
  in service mode.
- **Keyed capture: NOT turnkey on the Linux/Wine lane** because (A) Wine can't carry
  the USB reset and (B) there's no GUI viewer. The **VM/Frida lane is the turnkey
  route for the actual keyed USB capture today**; the Linux lane is turnkey for
  everything *except* WICReset-driving-the-USB-reset, and is the right home for the
  **offline-replay LOCAL-vs-CLOUD verdict** once any clearing sequence exists.
