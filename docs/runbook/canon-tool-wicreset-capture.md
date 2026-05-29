# Runbook — capture WICReset doing the real absorber reset (R-arm: oracle capture)

**Status:** primary byte-recovery path as of 2026-05-29.
**Why this supersedes the gamble:** [TIN-1694](https://linear.app/tinyland/issue/TIN-1694)
(v5103 in *G3010 mode* against the G6020) was a family-protocol **hypothesis**;
the firmware cross-ref ([TIN-1696](https://linear.app/tinyland/issue/TIN-1696))
is **blocked** (G6020 is panel/internet-only and 5B00 locks the panel — chicken
-and-egg; see `docs/research/canon-tool-firmware-sourcing.md`). We now have a
**known-good oracle**: a purchased **WICReset** key (OctoInkjet order ISC69146)
that resets *this* G6020's counter. Capturing WICReset over usbmon gives the
**verified, real** absorber-reset wire bytes against our actual unit — no
hypothesis, no firmware needed. Those bytes replay across the identical fleet.

## What WICReset is

WIC Reset Utility (wicreset.com → operated by OctoInkjet; built by PrinterPotty)
— commercial waste-ink-counter resetter. Talks to the printer **directly over
USB** (select printer → USB). Works while the printer shows **5B00**.
`Read waste counters` is **free**; `Reset` consumes a **single-use key** (one
printer, once) and takes ~2 min.

- **No native Linux binary.** `wicreset.com/download` → octoink.co.uk; the Linux
  entry only meta-refreshes to a forum thread. So on Linux we run the **Windows
  build under Wine** — reusing the exact Flathub Wine + USB-passthrough rig from
  the v5103 work (`/usr/local/bin/wine`, `--device=all` override).
- Staged on mbp-13: `~/canon-tool-staging/wicreset/PrinterPotty_WICReset.exe`
  (3,085,758 bytes, PE32 32-bit GUI,
  `sha256 e5a7929fa9992de081dbb0f798ed758983fc3445c0bbc91a9eafb91fdaadf9ec`,
  from `printerpotty.com/_dlds/wicreset/` via octoink `getwicreset`, 2026-05-29).
- Launch: `wine ~/canon-tool-staging/wicreset/PrinterPotty_WICReset.exe`
- Key (OctoInkjet ISC69146): held by operator — **not committed** to the repo.
- The same EEPROM channel WICReset uses is our interface-4 maintenance lane
  (bulk OUT `0x03` / bulk IN `0x86`), so usbmon sees the exact reset transaction.

> Phase 1 is also the **first real test of Wine USB passthrough** for a maintenance
> op (the v5103 negative-control had zero bulk-OUT). If WICReset can't see the
> printer under Wine, that surfaces immediately — for free, before any key spend.

## Sequencing (IMPORTANT — physical safety)

OctoInkjet's own instruction: **fit the new waste-ink pads / external kit BEFORE
resetting** — a reset lets the printer print again on a physically-full absorber,
which can overflow. The external kit shipped 2026-05-29 (PostNL → Lewiston ME),
so it is days out.

| Phase | When | Key? | Risk |
|---|---|---|---|
| **1 — Read capture** | now | no | none (read-only, no reset) |
| **2 — Reset capture** | after pads/kit installed | **yes** | spends key; printer prints again |

Do Phase 1 now to prove the pipeline and bank the handshake/read protocol. Do
**not** run Phase 2 until the absorber is physically handled.

## One-time host setup (IaC)

The capture runs **unprivileged** — `canon_tool_dev` puts the capture user in the
`usbmon` group (so tshark reads `/dev/usbmonN` via dumpcap's file-capabilities)
and installs a **scoped** `/etc/sudoers.d/canon-capture` (NOPASSWD for *only*
`systemctl stop/start ipp-usb`; lab `roles/common` convention, command-scoped).
Apply once (become password from your store / `ANSIBLE_BECOME_PASSWORD`):

```sh
# become password comes from $BECOME_PASSWORD_FILE (sops-decrypted) or --ask-become-pass
just canon-dev-setup '--tags canon-tool-dev,sudo,groups'
# then re-login (or `newgrp usbmon`) so the usbmon group membership is live
```

After that the capture is fully headless — no sudo prompt, drivable over ssh.

## Phase 1 — free read capture (do now)

On **mbp-13** (printer connected, role applied, in the canon worktree):

```sh
~/git/printstack-canon/services/canon-tool/scripts/wicreset-capture.sh wicreset-read-1
# runs as YOU (not root): pre-flight (fw 1.070) → sudo-stop ipp-usb → tshark → READY
# operator (separate terminal / display): launch WICReset, select the G6020 via
#   USB, click "Read waste counters" (NO key, NO reset). Let it finish.
# stop: press ENTER (TTY)  —or headless—  kill -TERM $(cat ~/canon-tool-staging/.wicreset-capture-wicreset-read-1.pid)
```

Then rsync to neo + analyze:

```sh
rsync mbp-13:~/canon-tool-staging/captures/wicreset-read-1-*.pcapng.gz \
  services/canon-tool/captures/
just canon-analyze services/canon-tool/captures/wicreset-read-1-<TS>.pcapng.gz
```

**Success check:** the pcap must contain bulk-OUT on `0x03` + bulk-IN on `0x86`
(the negative-control launch-no-clicks fixture had **zero** bulk-OUT 0x03 — any
0x03 traffic here is real maintenance protocol). If empty, fix capture BEFORE
Phase 2 — we cannot waste the single-use key on a broken pipeline.

Run it 2–3× — identical read transactions confirm the protocol is deterministic
(the same differential-determinism check the project relies on for replay).

## Phase 2 — reset capture (only after pads installed)

```sh
~/git/printstack-canon/services/canon-tool/scripts/wicreset-capture.sh wicreset-reset-real
# operator: launch WICReset → select G6020 (USB) → enter key 3321...E (from the
#   OctoInkjet email; do NOT paste the key into any repo file) → click Reset.
#   Wait ~2 min for completion. Then power-cycle the printer.
# back in the script terminal: ENTER → stop, gzip, summary
```

**GUI driving (hybrid, per decision):** Phase 1's read is automated headlessly
via Xvfb + xdotool (built + validated separately, since it's free + re-runnable);
Phase 2's keyed Reset stays behind a **human-confirmed forwarded display** —
we do not point blind GUI automation at a single-use paid action.

Record outcome in a `.meta.yaml` sidecar (copy the existing template). The
analyzer pins `extracted_byte_sequence`; promote
`printers/canon-g6020/maintenance.yaml::supported.absorber_reset` from
`pending-capture` → `verified-captured` with the WICReset bytes + the
`[cmd,arg_hi,arg_lo][payload]` framing recovered by the Ghidra trace (Finding A).

## After

- Printer should boot **without 5B00**; confirm via IPP `printer-state`.
- The recovered bytes are the SSOT to build `canon-tool`'s own replay for the
  **rest of the fleet** (behind the EEPROM-dump + write-budget gates) — so we
  don't buy a key per unit.
- WICReset captures double as ground truth for the Ghidra `EncCommService`
  obfuscation question: if WICReset's reset payload is *not* encoded, the
  encode layer is Service-Tool-specific, not protocol-level.
