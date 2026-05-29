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

WIC Reset Utility / "WIC Reset Connect" (wic.support / wicreset.com) — commercial
waste-ink-counter resetter. Native **Linux / macOS / Windows** builds. Talks to
the printer **directly over USB** (select printer → USB). Works while the printer
shows **5B00**. `Read waste counters` is **free**; `Reset` consumes a **single-use
key** (one printer, once) and takes ~2 min.

- Key (OctoInkjet ISC69146): stored by operator — **not committed** to the repo.
- The same EEPROM channel WICReset uses is our interface-4 maintenance lane
  (bulk OUT `0x03` / bulk IN `0x86`), so usbmon sees the exact reset transaction.

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

## Phase 1 — free read capture (do now)

On **mbp-13** (printer connected, `canon_tool_dev` applied):

```sh
sudo services/canon-tool/scripts/wicreset-capture.sh wicreset-read-1
# script: pre-flight (fw 1.070) → stop ipp-usb → tshark usbmon1 → READY
# operator (separate terminal / display): launch WICReset, select the G6020 via
#   USB, click "Read waste counters" (NO key, NO reset). Let it finish.
# back in the script terminal: press ENTER → stop, gzip, summary
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
sudo services/canon-tool/scripts/wicreset-capture.sh wicreset-reset-real
# operator: launch WICReset → select G6020 (USB) → enter key 3321...E (from the
#   OctoInkjet email; do NOT paste the key into any repo file) → click Reset.
#   Wait ~2 min for completion. Then power-cycle the printer.
# back in the script terminal: ENTER → stop, gzip, summary
```

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
