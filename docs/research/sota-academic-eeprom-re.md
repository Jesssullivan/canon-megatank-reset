# SOTA — Academic & Serious-Whitepaper State of the Art on Printer/Inkjet NVRAM Counter RE

**Research lane deliverable (Lane 2 — academic / paper review).** Scholarly +
serious-whitepaper prior art relevant to `canon-megatank-reset`: inkjet/printer
firmware reverse engineering, consumable-chip and EEPROM counter reversing,
waste-ink counter mechanics, and right-to-repair circumvention of printer
maintenance locks. Compiled 2026-05-31.

> Scope/method: public reading only. **No contact** was made with leecher1337 or
> any upstream maintainer. Every load-bearing claim is cross-checked across ≥2
> sources, cited inline, and flagged with confidence. The genuinely academic
> literature on *consumer-inkjet waste-ink counters specifically* is thin — the
> deepest engineering knowledge lives in open-source tooling (reink,
> epson_print_conf, Epson-Waste-Reset) and one peer-reviewed cartridge-DRM paper
> (Cybowski 2022). The formal security literature (NDSS/IEEE-S&P) covers the
> adjacent primitives — firmware modification, PJL/PostScript NVRAM access — that
> directly inform "how to find and write a durable counter."

---

## TL;DR — what the literature tells the G6020 project

1. **The single most transferable body of prior art is the open-source Epson
   waste-ink resetter lineage** (reink → reinkpy → epson_print_conf →
   Epson-Waste-Reset). It documents, in working code, the exact pattern this
   project needs: a vendor maintenance command channel (Epson's `||`/`@BDC`
   EPSON-CTRL ops with a read-key/write-key), **multi-byte little-endian counters
   at per-model EEPROM addresses divided by a model constant to a percent**, and
   an explicit **temporary-vs-permanent (committed) reset** distinction. (High
   confidence — multiple converging repos + tool docs.)
2. **The "locate + reset a durable NVRAM counter" methodology is well-established
   and matches your plan:** capture the maintenance traffic, *diff* it against an
   observed counter change to interpret bytes, find the read/write opcode + the
   address, then replay the write and confirm persistence across a power-cycle.
   Cybowski (2022, peer-reviewed) states this diff-against-observed-effect method
   explicitly; PRET/Müller formalize NVRAM read/write at a *specified address* as
   a generic primitive. (High confidence.)
3. **Cloud-gating of consumable/maintenance resets is real, documented prior art,
   and the WICReset/WIC-Reset-Connect model is the canonical example for *your*
   exact device.** WIC Reset Connect requires an internet connection and
   **validates a one-time, per-reset key against the vendor server before it will
   reset**, with the per-model reset logic fed from the cloud — i.e. the binary is
   a thin client. That is precisely the "cloud-validated per-reset" failure mode
   your open question asks about. The academic framing of *why* vendors do this
   (Anderson; Cybowski; CRS R44590) is mature even though no paper "defeats"
   WICReset's specific server check. (High confidence on the WICReset cloud
   mechanics; medium that it implies Canon-G6020 resets are *necessarily* a
   per-reset nonce vs a static per-model blob — see §4.)
4. **No academic source publishes Canon G-series service-mode counter offsets or
   the commit opcode.** This is a genuine gap; the authoritative recovery path
   remains a usbmon/USBPcap capture of a tool that actually clears, exactly as
   your in-repo transport docs already conclude. The literature tells you the
   *shape* of the answer, not the G6020 constants.

---

## 1. Curated reading list (most relevant first)

### A. Consumable-chip / waste-ink / EEPROM counter RE (most directly on-point)

- **W. Cybowski, "Methods of implementation and operation of hardware DRM
  protection on the example of printer cartridges," *Technical Sciences* 25
  (2022): 117–137.** Peer-reviewed. The closest academic analogue to this
  project: reverse-engineers printer-cartridge security chips, *modifies the data
  on the chip to reset the protection*, and builds physical "resetter" devices
  (design + docs on the author's GitHub). Explicitly states the interpretation
  method — change a value, observe that "the printer reports a different level of
  print material usage," and conclude you've correctly interpreted part of the
  captured protocol.
  https://czasopisma.uwm.edu.pl/index.php/ts/article/view/7634
  *Relevance: the canonical scholarly write-up of capture→diff→interpret→reset a
  durable consumable counter — your methodology, peer-reviewed.* (High.)

- **reink (lion-simba / "Elena"), open-source Epson ink + waste-counter resetter
  for Linux.** Documents the IEEE-1284.4 (D4) transport and arbitrary-EEPROM-
  address write primitive; "Elena" is credited with the protocol RE.
  https://lion-simba.github.io/reink/ ; src https://github.com/lion-simba/reink
  *Relevance: the foundational open EEPROM-counter RE that all later Epson tools
  fork from; establishes "write any EEPROM address" as the core capability.* (High.)

- **Ircama, `epson_print_conf` — Epson printer config + waste-ink resetter.**
  The best *written* spec of the Epson maintenance protocol: SNMP/EPSON-CTRL `||`
  op (OID base `1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1`), **read** frame
  `7C 7C 07 00 <read-key> 41 BE A0 <addr-LSB> <addr-MSB>` and **write** frame
  `7C 7C 10 00 <read-key> 42 BD 21 <addr> <value> <8-byte write-key>`; waste
  decoded as **reversed-byte (little-endian) hex ÷ model divider → percent** (its
  example: `A4 2A` ÷ `62.06`); and an explicit **temporary (reboot-clears) vs
  permanent (EEPROM-written) reset** split.
  https://github.com/Ircama/epson_print_conf
  *Relevance: a concrete, replicable counter-mechanics + read/write/commit model
  to pattern-match the Canon capture against.* (High.)

- **RxNaison, `Epson-Waste-Reset` (EWR).** Native C++ tool that **constructs
  EEPROM write packets (`|B`) on the fly per model** over USB via the IEEE-1284.4
  D4 credit system, and can parse Wireshark captures to derive packets — a
  modern, fleet-style reimplementation of the same idea.
  https://github.com/RxNaison/Epson-Waste-Reset
  *Relevance: closest in spirit to "native key-free fleet tool"; proves the
  per-model-address, dynamically-built-write approach is viable in clean code.*
  (High.)

- **atufi, `reinkpy`** (Codeberg) — Python successor to reink; broadens Epson
  model coverage. https://codeberg.org/atufi/reinkpy
  **Zedeldi, `epson-printer-snmp`** — minimal SNMP read/reset reference, useful
  as a second independent spec of the same OID/key scheme.
  https://github.com/Zedeldi/epson-printer-snmp
  *Relevance: independent corroboration of the epson_print_conf protocol.* (High.)

### B. Printer firmware RE & durable-NVRAM primitives (formal security venues)

- **A. Cui, M. Costello, S. J. Stolfo, "When Firmware Modifications Attack: A
  Case Study of Embedded Exploitation," NDSS 2013.**
  PDF: https://ids.cs.columbia.edu/sites/default/files/ndss-2013.pdf ;
  prog: https://www.ndss-symposium.org/ndss2013/ndss-2013-programme/when-firmware-modifications-attack-case-study-embedded-exploitation/ ;
  DOI/archive: https://doi.org/10.7916/D8P55NKB
  *Relevance: the canonical academic printer-firmware-RE paper (HP LaserJet RFU);
  documents the firmware-format reverse-engineering workflow and persistent
  modification of an embedded printer — the upstream of all printer-RE security
  work.* (High.)

- **J. Müller, V. Mladenov, J. Somorovsky, J. Schwenk, "SoK: Exploiting Network
  Printers," IEEE Symposium on Security & Privacy (S&P) 2017.**
  Paper PDF (RUB-NDS): https://www.nds.rub.de/media/ei/arbeiten/2017/01/30/exploiting-printers.pdf ;
  IEEE: https://ieeexplore.ieee.org/document/7958579
  Tooling: **PRET — Printer Exploitation Toolkit**, https://github.com/RUB-NDS/PRET
  (see `pjl.py`). Documents PJL/PostScript primitives that **read and write the
  printer's NVRAM at a specified address** and manipulate persistent values
  (incl. counters), plus factory-reset semantics.
  *Relevance: formalizes "access a durable counter in printer NVRAM at a named
  address" as a generic, tool-supported primitive — the abstract version of the
  Canon service-mode write you're replaying.* (High; two sources: SoK + PRET code.)

- **J. Müller, V. Mladenov, D. Felsch, J. Schwenk, "PostScript Undead: Pwning the
  Web with a 35 Years Old Language," RAID 2018.**
  https://doi.org/10.1007/978-3-030-00470-5_28
  *Relevance: deeper PostScript-level persistence/NVRAM abuse; supporting context
  for language-level access to durable printer state.* (Medium.)

- **O. Shwartz, Y. Mathov, M. Bohadana, Y. Oren, Y. Elovici, "Reverse Engineering
  IoT Devices: Effective Techniques and Methods," IEEE IoT Journal, 2018.**
  https://ieeexplore.ieee.org/document/8488542
  *Relevance: general method spine for chip/firmware/NVRAM RE (bus sniffing, dump,
  diff) applicable to the service-mode counter hunt.* (Medium.)

- **T. Bakhshi, B. Ghita, I. Kuzminykh, "A Review of IoT Firmware Vulnerabilities
  and Auditing Techniques," *Sensors* 24(2):708, 2024.**
  https://www.mdpi.com/1424-8220/24/2/708
  *Relevance: current survey of firmware-RE/auditing tooling and dump/diff
  workflow; useful taxonomy + tool list.* (Medium.)

### C. Right-to-repair / cloud-gating / consumable-DRM framing (law + economics + crypto)

- **R. Anderson, *Security Engineering* — DRM / "accessory control" chapter (and
  "Cryptography and competition policy: issues with 'trusted computing'," CACM
  2003, https://doi.org/10.1145/872035.872036).**
  Free chapters: https://www.cl.cam.ac.uk/archive/rja14/Papers/SEv3-ch24.pdf
  *Relevance: the canonical analysis of *why* printer cartridges/consumables carry
  authentication chips and how vendors bind consumables to the device — the
  threat-model rationale behind a cloud-gated reset.* (High.)

- **B. T. Yeh, "Repair, Modification, or Resale of Software-Enabled Consumer
  Electronic Devices: Copyright Law Issues," Congressional Research Service
  R44590, 2016.** https://crsreports.congress.gov/product/details?id=R44590
  *Relevance: authoritative legal framing of toner/cartridge DRM circumvention &
  DMCA §1201 — the right-to-repair lens on resetting maintenance locks.* (High.)

- **OctoInkjet KB — "Reset Utility: WICReset Service" / "WICReset: Instructions,
  Access, Troubleshooting."** Serious operator-facing whitepaper-grade docs on the
  WICReset key/cloud model and the explicit observation that *manufacturers now
  deliberately hamper end-user access to reset tools*.
  https://www.octoink.co.uk/docs/kb/wicreset-instructions-access-troubleshooting/
  *Relevance: the best public characterization of the cloud-gated reset business
  model you're up against, written by a reputable repair vendor.* (High.)

---

## 2. Documented techniques for locating + resetting durable NVRAM counters

Synthesized from Cybowski 2022, the Epson tool lineage, Müller/PRET, and
Shwartz et al.; each technique below has ≥2 supporting sources.

**(a) Locate the counter — EEPROM dump + diff.**
- Capture the maintenance command channel (USB: usbmon/USBPcap; or SNMP/network),
  or dump the EEPROM/NVRAM directly, **before and after a known counter-changing
  action**, and diff. Cybowski's stated test: change a candidate value and watch
  whether "the printer reports a different level of print material usage" — the
  byte(s) that move are the counter. (Cybowski 2022; Shwartz 2018.)
- For Epson the counter is **multi-byte little-endian** spread across several
  EEPROM addresses; combine, reverse, ÷ model divider → percent
  (epson_print_conf; reink). Expect Canon's absorber counter to be similarly a
  small multi-byte field, not a single byte.

**(b) Read/write opcode + addressing.**
- Vendor maintenance protocols expose a *read at address* and *write at address*
  pair. Epson: read `…41 BE A0 <addr>` / write `…42 BD 21 <addr> <val> <write-key>`
  (epson_print_conf; Zedeldi epson-printer-snmp). PJL: read/write NVRAM "at the
  specified address" (Müller SoK; PRET `pjl.py`). Canon's analogue in your
  in-repo work is the vendor control-OUT `bmRequestType=0x40 bRequest=0x85
  data=[00 03 01 03 07]`; the literature says **expect a paired read opcode and an
  address/index field** — your `data[4]=0x07` "Main" index is that address field.

**(c) Checksum / parity / key models.**
- Epson gates writes with a **derived read-key/write-key** (key bytes derived from
  the command character, e.g. `A`→`BE A0`, `B`→`BD 21`) rather than a data
  checksum; epson_print_conf documents no separate counter checksum beyond the key
  scheme. (epson_print_conf; reink.) Cartridge chips (Cybowski) more often use a
  **checksum/CRC or signature over the chip data** that must be recomputed after a
  write — so for Canon's EEPROM, *budget for a checksum/parity field that must be
  fixed up*, and look for it in the dump-diff as a second byte that moves whenever
  the counter moves.

**(d) Commit / persistence semantics (the crux of "ACK but no clear").**
- Tools uniformly distinguish a **temporary reset** (RAM/session, clears on
  reboot) from a **permanent reset** (EEPROM write, survives power-cycle). An ACK
  with no durable change is the classic signature of a write that was accepted but
  **not committed to NVRAM**, or routed to a disabled path. (epson_print_conf
  explicit temp-vs-permanent split; Cui/Stolfo on persistent firmware writes;
  matches your in-repo "uncommitted write OR disabled gate" hypothesis.)
- Practical recovery: in the working-tool capture, look for a **second
  transfer after the counter write** (a flush/commit/service-exit) and a
  power-cycle prompt; verify with an **EEPROM read-back across a reboot** (the
  counter must drop and stay dropped). This is the universal validation step in
  every tool above.

**(e) Confirm by read-back, not by ACK.** Every credible tool verifies via a
post-reset EEPROM read; none trust the device ACK. (epson_print_conf; reink; EWR.)

---

## 3. Prior art on vendor cloud-gating of consumable/maintenance resets

**The mechanism (well-documented).** WIC Reset Connect / WICReset is the
canonical cloud-gated *maintenance* reset for exactly your device class
(Epson **and Canon**, incl. Canon G-series 5B00). It:
- **requires an active internet connection** to perform a reset, and connects the
  printer over USB to a client that talks to the vendor server;
- consumes a **one-time, per-reset key** validated **online against the vendor
  server before** the reset is allowed to complete (a key can be locked/blocked
  server-side);
- pulls the **per-model reset definition from the cloud** ("WIC Reset Connect"),
  so the local binary carries little/no model-specific reset data.
  Sources: WicResetConnect (https://wicresetconnect.com/en/),
  resetter.net WIC online (https://wic.resetter.net/),
  OctoInkjet KB (https://www.octoink.co.uk/docs/kb/wicreset-instructions-access-troubleshooting/),
  Printer Potty WICReset troubleshooting
  (https://support.printerpotty.com/2013/wicreset-troubleshooting). (High confidence —
  ≥3 independent sources agree on internet-required + per-reset key + online
  validation.)

**The academic/why framing (mature).** Anderson (*Security Engineering* / CACM
2003) and Cybowski (2022) explain consumable/accessory binding and authentication
as deliberate competition- and warranty-control mechanisms; CRS R44590 (Yeh 2016)
covers the DMCA §1201 legal regime that makes circumvention contentious. Together
they frame cloud-gating as the modern evolution of the cartridge-chip lock:
**move the secret/decision off the device and behind a server so it cannot be
replayed locally.** (High confidence on the framing.)

**How researchers have characterized / defeated it.**
- **For static, on-device counters** (older Epson, cartridge chips), researchers
  *defeated* the lock entirely by reversing the local protocol and writing the
  EEPROM directly — no server in the loop (reink, epson_print_conf, EWR, Cybowski
  resetters). This is the **replayable-local** outcome your open question hopes
  for. (High.)
- **For cloud-validated resets** (WIC Reset Connect's model), no public academic
  work demonstrates a clean local replay that bypasses the server check; the
  documented community reality is that you **pay per reset** because the
  authorizing decision/data is server-side. The literature characterizes this as
  the hard case and does **not** publish a defeat. (High that no public defeat
  exists; this is the boundary of the prior art.)

**Direct implication for the G6020 open question (replayable-local vs
cloud-nonce).** The prior art does **not** by itself settle whether the *Canon
G6020 reset bytes* are a static per-model blob (→ native key-free tool feasible,
like Epson) or a per-reset server nonce (→ native replay impossible). Two
distinct things are conflated in the wild: (1) WICReset's *business* gating
(online key check) — which is about authorizing *the tool*, and can sit on top of
an otherwise static command; vs (2) whether *the printer firmware itself* demands
a fresh server-derived nonce per reset. The literature shows (1) is common and
(2) is rare for waste-ink counters (Epson's are static and locally replayable).
**The decisive test is the one your in-repo docs already specify:** USB-capture a
tool that actually clears the G6020 twice and diff the two captures — if the
counter-write payload is **byte-identical across resets**, it is replayable-local
(native tool feasible); if it carries a **changing nonce/challenge token**, it is
cloud-validated. (Medium confidence in the framing; the experiment, not the
literature, settles it.)

---

## 4. Confidence summary & residual gaps

- **High:** the Epson resetter lineage documents counter mechanics
  (multi-byte LE ÷ divider), read/write-at-address opcodes with derived keys, and
  temp-vs-permanent commit semantics; the capture→diff→interpret→write→verify
  methodology is the established practice (Cybowski peer-reviewed + tools + PRET);
  printer firmware/NVRAM RE has canonical venues (NDSS 2013, IEEE S&P 2017);
  WIC Reset Connect is internet-required, per-reset-keyed, cloud-fed for Canon.
- **Medium:** that the cloud-gating necessarily implies the *Canon firmware*
  enforces a per-reset nonce (vs WICReset merely gating tool access over a static
  command); whether Canon's EEPROM carries a checksum that must be recomputed.
- **Residual gap (unchanged from in-repo transport docs):** no academic/whitepaper
  source publishes Canon G-series service-mode counter offsets, the commit opcode,
  or a G6020 reset payload. The authoritative recovery remains a usbmon/USBPcap
  capture of a tool that actually clears, captured twice to settle
  replayable-local vs nonce.

## 5. Cross-check matrix (≥2 sources per load-bearing claim)

| Claim | Source A | Source B |
|---|---|---|
| Epson waste counter = multi-byte LE EEPROM ÷ model divider → percent | epson_print_conf (Ircama) | reink (lion-simba) |
| Read/write-at-address opcodes with derived read/write keys | epson_print_conf | Zedeldi epson-printer-snmp |
| Temp (reboot-clears) vs permanent (EEPROM, persists) reset distinction | epson_print_conf | Epson-Waste-Reset (EWR) |
| Capture→diff-against-observed-counter-change is the interpretation method | Cybowski 2022 (peer-reviewed) | Shwartz et al. 2018 (IoT RE) |
| Printer NVRAM read/write at a named address is a documented primitive | Müller SoK (IEEE S&P 2017) | PRET `pjl.py` (RUB-NDS) |
| Canonical printer-firmware RE / persistent modification | Cui-Costello-Stolfo NDSS 2013 | Müller SoK 2017 |
| Consumable/accessory DRM is deliberate vendor lock-in | Anderson SE/CACM 2003 | Cybowski 2022 / CRS R44590 |
| WIC Reset Connect: internet required + per-reset key + cloud-fed (Canon incl.) | WicResetConnect / resetter.net WIC | OctoInkjet KB + Printer Potty KB |
| Vendors deliberately hamper end-user reset-tool access | OctoInkjet KB | Anderson (competition-policy framing) |

---

*Provenance: searches via Google Scholar (paper-search MCP), arXiv (rate-limited
this run), DuckDuckGo, WebSearch, and direct fetch of source repos/KBs. The
deepest applicable knowledge is in open tooling + Cybowski 2022, not in a
waste-ink-specific academic paper (which does not appear to exist). No upstream/
leecher1337 contact; public reading only.*
