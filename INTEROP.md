# Interop & upstream plan

How this project relates to the prior art it builds on (the `leecher1337/pixma`
firmware lineage and the SANE `pixma` scanner backend), how the firmware-decrypt /
protocol cross-check path works, and a **concrete, drafted-but-unsent** plan for
contributing the validated open G6020 (G6000-series MegaTank) waste-ink / 5B00
reset findings back to the world as a good FOSS samaritan.

> **Status (2026-06-01):** the native, key-free, cloud-free G6020 5B00 reset is
> **hardware-validated** (commit `d2f3c81`; see `docs/runbook/g6020-native-reset.md`).
> The reset bytes are built **entirely locally** from a decrypted, PE-embedded
> template plus a cracked write cipher; the WICReset cloud was proven to be
> *licensing only* (a key-validation boolean + a post-reset accounting report — it
> sources none of the device bytes). This makes the upstream/publication plan below
> **actionable now**, not aspirational.

> **No external action is taken from this document.** Every PR, issue, and outreach
> message below is a **draft for the operator to send by hand**. No PR is opened, no
> issue is filed, no maintainer is contacted, and nothing is pushed from here. The
> operator owns all upstream relationships.

---

## 1. The two distinct "pixma" projects — do not conflate

There are two unrelated upstreams that both carry the name "pixma". They have
different scopes, different channels, and different relevance to this work.

### 1a. `leecher1337/pixma` — the firmware-unpack lineage (the work we extend)

A small **firmware-unpacking / analysis** toolkit (~340 LOC of C), **not** a reset
tool and **not** a runtime maintenance path. Built on the Context IS 2016 "Hacking
Canon PIXMA Printers — Doomed Encryption" research. Three tools:

- `pixma_decrypt.c` — known-plaintext recovery of a 16-byte XOR key from the SREC
  magic (`SF0900` / `SF050000`), then streaming XOR-decrypt of Canon firmware
  (`.bin` → `.asc`).
- `pixma_unpack.c` — finds a Thumb decompressor signature (`70 B5 05 4C …`), reads
  offset/start/end, runs an unidentified LZ-style decompressor (the author hedges
  "LZ4 or something..?").
- `dec_sdata.c` (+ a 6557-line XOR table) — decrypts Canon's public CA-cert blob
  `sdata.bin`.

The author's own motivation was a stuck waste-ink counter, but he **"soon gave up
on it."** The repo has **no service mode, no USB command framing, no waste-counter
logic, and no G-series / MegaTank model code**. Its forks
(`paulschreiber/pixma`, the operator's own `jesssullivan/pixma`) add only
compile-portability fixes and a `Makefile` — **zero reset capability**. Fully
cross-checked in `docs/research/sota-pixma-octo-lineage.md` §1.

> **Licensing caveat (load-bearing):** `leecher1337/pixma` ships **no LICENSE /
> COPYING file**. Absent an explicit grant it is "all rights reserved" by default,
> which makes derivative *code* contribution legally murky and citation-as-software
> awkward. This shapes the entire upstream strategy below (§3).

### 1b. SANE `pixma` backend — the scanner command backend (prior-art citation only)

`gitlab.com/sane-project/backends`, `backend/pixma*.c` — the Canon **scanner**
command backend. It has real per-model tables and an active maintainer/PR process,
but it is a **scanner** backend with **no waste-ink / maintenance surface**, and its
command path is **BULK**, a different channel from our service-mode **VENDOR
control** transport (`0x41` OUT / `0xC1` IN). We already cite it correctly as
Canon command-framing **lineage prior art** in
`docs/research/canon-servicemode-transport-research.md`. We do **not** contribute
maintenance code there — there is no home for it.

---

## 2. The firmware-decrypt / protocol cross-check path

The `leecher1337/pixma` lineage is the reference for decoding Canon MegaTank
**firmware**, which carries the on-printer command **dispatch table** — an
independent oracle to cross-check any reset opcode recovered from the host-side
tools.

- **We do not vendor pixma source here.** It is referenced as an external
  dependency; the operator's `jesssullivan/pixma` fork (branch
  `tin-1698-pixma-build-tooling`: a reproducible `Makefile` + portability fix,
  binaries gitignored) is the working clone. `third_party/pixma/README.md` is a
  placeholder describing the planned submodule wiring.
- **The cross-check is currently BLOCKED on firmware sourcing for the G6020**
  (panel/internet-only delivery, CDN 404s — see
  `docs/research/canon-tool-firmware-sourcing.md`). The dispatch-table cross-check
  is therefore **secondary**: it was never on the critical path, and the native
  reset was validated *without* it (the oracle that actually delivered was the
  decrypted WICReset `APP.BIN` → `devices.xml` template plus the cracked functor-2
  write cipher — see `docs/runbook/g6020-native-reset.md` §6, §8).
- **Why pixma still matters:** once G6020 firmware is sourced, the pixma decrypt +
  unpack stage is the lever to locate the **waste-clear opcode** and the
  **EEPROM-commit routine** statically — corroborating, from the device side, the
  cloud-independence we proved from the host side, and pinning whether the
  maintenance command path is firmware-signed.

---

## 3. Upstream contribution plan — what, in what shape, and why

**Ranked, all DRAFT-only.** The guiding principle is to contribute in the shape
leecher himself contributed (a protocol writeup + reference tools), **without
inheriting the lineage's license/maintenance debt**.

### PRIMARY — a self-contained, citable PROTOCOL ARTIFACT published from this repo

Do **not** try to land the reset/cipher into `leecher1337/pixma`. It is an
abandoned, unlicensed firmware-unpack hobby fork with no model registry and no
maintenance surface; a cipher/model-entry PR has **nowhere clean to live** there,
and the missing LICENSE makes a derivative code contribution legally murky.

Instead, the cleanest, highest-leverage, lowest-friction contribution is a
**self-contained artifact published from THIS repo**, under this repo's own license:

1. **The formal protocol spec** already staged at
   `docs/spec/megatank-maintenance-protocol.md` — promote it to a stable, citable
   document describing the maintenance transport (usbprint VENDOR control:
   `0x41` OUT / `0xC1` IN, `bRequest = cmd`), the session protocol (plain
   `set_session`, live per-session `get_keyword`, `set_command`, `get_command`),
   the CANON-SR5 envelope/cipher boundary, and the **commit-on-clean-power-button**
   nuance.
2. **The CANON-SR5 reference codec** (`scripts/canon_sr5_cipher.py` +
   `src/canon_megatank/protocol/wicreset.py`) as the reproducible reference
   implementation, with the 23/23 ground-truth verification
   (`docs/runbook/g6020-native-reset.md` §8) as the conformance anchor.
3. **A research paper + a Zenodo-DOI'd release** (the paper lane: `docs/paper/`,
   mirroring the hiberpower-ntfs IEEEtran/tectonic convention — that path is free
   in this repo and owned by a sibling lane). The DOI makes the work **citable as a
   first-class artifact** rather than a dangling fork.

This is the leecher-lineage-**compatible** move (his own contribution was a protocol
writeup + reference tools — we mirror that shape) while staying entirely inside this
repo's clean license and right-to-repair framing (`SECURITY.md`,
`ETHICS/RIGHT-TO-REPAIR.md`).

### SECONDARY — a narrow firmware-decrypt PR to `jesssullivan/pixma` (only if firmware is sourced)

Currently **blocked** (no G6020 firmware). *If* a G6020 firmware blob is ever
sourced, the single change that fits leecher's actual scope is a narrow PR to the
operator's `jesssullivan/pixma` fork that adds **only firmware-decrypt support for
the newer G6000/GM SREC/crypto generation** — extending `pixma_decrypt`'s
known-plaintext recovery and `pixma_unpack`'s decompressor-signature table. Frame it
as **"make the existing unpacker handle one more generation,"** *not* as a reset
tool. **Gate it behind first getting upstream to add a LICENSE** (raise that as the
opening ask — see the issue draft in §5). Do **not** push reset/cipher/model-registry
code into the pixma lineage; it has no surface for it.

### TERTIARY — SANE `pixma`: cite only, do not contribute code

The SANE `pixma` backend is a scanner backend on a bulk channel; our maintenance
findings have **no home there**. Cite it as protocol-lineage prior art (Canon
command framing) exactly as the repo already does — nothing more.

---

## 4. Licensing & right-to-repair framing

- **This repo's license must be explicit and permissive enough to be cited and
  reused.** There is currently **no `LICENSE` file** in this repo — add one before
  the PRIMARY publication (a permissive OSI license, e.g. MIT or Apache-2.0, matches
  the "anyone can reproduce/derive" intent and avoids the leecher-style ambiguity).
  This is a prerequisite for the Zenodo DOI and for any external reuse.
- **Clean-room / interoperability / right-to-repair** is the legal posture
  throughout (`SECURITY.md`, `ETHICS/RIGHT-TO-REPAIR.md`): we reverse-engineer the
  vendor tools as **oracles for interoperability and repair of hardware the operator
  owns**, redistribute **no** Canon firmware, Service Tool, WICReset binary, or
  Ghidra project, and gate every write behind UUID isolation + EEPROM dump + write
  budget + lockfile.
- **The cloud-independence proof is the right-to-repair headline:** the device-side
  reset takes **zero** cloud bytes (the cloud is OctoInkjet/WIC **licensing** only).
  Publishing that proof is squarely interoperability/repair, not circumvention of a
  technical protection on copyrighted content — it documents a maintenance command
  the manufacturer has administratively (not cryptographically) withheld from
  owners. See `ETHICS/RIGHT-TO-REPAIR.md` for the dual-use posture.
- **Attribution flows both ways.** The paper and spec credit the prior art we stand
  on (Context IS 2016, `leecher1337/pixma`, the Epson open-resetter lineage,
  BCH Technologies' ideation post) so the next person can walk the chain — see §7.

---

## 5. Drafted PR / issue text (DO NOT SEND — operator dispatches by hand)

### 5a. Issue draft — to `leecher1337/pixma` (opening ask: add a LICENSE)

> **Title:** Please add an explicit LICENSE so the firmware-unpack tools can be
> built on
>
> **Body:**
> Thanks for `pixma` — the firmware decrypt/unpack tooling (and the Context IS
> "doomed encryption" groundwork it builds on) is the cleanest reference for getting
> inside Canon PIXMA firmware images.
>
> One blocker for building on it in the open: the repo has no `LICENSE`/`COPYING`
> file, so by default it's "all rights reserved", which makes it hard to cite as
> software or to contribute compatible derivative work. Would you consider adding an
> explicit open-source license (e.g. MIT/Apache-2.0/GPL — your call)? That would let
> downstream right-to-repair work reference and extend the unpacker cleanly.
>
> Context for *why* I'm asking: I've been working on an open, native-Linux,
> key-free reset of the Canon MegaTank G6000-series waste-ink (5B00) counter for
> printers I own, and your firmware-unpack lineage is the natural place to
> cross-check the on-printer command dispatch table. Happy to share findings either
> way.

### 5b. PR draft — to `jesssullivan/pixma` (SECONDARY; only after firmware is sourced + upstream licenses)

> **Title:** decrypt: handle the newer G6000/GM SREC + crypto generation
>
> **Summary:** Extends the existing firmware-unpack path to one more Canon
> generation. **No new tool, no reset logic** — this only teaches the *existing*
> `pixma_decrypt` / `pixma_unpack` to recognize and decrypt the G6000/GM-series
> firmware container (newer SREC magic + decompressor signature than the 2016
> Context IS generation).
>
> **What changed:**
> - `pixma_decrypt.c`: add the G6000/GM known-plaintext magic to the XOR-key
>   recovery table.
> - `pixma_unpack.c`: add the G6000/GM Thumb decompressor signature + offsets to the
>   signature table.
>
> **Why:** to locate the waste-clear opcode + EEPROM-commit routine statically, as a
> device-side cross-check of an open MegaTank maintenance protocol (link to the
> published spec/DOI). Scope is deliberately "one more generation for the unpacker",
> nothing more.
>
> **Out of scope (on purpose):** the waste-ink reset itself, the maintenance command
> framing, the write cipher, and any model registry — those live in the standalone
> protocol artifact, not in the firmware unpacker.

### 5c. Outreach draft — to OctoInkjet / Printer Potty (collaboration, not adversarial)

> Hi — I run a small Linux printer fleet and have been doing right-to-repair work on
> the Canon MegaTank G6000-series 5B00 ink-absorber counter (on units I own, with
> external waste tanks fitted). I've documented the maintenance protocol and a
> native reset path, and I want to be a good neighbor about it. A few things I'd value
> your view on: (1) whether you'd object to a published, vendor-neutral protocol
> writeup that credits the WICReset/Printer Potty ecosystem as the working reference;
> (2) whether there's a collaboration shape you'd prefer over a silent fork; and (3)
> confirmation of the physical-safety guidance (fit pads/tank before reset) so the
> publication carries the same warnings you do. Not looking to undercut the key
> business — the cloud licensing is orthogonal to the device-side command, which is
> exactly what I want to state clearly and safely.

---

## 6. Good-FOSS-samaritan traceability (so the next person can build on this)

The whole point is that a future debugger can walk from **RE evidence → code** and
reproduce the result without a key, a cloud, or a Windows tool:

| Want to verify… | Start here |
|---|---|
| the validated end-to-end reset | `docs/runbook/g6020-native-reset.md` |
| the transport (usbprint VENDOR control 0x41/0xC1) | `docs/research/usbprint-vendor-urb-mapping.md` §7 |
| the session/wire protocol | `docs/research/g6020-wire-codec-crack.md` |
| the genuine `set_command` decode (and the negative result) | `docs/research/g6020-genuine-setcommand-decode.md` |
| the cracked write cipher (functor-2 buffer-role swap, 23/23) | `docs/runbook/g6020-native-reset.md` §3, §8 |
| cloud-independence (decompile proof) | `docs/research/wicreset-cloud-vs-local-template.md`, `docs/research/wicreset-drm-bypass.md` |
| the formal protocol model | `docs/spec/megatank-maintenance-protocol.md` |
| the pixma lineage assessment | `docs/research/sota-pixma-octo-lineage.md` |
| the citation universe (≥2-source cross-checked) | `docs/research/sota-academic-eeprom-re.md`, `docs/research/sota-dynamic-instrumentation.md` |
| the ethics / dual-use posture | `ETHICS/RIGHT-TO-REPAIR.md`, `SECURITY.md` |

Provenance discipline: every load-bearing claim in the research docs is cross-checked
across ≥2 sources and confidence-flagged; the ground-truth frames are asserted
byte-exact (23/23) against WICReset's real captured wire; and the cloud-independence
verdict is backed by an adversarial decompile (`docs/research/wicreset-drm-bypass.md`)
plus a Frida DRM-bypass that captured the one genuine reset frame. The trifecta is
**host usbmon wire capture ↔ Frida IOCTL/DRM instrumentation in a Win11 VM ↔ Ghidra
decompile** — reproducible from the runbooks under `docs/runbook/`.

---

## 7. Seed citation list (for the spec + paper)

Mirror the hiberpower-ntfs `references.bib` BibTeX convention (`@misc`/`@article`/
`@inproceedings` + `url` + `note`; build via `rules_tectonic` + IEEEtran). All
entries below are already ≥2-source verified in
`docs/research/sota-academic-eeprom-re.md` and
`docs/research/sota-dynamic-instrumentation.md`.

- **Prior Canon RE:** Context IS, *Hacking Canon PIXMA Printers — Doomed Encryption*
  (2016); `leecher1337/pixma` (firmware-unpack lineage — the work we extend);
  BCH Technologies, *Developing an Open-Source Alternative to Canon Service Tool*
  (ideation / USB-control sniffing).
- **Epson waste-counter lineage (transferable open-RE prior art):** `reink`
  (lion-simba, IEEE-1284.4 D4 EEPROM write); `Ircama/epson_print_conf` (SNMP
  EPSON-CTRL read/write-key frames; multi-byte LE counter ÷ divider; temporary-vs-
  permanent commit); `RxNaison/Epson-Waste-Reset`; `atufi/reinkpy`;
  `Zedeldi/epson-printer-snmp` (parameters derived by sniffing WICReset — our exact
  method).
- **Peer-reviewed consumable-DRM RE:** W. Cybowski, *Methods of implementation and
  operation of hardware DRM protection on the example of printer cartridges*,
  Technical Sciences 25 (2022) 117–137 (the canonical capture→diff→interpret→reset
  writeup).
- **Printer firmware / NVRAM security venues:** Cui, Costello, Stolfo, *When Firmware
  Modifications Attack*, NDSS 2013; Müller, Mladenov, Somorovsky, Schwenk, *SoK:
  Exploiting Network Printers*, IEEE S&P 2017 (+ PRET); Müller et al., *PostScript
  Undead*, RAID 2018; Shwartz et al., *Reverse Engineering IoT Devices*, IEEE IoT J.
  2018; Bakhshi et al., *IoT Firmware Vulnerabilities*, Sensors 24(2):708 (2024).
- **USB protocol-RE methodology:** USB Printer Class spec v1.1; SANE `sane-pixma(5)`
  (Canon framing lineage); snorp.dev and botmonster pyusb USB-RE writeups; QEMU USB
  pcap docs; Wireshark CaptureSetup/USB; USBPcap capture-limitations.
- **Tooling:** Frida (frida.re); Ghidra p-code emulation (cetfor); Unicorn Engine;
  x64dbg (self-decryption / HW-BP technique); `Z4kSec/IoctlHunter`
  (`DeviceIoControl` hooking pattern).
- **Right-to-repair / cloud-gating framing:** R. Anderson, *Security Engineering*
  (DRM / accessory-control ch.) + CACM 2003 *Cryptography and competition policy*;
  B. T. Yeh, CRS R44590 (2016) on DMCA §1201 + software-enabled-device repair;
  OctoInkjet KB + WIC Reset Connect product pages (the cloud-gated business model our
  work proves is device-independent).

---

## 8. Mirror / canonical topology

Once the PRIMARY artifact is published, mirror to `tinyland-inc` per the standard
canonical/mirror topology (canonical repo + downstream mirror). Keep `SECURITY.md`'s
private-advisory reporting path on the canonical repo. No transfer of any third-party
repo is implied or required.
