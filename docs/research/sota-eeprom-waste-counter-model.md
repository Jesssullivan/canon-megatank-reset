# Canon MegaTank / G-series — Waste-Ink Absorber Counter Storage Model (SOTA lane 4)

> Public reading only. **No contact made with leecher1337 or any upstream
> maintainer.** All load-bearing claims cross-checked across ≥2 sources; confidence
> flagged per item. Compiled 2026-05-31.
>
> Read alongside the two established lane docs:
> `docs/research/g6020-servicetool-version-research.md` (5B00 / disabled-gate
> evidence) and `docs/research/canon-servicemode-transport-research.md`
> (USB transport crack). This doc adds the *storage / commit / hardware* layer.

---

## TL;DR for the G6020 fleet effort

1. **The waste counter is a set of per-absorber percentage counters held in the
   mainboard EEPROM (an I2C serial EEPROM, M24Cxx family).** On the older
   cartridge/MegaTank gens the part is an **ST M24C08** (8 Kbit / 1 KByte,
   I2C, TSSOP-8) sitting on the logic board next to a separate **25Qxx SPI
   firmware flash**. 5B00 = "absorber full" fires when a counter reaches
   **D = 100.0 %**. (High confidence — service-manual counter notation + two
   independent teardown/dump sources.)
2. **The counter is structured per-absorber, not a single value:** **D / D_BK**
   (Main, black), **D_CL** (Main, color), **Dp_HM** (Platen, Home), **Dp_AW**
   (Platen, Away). 5B00/5B02/5B03 = Main(black) full; 5B04/5B05 = Main(color)
   full; 5B12/5B13 = Platen(home) full; 5B14/5B15 = Platen(away) full. Reset is
   **per-absorber** (ServiceTool exposes a MAIN / PLATEN pull-down + a 0–100 %
   value pull-down in 10 % steps). (High confidence — multiply corroborated.)
3. **ServiceTool CAN read the counter back — but the documented readback path is
   an EEPROM-information *PRINT* (and a "EEPROM Save" to a PC text file), not a
   live on-wire dump.** The canonical verify flow is: *print EEPROM info →
   read `D=100.0` → reset → print EEPROM info again → confirm `D=000.0`.* That
   means a reset is normally **verified by a printout, which requires the
   print/feed path — effectively a power-cycle's worth of mechanism, not a pure
   USB read.** Whether the same EEPROM block is also returned over the wire as a
   status reply (so we could verify *without* a power-cycle) is **plausible but
   NOT publicly documented** — it has to be confirmed from our own SEND-primed
   status reply on `04a9:12fe`. (High confidence on the print path; **low** on a
   pure on-wire readback.)
4. **The G6020 specifically is the "fixed-pad, mainboard-EEPROM-counter"
   generation — it has NO user-replaceable maintenance cartridge with an
   on-chip counter.** This is the load-bearing branch for the hardware fallback:
   the counter lives in the board EEPROM (M24Cxx), exactly the chip that the
   community resets by **de-solder → external programmer → edit the counter
   region → write back**. Newer/sibling models (GX6020/GX7020, G1220/G2260/
   G3260/G620, GM) instead use the **MC-G02 / MC-G01 maintenance cartridge**,
   whose counter sits on a **separate ST M24C16 I2C chip *inside the cartridge***
   and is reset by swapping/reflashing the cartridge — a *different* mechanism
   that does **not** apply to the G6020. (High confidence — Canon parts listings
   + community.)
5. **ACK-without-clear: most likely a DISABLED GATE, not an uncommitted write.**
   The EEPROM-commit model on these printers is real (counter write → NVRAM
   persist tied to the service-mode exit / power-down), so a missing-commit
   theory is physically plausible. **But** the dominant community evidence is
   that Canon *removed the service-mode WIC-clear opcode handler* on the
   G5000/G6000/G7000/GM firmware: the printer "smiles, whirrs, then shuts down"
   — it accepts the frame and does nothing. That signature (accept-and-ignore on
   a removed handler) is the leading explanation; "wrote but never flushed" is
   the secondary one. They are **distinguishable on-wire** (see §3). (Medium-high
   confidence.)

---

## 1. Storage model — chip, location, counter structure, d=100 %, checksum/commit

### 1.1 Where the counter lives (chip + board location)
- Canon PIXMA logic boards carry **two** non-volatile parts:
  - a **25Qxx SPI NOR flash** (firmware / S-record boot code), e.g.
    `IC303 = 25Q16 [25L1636E]`;
  - a **24Cxx / M24Cxx I2C serial EEPROM** holding **settings + counters**,
    e.g. `IC302 = 24C08 [4G08]` on mainboard `QM7-4508` (Canon E404 dump
    listing). The waste-ink counter is in the **24Cxx EEPROM**, not the SPI
    flash. (Source A: ORPYS E404 dump bill-of-materials —
    https://orpys.com/en/dumps/497-canon-e404-dump.html ; Source B: badcaps
    MG2550S "dump BIOS" thread — board has both a `25q16` and a `24c08 [4g08]`
    EEPROM — https://www.badcaps.net/forum/showthread.php?t=92191 ).
- A full teardown of the **MG2400/MG2500 (MG2450)** board confirms the part and
  its access: the small bottom-side IC that "stores settings and stats" is an
  **ST M24C08** — *"Voltage 1.8–5.5 V, Size 8 Kbit (1 KByte), Page size 16 byte,
  100–400 kHz"*, TSSOP-8, read/written via an EEPROM programmer through a
  TSSOP-8→DIP-8 adapter. The SOP-8 chip on the *top* side is the executable-code
  EEPROM (S-record) and is **not** the counter store. (Source:
  https://www.printerknowledge.com/threads/how-to-actually-reset-ink-absorber-count-on-mg2400-and-mg2500-printers.16864/ )
- **G6020 board EEPROM part not yet publicly pinned to a specific 24Cxx number.**
  The family is consistent (Canon uses M24Cxx I2C EEPROM for the
  settings/counter store across the PIXMA line), but the exact density/part on
  the GM/G6000 board (`QMx-xxxx`) is **not** in public text and must be read off
  the physical board. (Confidence: family = high; exact G6020 part = unknown.)

### 1.2 Counter structure (per-absorber) and the d=100 % semantics
- The waste counter is **not one number** — it is a set of per-absorber
  percentage accumulators stored in EEPROM:
  - **D / D_BK** — Main absorber, black;
  - **D_CL** — Main absorber, color;
  - **Dp_HM** — Platen absorber, Home;
  - **Dp_AW** — Platen absorber, Away.
- **`D = 100.0` means that absorber is full.** The error fires per-absorber:
  - **5B00 / 5B02 / 5B03** → Main absorber full (black);
  - **5B04 / 5B05** → Main absorber full (color);
  - **5B12 / 5B13** → Platen absorber full (home);
  - **5B14 / 5B15** → Platen absorber full (away).
  (Support code **1700/1701** is the soft "near-full" warning that precedes the
  hard 5Bxx fault.) (Source A: WIC.support 5Bxx code map —
  https://www.wic.support/canon-service-errors-5b00-5b02-5b03-5b04-5b05-5b12-5b13-5b14-5b15-reset-solutions/ ;
  Source B: easyFIXS MG5700/MG3500 absorber-code breakdowns —
  https://easyfixs.blogspot.com/2021/02/how-to-reset-canon-mg5700-series-and.html ,
  https://easyfixs.blogspot.com/2021/03/how-to-reset-canon-mg3500-series-ink.html )
- **ServiceTool exposes the reset per-absorber:** Ink Absorber Counter section →
  **Absorber** pull-down = `MAIN` or `PLATEN` → **Counter Value (%)** pull-down
  selected in **10 % increments** closest to the actual value → **SET**. This is
  why your reverse-engineered V5103 frame carries an **absorber-index byte**
  (Platen=0x00, Main_Black=0x01, Main_Color=0x03, Main&Platen=0x06, Main=0x07):
  the index *is* the absorber selector from this UI. (Source: Canon
  service-manual Clear-Ink-Counter text quoted across resetter writeups +
  MG-series manuals; corroborated by the per-absorber code map above.)

### 1.3 Checksum / commit model
- The EEPROM image is **checksummed and block-structured.** The MG2450 reset
  recipe overwrites a contiguous region from **offset 0xF0 to end-of-file** with
  a known-good default block; the dumped data shows repeated framed records with
  **`A3 A5` / `A5 A6` markers and `FF FF FF FF` block terminators** — i.e. the
  counter store is a set of length-delimited records, and resetting means
  rewriting whole records (the author could not isolate the single counter byte,
  so reset the whole settings tail). This block/marker structure is why an
  *arbitrary partial* poke is risky: a bad checksum/record can brick service
  mode. (Source: MG2450 thread, full hex block —
  https://www.printerknowledge.com/threads/how-to-actually-reset-ink-absorber-count-on-mg2400-and-mg2500-printers.16864/ )
- **Commit = the firmware persists the EEPROM on the service-mode write +
  service exit / power-down.** On the working older gens the tool sends the
  counter write, the device writes EEPROM, and ServiceTool then prompts a
  **power-cycle** before the cleared value takes effect on the next boot. So the
  normal flow already *implies* a commit-then-power-cycle; an ACK that survives a
  power-cycle as still-100 % is the diagnostic that the write never persisted (or
  was ignored). (Source A: tonercom 5B00 guide, "Method B: Service Tool via USB"
  power-cycle step — https://tonercom.net/2025/08/canon-5b00-reset-guide/ ;
  Source B: the EEPROM-info-print before/after verify flow below.)

---

## 2. Can ServiceTool's EEPROM read / "EEPROM Save" VERIFY a reset without a power-cycle?

**Documented answer: ServiceTool verifies via an EEPROM-information PRINT (or a
"EEPROM Save" to a PC text file), i.e. through the print/mechanism path — not a
guaranteed pure-USB readback.**

- **EEPROM information print / EEPROM Save are real ServiceTool/service-mode
  functions.** The MG2100–MG4200 simplified service manual lists **"8 EEPROM
  Save — EEPROM information saving … displayed on the PC or saved to the PC as a
  text file"** and an EEPROM-information print. The classic service menu (i-/MP-
  era) is literally **"1 = EEPROM info print, 2 = EEPROM initialize, 3 = reset
  waste ink counter."** (Source A: MG2100 series simplified service manual —
  https://download.daidai.tw/pdf/service_manual/canon/Canon%20MG2100,%20MG2200,%20MG3100,%20MG3200,%20MG4100,%20MG4200%20series%20Simplified%20Service%20Manual%20Rev.%2002.pdf ;
  Source B: Tom's Hardware i-series service-menu map "1 EEPROM info print / 2
  EEPROM initialize / 3 reset waste ink counter" —
  https://forums.tomshardware.com/threads/canon-i-series-waste-ink-tank-error-reset.26876/ )
- **The counter IS exposed in that readback as `D=` percentages**, which is the
  community-standard verify step: *print EEPROM info, read **D=100.0**, reset,
  print again, confirm **D=000.0**.* So the counter value is observable and a
  reset is checkable — **but the documented channel is the PRINTOUT (and the
  PC-saved text dump), which exercises the feed/print path.** (Source A:
  before/after `D=100.0 → D=000.0` verify flow as documented across
  service-manual-derived guides — surfaced via WebSearch of Canon service-manual
  Clear-Ink-Counter text; Source B: Tom's Hardware menu above, EEPROM-info-print
  as the inspection op.)
- **"EEPROM Save → PC text file" is the closest thing to an on-wire readback we
  have public evidence for** — it pulls the EEPROM image to the host over the
  same maintenance channel and renders `D=` values. **If** the GM/G6000 firmware
  still answers the EEPROM-information *query* (the SEND-primed `0x85`/`0x86`
  status reply on `04a9:12fe` from the transport doc), then the absorber
  percentages should be parseable from that ~20-byte status reply **without** a
  power-cycle. **This is the high-value verification hook for the native tool**,
  but it is **NOT publicly documented for G6020** — confirm it from our own
  capture. (Confidence: documented print/save readback = high; pure-USB
  no-power-cycle readback on G6020 = **low/unproven**.)
- **Bytes/offsets known:** publicly, only the **MG2450 settings-tail region
  (≥0xF0)** and the record markers (`A3 A5`, `A5 A6`, `FF FF FF FF`) are
  exposed, and only as a whole-block reset — **no public source isolates the
  single absorber-counter byte/offset**, and **none gives the G6020 offset at
  all.** Recovering the G6020 offsets requires either (a) an **EEPROM Save** text
  dump from a working tool, or (b) a physical chip dump (§4). (Confidence: high
  that no public G6020 offset exists.)

---

## 3. Does the reset need a separate EEPROM-commit/flush opcode? (gate vs uncommitted write)

**Two competing explanations for "device ACKs but 5B00 does not clear," and they
are distinguishable on-wire:**

- **(A) Disabled gate (LEADING explanation).** Community evidence is that Canon
  *removed the service-mode waste-counter-clear functionality* on the
  G5000/G6000/G7000/GM generation. The G6050 owner reports the printer enters
  service mode, accepts the button combo, *"throws out a few whirrs and clicks…
  as if it's going to work and then… just shuts down"* — i.e. **accept-and-
  ignore on a removed handler.** A second poster states this whole generation's
  service mode **"lack[s]… the functionality of resetting the waste counter
  without the use of PC-side software."** This matches your `0x40/0x85` ACK with
  no clear. (Source: PrinterKnowledge G5000–G7000 thread —
  https://www.printerknowledge.com/threads/canon-megatank-resetting-waste-counter-help-needed-g5000-g7000-series.16041/ ;
  cross-checked by Reddit r/printers "Canon disabled the ability to reset the
  WIC from service mode" — https://www.reddit.com/r/printers/comments/19d5m46/ )
- **(B) Uncommitted write (SECONDARY explanation).** Canon flows pair a counter
  write with an EEPROM persist that lands on the service-exit/power-down, and
  ServiceTool always prompts a power-cycle. An ACK with the value still 100 %
  after power-cycle would be consistent with a write that **was never flushed**
  — i.e. a missing **commit/flush opcode** (a second control/SEND frame after the
  counter write). The block/checksum structure (§1.3) means an EEPROM write that
  fails checksum-finalize is silently discarded. (Source: power-cycle-required
  step in tonercom Method B + the block-marker EEPROM structure above.)

**How to distinguish (decisive test):** capture a tool that *actually clears*
(STV6300/V6310 if it works on G6020, else WICReset Connect) and diff its
service-mode control/SEND sequence against your `0x40 0x85 … 00 03 01 03 07`
frame:
1. **If the working sequence has an extra post-write frame** (a distinct
   `bRequest`/cmd-byte after the counter write) → **(B) missing commit** — replay
   it and the native tool works key-free.
2. **If the working sequence is byte-identical to yours but the device clears
   anyway** (e.g. gated behind a per-reset nonce / cloud-issued token in the
   payload) → **(A) gate** — native replay impossible without the unlock, which
   ties to the open "replayable vs cloud-nonce" question in the lane brief.
3. **Verify either way via the EEPROM-information readback** (§2): a SEND-primed
   status read of `D=` before and after the write tells you instantly whether the
   write landed in EEPROM (B path active) **without** waiting for a power-cycle —
   *if* the firmware answers the query.
(Confidence: the test design is high-confidence; which branch is true for G6020
is the open question this lane exists to close.)

---

## 4. Hardware fallback if firmware-gating holds (DOCUMENTED OPTION — not an action)

If no tool clears the G6020 over USB (gate confirmed), the absorber counter is
still **directly resettable on the EEPROM chip**, because on this generation the
counter lives in the **mainboard I2C EEPROM** (no maintenance-cartridge chip to
swap).

- **Likely chip:** an **ST M24Cxx I2C serial EEPROM** (TSSOP-8 / SOP-8),
  1.8–5.5 V, page-write, 100–400 kHz — same family as the **M24C08** confirmed on
  MG2450 and the **24C08 [4G08]** on E404/MG2550S boards. Density on the GM/G6000
  board is **not publicly known** (could be 24C08/16/32/64) — **read it off the
  silkscreen on the physical board.** It sits **next to the 25Qxx SPI firmware
  flash**; the SPI flash is *firmware*, the I2C EEPROM is *counters/settings*.
  (Source A: MG2450 M24C08 teardown; Source B: ORPYS/E404 + badcaps MG2550S
  two-chip BoM.)
- **In-circuit read/write:** because it's **I2C**, an SOIC/TSSOP **chip-clip +
  USB I2C/SPI programmer (CH341A class) at 3.3 V** can read/write it; the MG2450
  community method de-solders to a TSSOP-8→DIP-8 adapter to be safe, but
  in-circuit clip reads of M24Cxx are routine. **Always dump-and-keep the
  original image first** (serial number, region, head-alignment, and the
  checksum/record markers live in the same chip — a bad write bricks the
  printer). (Source: MG2450 programmer/adapter procedure +
  badcaps "24c08 is erasable — just write 0s/1s" note.)
- **Is the absorber counter directly writable on-chip? YES** — that is exactly
  what the community does: dump the EEPROM, **rewrite the settings/counter
  records** (MG2450: overwrite the **≥0xF0** tail with a default block; or
  splice a clean per-model dump from ORPYS-style libraries), restore checksum,
  write back → 5B00/1700 clear. The **caveat is the checksum/record structure**
  (§1.3): you must rewrite *valid records*, not a single byte, unless the exact
  counter offset + checksum algorithm for the G6020 is reverse-engineered from a
  dump. (Source A: MG2450 whole-tail rewrite; Source B: ORPYS dump library
  "reset absorber (5B00, 5B02) and recovery service mode" via programmer —
  https://orpys.com/en/dumps/497-canon-e404-dump.html )
- **Documented WP-pin angle (older boards):** on the MG2450, EEPROM **pin 7
  (Write-Protect)** is tied to **GND** (writes enabled); a proposed mod bridges
  pin 7→pin 8 (Vcc) to **lock the EEPROM** so the counter can never advance — but
  that *also* freezes the ink-level-check setting, so the printer must be saved
  with level-check off first. **Not directly transferable to G6020** (different
  board) and listed only as a documented technique. (Source: MG2450 thread.)
- **Cartridge-chip path does NOT apply to G6020** (recorded to prevent a wrong
  turn): the **MC-G02/MC-G01** maintenance cartridge used by **GX6020/GX7020,
  G1220/G2260/G3260/G620, G580/G680/G1820/G2820/G3820** carries its **own ST
  **M24C16** (16 Kbit/2048 B, marked `416RT`/`4G16`) I2C chip**, reset by
  dumping a fresh cartridge ROM and writing it back (wangyu Arduino resetter).
  **The G6020 has no user-replaceable maintenance cartridge**, so its counter is
  in the *board* EEPROM, not a cartridge chip. (Source A: wangyu
  canon_mc-g02_resetter wiki — M24C16/416RT, model list —
  https://github.com/wangyu-/canon_mc-g02_resetter ; Source B: Canon parts +
  community confirming G6020 has no user-replaceable maintenance cartridge —
  https://community.usa.canon.com/t5/Desktop-Inkjet-Printers/PIXMA-G6020-maintenance-cartridge/td-p/541987 ,
  Amazon MC-G02 compatibility list excluding G6020.)

---

## 5. Cross-check matrix (≥2 independent sources per load-bearing claim)

| Claim | Source A | Source B |
|---|---|---|
| Counter store = I2C M24Cxx EEPROM (separate from 25Qxx SPI firmware flash) | ORPYS E404 `IC302 24C08 / IC303 25Q16` | badcaps MG2550S two-chip board |
| Specific part on a real board = ST M24C08, 8 Kbit, TSSOP-8, page 16 B | MG2450 teardown thread | E404/MG2550S `24c08 [4g08]` |
| Per-absorber counters D/D_BK, D_CL, Dp_HM, Dp_AW; 100.0 = full | WIC.support 5Bxx code map | easyFIXS MG5700/MG3500 code breakdowns |
| 5Bxx split = Main(blk) / Main(clr) / Platen(home) / Platen(away) | WIC.support | easyFIXS |
| ServiceTool resets per-absorber (MAIN/PLATEN + % in 10% steps + SET) | Canon Clear-Ink-Counter manual text | per-absorber 5Bxx map (implies indices) |
| EEPROM info **print** / EEPROM Save is the documented readback; verify D=100→000 | MG2100 service manual "EEPROM Save" | Tom's Hardware service-menu map |
| Reset normally requires a power-cycle to take effect (commit-then-boot) | tonercom Method B | EEPROM-info before/after verify flow |
| G5000/6000/7000/GM service mode LACKS the WIC-clear (accept-and-ignore) | PrinterKnowledge G5000–G7000 thread | Reddit r/printers G6020 "Canon disabled" |
| G6020 has NO user-replaceable maint. cartridge → counter in board EEPROM | Canon Community G6020 maint-cartridge | Amazon MC-G02 compat list (G6020 absent) |
| Maint-cartridge models reset via on-cartridge ST M24C16 (416RT) I2C chip | wangyu canon_mc-g02_resetter | Arduino/Hackster MC-G02 16 Kbit chip |
| Board EEPROM is directly writable (dump→edit records→write back) clears 5B00 | MG2450 whole-tail rewrite | ORPYS dump-library reset listing |

---

## 6. Confidence + residual unknowns

- **High confidence:** counter = per-absorber % values (D/D_BK/D_CL/Dp_HM/Dp_AW)
  in an I2C M24Cxx mainboard EEPROM; 100.0 = full; ServiceTool resets per
  absorber and verifies via EEPROM-info **print**/Save (D=100→000); the
  EEPROM is block/checksum-structured and directly re-writable with a programmer;
  G6020 has no maintenance-cartridge chip (counter is board-resident); the
  G5000/6000/7000/GM generation's service-mode WIC-clear is the disabled/removed
  path.
- **Medium confidence:** ACK-without-clear is a **removed gate** rather than an
  uncommitted write (leading, not certain); a missing-commit second opcode
  remains a live secondary hypothesis.
- **Low / unproven (needs our own capture or a board dump):**
  1. a **pure on-wire EEPROM readback** that confirms a reset on `04a9:12fe`
     **without** a power-cycle (the SEND-primed `D=` status reply) — plausible,
     undocumented for G6020;
  2. the **exact G6020 EEPROM part number/density** and the **byte offset(s)** of
     the absorber counters + the checksum algorithm — no public source; recover
     via **EEPROM Save** text dump from a working tool or a physical chip read;
  3. whether the working clear sequence carries a **per-reset nonce/token**
     (→ cloud-validated, native replay impossible) vs a **plain extra commit
     frame** (→ replayable, native tool viable) — the decisive §3 diff.

## Sources
- ORPYS Canon E404 dump (25Q16 IC303 + 24C08 IC302, board QM7-4508; "reset absorber 5B00/5B02, recover service mode"): https://orpys.com/en/dumps/497-canon-e404-dump.html
- badcaps "Canon Pixma MG2550S dump BIOS" (25q16 + 24c08[4g08]; "24c08 is erasable"): https://www.badcaps.net/forum/showthread.php?t=92191
- PrinterKnowledge MG2400/MG2500 (MG2450) — ST M24C08 teardown, ≥0xF0 reset block, record markers, WP pin-7→GND: https://www.printerknowledge.com/threads/how-to-actually-reset-ink-absorber-count-on-mg2400-and-mg2500-printers.16864/
- PrinterKnowledge G5000–G7000 — service-mode lacks WIC-clear; "whirrs then shuts down": https://www.printerknowledge.com/threads/canon-megatank-resetting-waste-counter-help-needed-g5000-g7000-series.16041/
- Reddit r/printers — "Canon disabled the ability to reset the WIC from service mode" (G6020): https://www.reddit.com/r/printers/comments/19d5m46/canon_pixma_g6020_waste_ink_counter_issue/
- WIC.support — 5B00/5B02/5B03/5B04/5B05/5B12/5B13/5B14/5B15 per-absorber meanings: https://www.wic.support/canon-service-errors-5b00-5b02-5b03-5b04-5b05-5b12-5b13-5b14-5b15-reset-solutions/
- easyFIXS MG5700 / MG3500 absorber code breakdowns: https://easyfixs.blogspot.com/2021/02/how-to-reset-canon-mg5700-series-and.html , https://easyfixs.blogspot.com/2021/03/how-to-reset-canon-mg3500-series-ink.html
- Canon MG2100–MG4200 simplified service manual (EEPROM Save = EEPROM info to PC/text; Clear Ink Counter): https://download.daidai.tw/pdf/service_manual/canon/Canon%20MG2100,%20MG2200,%20MG3100,%20MG3200,%20MG4100,%20MG4200%20series%20Simplified%20Service%20Manual%20Rev.%2002.pdf
- Tom's Hardware i-series service menu (1 EEPROM info print / 2 EEPROM initialize / 3 reset waste ink counter): https://forums.tomshardware.com/threads/canon-i-series-waste-ink-tank-error-reset.26876/
- tonercom 5B00 guide (Method B: Service Tool via USB, power-cycle): https://tonercom.net/2025/08/canon-5b00-reset-guide/
- wangyu canon_mc-g02_resetter (ST M24C16 / 416RT on MC-G02/MC-G01 cartridge; model list): https://github.com/wangyu-/canon_mc-g02_resetter
- Arduino blog / Hackster MC-G02 hack (16 Kbit / 2048 B cartridge chip): https://blog.arduino.cc/2022/04/06/reset-your-canon-printers-maintenance-cartridge-with-this-hack/ , https://www.hackster.io/kamaluddinkhan/hack-using-using-arduino-uno-reset-your-printer-f2dabb
- Canon Community — PIXMA G6020 maintenance cartridge (G6020 has no user-replaceable maint. cartridge): https://community.usa.canon.com/t5/Desktop-Inkjet-Printers/PIXMA-G6020-maintenance-cartridge/td-p/541987
- Canon MC-G02 compatibility (G1220/G2260/G3260/G620, GX6020/GX7020 — G6020 absent): https://www.usa.canon.com/shop/p/mc-g02-maintenance-cartridge
- iFixit — counter stored in EEPROM IC; some models need chip reprogram/replace: https://www.ifixit.com/Answers/View/502878/resetting+my+ink+absorber

---

*Provenance: live web search (DuckDuckGo MCP, SearXNG, WebSearch) + WebFetch /
fetch MCP all functioned this run. No upstream/leecher1337 contact. The two
decisive open items — a no-power-cycle on-wire readback on G6020 and the
gate-vs-commit branch — are not settled by public text and require our own
service-mode capture or a board EEPROM dump.*
