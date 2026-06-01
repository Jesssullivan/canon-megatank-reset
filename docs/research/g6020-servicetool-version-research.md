# Canon PIXMA G6020 (G6000-series MegaTank) — ServiceTool version & 5B00 absorber-reset research

> Public reading only. No contact was made with leecher1337 or any upstream
> maintainer. All claims are sourced inline; confidence is flagged per item.
> Compiled 2026-05-31.

---

## TL;DR for the fleet G6020 effort

1. **The single most important finding (corroborated):** the G6020 generation is
   **the model where Canon removed/disabled the in-printer service-mode WIC reset
   path** that works on older PIXMA/G-series. Multiple independent community
   reports say the classic "service mode → Stop ×N → reset" procedure shown in
   YouTube videos **does not clear 5B00 on the G6020**, even though the printer
   *does* enter service mode. This reframes your "device ACKs but does not clear"
   result: it is consistent not only with a wrong tool version, but with the
   counter-clear path itself being **gated/removed on this generation's
   firmware**. (Sources: Reddit r/printers G6020 WIC thread; PrinterKnowledge
   G6020 thread; Canon Community G7020 "refuses to reset".)
2. **Which ServiceTool builds list the G6000 series:** the **newer V6xxx line —
   ServiceTool V6.300 (STV6300, released 2024-02-18) and V6.310** — are the
   builds repair sites advertise as covering the full G6000 series **including
   G6020** (verbatim STV6300 list: G6000, G6010, G6011, **G6020**, G6030, G6040,
   G6050, G6060, G6065, G6070, G6080, G6090, G6091, G6092 … through G7092).
   **V5610** is also advertised as listing G6020 **and the full G5000 series**
   (G5000/G5010/**G5020**/G5040/G5050/G5070/G5080) — important because the G6020
   shares the GM/G5-G6 board generation. The older **V5302 / V5306** are the
   classic mid-gen builds; their advertised lists are dominated by the 2000s–2010s
   i/S/iX/MG/MX/TS line and do **not** reliably show G6020. **V5103 (your current
   build) targets G1000–G4000 and has no G6020 — confirmed by your own model-table
   finding.** STV6300 resets 5B00/5B02/5B04/5B14/1700/1701/1702 but carries an
   explicit caveat: it **"can be used only when the printer is placed in Service
   Mode" and does NOT work on printers with damaged EEPROM or 'disposable'
   models** — i.e. listing G6020 does not by itself prove the firmware honors the
   clear. (Sources: resetter.net STV6300; chiplessprinter V5610; YouTube ST
   v6.310 G-series; datvietcomputer.)
3. **Caveat that ties it together:** even the builds that *list* G6020 in their
   marketing model table may be relying on the same disabled firmware path — so a
   "G6020-compatible" ServiceTool build is **necessary but may not be sufficient**.
   The community's working answer for G6020 specifically has shifted to
   **WICReset / WIC Reset Connect** (a paid, cloud-fed per-model resetter), which
   is exactly the pivot already recorded in MEMORY. Confirm any ServiceTool build
   *actually clears* before trusting it, not just that the model appears in a list.

---

## (1) ServiceTool versions documented to support the G6020 / G6000 series

### Version lineage (with what each build's model table is advertised to cover)
ServiceTool ("ST", `Service_Tool_Vxxxx.exe`) ships a **fixed internal model
table** per build — a printer can only be reset by a build whose table contains
its model. This is the exact failure mode you hit with V5103.

| Build | Generation its table is advertised to cover | G6020 listed? |
|-------|---------------------------------------------|---------------|
| V4720 | older i/S/iX/MP/MG | no |
| **V5103** (your build) | **G1000–G4000 (2017 MegaTank gen), TS/MG** | **no — confirmed by your model table** |
| V5302 / V5306 | i/S/iX/MG/MX/TS mid-gen (huge legacy list) | not reliably; legacy-dominated |
| **V5610** | broader TS + **G6000 series incl. G6020** | **yes (advertised)** |
| **V6.300 (STV6300)** | newest-gen incl. **full G6000 series, G6020** | **yes (advertised)** |
| **V6.310** | newest public build; G-series MegaTank | **yes (advertised, G6000-series video)** |

Verbatim G6000-series list advertised for **STV6300**: "G6000, G6010, G6011,
**G6020**, G6030, G6040, G6050, G6060, G6065, G6070, G6080, G6090, G6091, G6092"
(resetter.net). **V5610** advertised G6000 list: "G6000, G6070, G6010, G6020,
G6040, G6050, G6070, G6080" (WebSearch of chiplessprinter/resetter). Errors these
builds claim to reset: **5B00, 1700, 1701, "Waste Ink Pad Reset", "Clear Ink
Counter."**

> **Action ranking for builds to obtain & test, highest first:**
> 1. **ServiceTool V6.310** (newest; explicitly demoed on G6000-series).
> 2. **ServiceTool V6.300 / STV6300** (explicit G6020 in list).
> 3. **ServiceTool V5610** (explicit G6020 in list).
> For each: open the model dropdown, confirm `G6020`/`G6000 series` is present,
> then verify it *actually clears* (read-back), because of the firmware-gating
> caveat below.

### Where these are obtained (public; ST is NOT distributed by Canon)
Public copies circulate via printer-repair communities. Canonical public landing
points found in this research (binaries themselves move/are unstable and may be
malware — get the identified *version* from a reputable community and verify the
dropdown + an actual clear before trusting):
- **resetter.net** — STV6300 / V5610 landing pages with the supported-model lists. https://resetter.net/canon-service-tool-version-6-300-v6300 ; https://resetter.net/canon-service-tool-5610
- **chiplessprinter.com** — V5610 supported-model list. https://chiplessprinter.com/canon-service-tool-v5610.html
- **github.com/datvietcomputer/Canon-service-tool-** and **github.com/shpgn/service_tool_canon/releases** — community ST mirrors (v5302/v5306 and others). https://github.com/datvietcomputer/Canon-service-tool- ; https://github.com/shpgn/service_tool_canon/releases
- **copytechnet.com** (Canon tech forum) — "New Canon Service Support Tool (SST) Version 5.1" and ST↔model discussion. https://www.copytechnet.com/forum/tech-support/canon/1595742-new-canon-service-support-tool-sst-version-5-1
- **scribd easyFIXS "Canon Service Tools and Supported Printers"** — tables mapping models → manual-reset vs General-Tool vs ServiceTool. https://www.scribd.com/document/630960408/easyFIXS-Canon-Service-Tools-and-Supported-Printers-pdf
- **YouTube** — "NEW Service Tool Version! Reset Canon Pixma G-Series" (v6.310). https://www.youtube.com/watch?v=99hWbeVUMg4 ; "Reset Canon + Service mode G6010 G6020 …" https://www.youtube.com/watch?v=je6lvKDTYeg

---

## (2) Community-documented G6020 service-mode (5B00) reset procedure + specifics

### Service-mode ENTRY (corroborated across multiple sources)
G6020 uses the modern **Stop + Power** entry (not the old resume-tap dance):
1. Power OFF (stay plugged in).
2. Press & **hold Stop** (▢/✕).
3. While holding Stop, press & **hold Power**; the printer powers on.
4. **Release Stop** (keep holding Power).
5. **Press/release Stop 5 times.**
6. After the 5th tap, wait a moment, then **release Power.** The printer enters
   service mode (solid/block-color panel). If it doesn't, unplug 10–15 s and
   retry. (Sources: WebSearch wicreset.info/G6020; Facebook ElectronicParts;
   PrinterKnowledge G6020 thread "I have figured out how to put it into service
   mode.")

> NOTE: your own MEMORY records the alternate **resume/cancel ×5** combo working
> on the lab unit to reach the block-color LCD and the `04a9:12fe` service device.
> Both entry combos appear in the wild; the device-enumeration change (→ `12fe`)
> is the real success signal, not the exact tap dance.

### The reset itself — and the G6020-specific wall (KEY)
- **Standard service-mode/YouTube reset DOES NOT clear 5B00 on the G6020.** This
  is the crux finding and is multiply corroborated:
  - **Reddit r/printers (G6020 WIC issue):** *"On the G6020, Canon disabled the
    ability to reset the Waste Ink Counter (WIC) from the service mode. On other
    models you would enter service mode by continuously pressing the ON/OFF
    button and then pressing the 'STOP' button five times … You could then reset
    the WIC pressing the STOP button 3 times."* — i.e. **STOP ×3 = the WIC clear
    on older models, disabled on G6020.** https://www.reddit.com/r/printers/comments/19d5m46/canon_pixma_g6020_waste_ink_counter_issue/
  - **PrinterKnowledge (G6020 Woes …5B00, p.2):** *"The instructions showcased in
    that video do not work on the G6020, but I have figured out how to put it into
    service mode."* (entry works, clear doesn't via the video method). https://www.printerknowledge.com/threads/g6020-woes-black-no-print-and-now-5b00.15539/page-2
  - **Canon Community (G7020 Error 5B00 … refuses to reset):** same-generation
    sibling, same "refuses to reset" symptom. https://community.usa.canon.com/t5/Desktop-Inkjet-Printers/PIXMA-G7020-Error-5B00-refuses-to-reset/td-p/442624
  - **PrinterKnowledge (Canon MegaTank waste-counter, G5000–G7000):** *"The
    G50xx/60xx/70xx and GM series seems to be an in-between generation … with the
    exception of service mode lacking (at least to my knowledge) the functionality
    of resetting the waste counter without the use of a [tool]."* — independent
    confirmation that this whole generation's service mode lacks the built-in
    waste-counter clear. https://www.printerknowledge.com/threads/canon-megatank-resetting-waste-counter-help-needed-g5000-g7000-series.16041/
  - **PrinterKnowledge (G6020 Woes p.2), direct user attempt:** entry combo that
    worked = **"hold the color button, then press & hold power; let go of color,
    hit Stop five times, then let go of power"**; and *"I have not been able to
    get anything to happen once it's in service mode"* — service mode reached, but
    no button sequence does the clear. A moderator adds the WIC clear needs *"the
    right version of the software tool."*
- **The supported-tool path (when a G6020-listing ST build works):** in service
  mode over USB, in ST's **Clear Ink Counter / Ink Absorber** group, set
  **Main → Set** and **Platen → Set**, ST sends the maintenance command, device
  commits to EEPROM, ST prompts a **power-cycle**, 5B00 clears on next boot.
  Confirm via ST **EEPROM-info read-back** (counter should drop from ~100%+ to
  ~0% and survive the power-cycle). (Sources: tonercom 5B00 guide "Method B:
  Service Tool via USB"; printerpotty G6000/G7000 fix; realitypathing.)

### Byte-level / counter-index specifics (the crux of your blocker)
- Your reverse-engineered frame `00 03 01 03 07` (**idx 0x07 = "Main"**) is the
  **V5103-generation** mapping (Platen=0x00, Main_Black=0x01, Main_Color=0x03,
  Main&Platen=0x06, Main=0x07 — from your own v5103 RE). On the G6020 the device
  **ACKs but does not clear** — and the community evidence above says the G6020's
  WIC-clear path is **firmware-gated/disabled**, so the most likely explanations,
  in order:
  1. **The G6020 firmware does not honor the clear via this path at all** (Canon
     disabled service-mode WIC reset on this generation) — i.e. no byte tweak on
     the V5103-shaped frame will work; a *different* mechanism (the one
     WICReset/STV6300 uses) is required.
  2. **Missing EEPROM-commit/save step** after the counter-write (ACK-without-
     clear is the classic uncommitted-write signature) — look for a *second*
     control transfer after the clear and replay it.
  3. **Different counter index** on the GM/G6000 board than 0x07.
- **No public source exposes the literal G6020 counter bytes/offsets.** WICReset
  pulls the per-model reset definition from its **cloud** ("WIC Reset Connect"),
  so its binary has zero G6020 strings (already in MEMORY). The authoritative way
  to get the *correct* G6020 sequence is a **USB capture of a tool that actually
  clears** (STV6300/V6310 if it works, or WICReset Connect) over the `04a9:12fe`
  control endpoint. (Sources: printerknowledge "special software tool"; reddit
  "special service tool"; your own MEMORY/WICReset RE.)

---

## (3) Does G-series service mode report `MDL:Device` generically?

- In **service mode** the G6020 enumerates as a **different USB device** —
  `04a9:12fe`, a single printer-class interface — and answers the IEEE-1284
  device-ID query with a service-mode string. Your live capture shows it returns
  `MFG:Canon;CMD:BJL,…;PSE:KMDA10021` and the SN, i.e. it does **not** advertise a
  clean `MDL:G6000 series` the way normal mode (`04a9:1865`) does; the maintenance
  identity is generic/BJL-class. This matches the general pattern that recent
  Canon service mode presents a **stripped/generic device ID**, so a service-mode
  `lsusb`/descriptor probe is unreliable for model detection. (Source: your own
  MEMORY live captures; general behavior corroborated by the multi-model
  ServiceTool design.)
- **How the correct ST identifies the model:** not from the service-mode `MDL:`
  string. ST keys off the **USB Product ID** (Canon VID `0x04A9`; service-mode
  PID `0x12fe`) and/or a **model/EEPROM query maintenance command** matched
  against its **internal model table**; in many builds the operator also selects
  the model group in the UI. Practical consequence: a generic/`Device`-style MDL
  is **normal** and is **not** proof you have the wrong tool — what matters is
  whether the ST build maps the **PID `12fe`** to a real, *non-disabled* reset
  routine for G6020. (Inference grounded in your live PID findings + ST's
  multi-model architecture; needs confirmation against a build that lists G6020.)

---

## (4) Public detail on Canon service-mode USB maintenance command structure

Your team has already **cracked the transport** (in MEMORY) and it agrees with
the sparse public understanding:
- **Transport = USB CONTROL transfers, not bulk.** On Linux the `12fe`
  printer-class bulk OUT (0x01) times out and bulk IN (0x82) only ZLPs; the
  Windows usbprint IOCTL frame `[cmd][arg_hi][arg_lo][payload]` maps to a USB
  **control** transfer.
- **Reads = class control-IN** `bmRequestType=0xA1`: `bRequest=0x00`
  (GET_DEVICE_ID → the 1284 ID), `bRequest=0x01` (GET_PORT_STATUS → 1 byte
  `0x18`).
- **Absorber reset = vendor control-OUT:** `bmRequestType=0x40, bRequest=0x85,
  wValue=0x0000, wIndex=0x0000, data=[00 03 01 03 07]` (idx 0x07 Main) → device
  **ACK 5**. (i.e. `bRequest` carries the cmd byte, `wValue/wIndex` carry the
  arg, the data stage carries the payload — the IOCTL-frame-to-control mapping.)
- **EEPROM-commit / save step (the likely missing piece OR the disabled gate):**
  Canon flows generally follow a counter-write with an explicit commit/flush and
  a power-cycle/service-exit that persists NVRAM. **An ACK with no clear is the
  signature of an uncommitted write — OR of a firmware that accepts-and-ignores
  the command on a disabled path.** Given the section-(2) evidence that G6020's
  WIC reset is gated, prioritize: (a) capture a tool that *actually clears* and
  diff its control-transfer sequence against `0x40/0x85/…`; (b) hunt for a
  post-clear commit transfer; (c) verify with EEPROM read-back across a
  power-cycle.
- **No public source publishes the GM/G6000 `bRequest`/`wValue` constants or the
  commit opcode.** The authoritative source is a USB capture of a working tool.
  (Sources: your own MEMORY transport crack; general Canon service-flow
  descriptions in tonercom/realitypathing/printerpotty.)

---

## Recommended next actions (closing the blocker)

1. **Obtain & test ServiceTool V6.310, then V6.300/STV6300, then V5610** — in that
   order. For each: confirm `G6020` in the dropdown **and** that it *actually
   clears* (EEPROM read-back), because the model may be listed but the firmware
   path disabled.
2. **If no ST build clears it:** treat **WICReset / WIC Reset Connect** as the
   real working tool for G6020 (matches your MEMORY pivot) and **USB-capture it**
   clearing over `04a9:12fe` to learn the genuine control-transfer sequence +
   commit step.
3. **Diff the working sequence** against your `0x40/0x85/wValue=0/data=00 03 01 03
   07` frame to find what the G6020 generation actually requires (different
   index? extra commit transfer? different bRequest?).
4. **Always gate on physical safety:** new waste-ink pads installed before any
   real reset (per OctoInkjet) — a reset on a full absorber overflows. OctoInkjet
   now ships a **G5 Printer Potty kit covering the G6020/G6050 MegaTank with video
   guides for fitting the tank AND resetting the waste-ink counter** — that reset
   guide is the operator-facing companion to the tool work here and worth pulling.
   https://www.facebook.com/octoinkjet/posts/the-g5-printer-potty-kit-now-covers-the-g6050-g6020-canon-megatank-printers-with/725658642896527/

## Sources (with relevance)
- Reddit r/printers — **G6020: "Canon disabled the ability to reset the WIC from service mode"; older models STOP×5 enter, STOP×3 clears.** https://www.reddit.com/r/printers/comments/19d5m46/canon_pixma_g6020_waste_ink_counter_issue/
- PrinterKnowledge — **G6020: standard video method does not clear; service-mode entry figured out.** https://www.printerknowledge.com/threads/g6020-woes-black-no-print-and-now-5b00.15539/page-2
- PrinterKnowledge — **newest Canon printers don't work with known service tools/methods.** https://www.printerknowledge.com/threads/service-tools-for-canon-printers.10985/
- Canon Community — **G7020 (sibling) 5B00 refuses to reset.** https://community.usa.canon.com/t5/Desktop-Inkjet-Printers/PIXMA-G7020-Error-5B00-refuses-to-reset/td-p/442624
- Canon Community — **PIXMA G6020 service mode and ink absorbers.** https://community.usa.canon.com/t5/Desktop-Inkjet-Printers/PIXMA-G6020-service-mode-and-ink-absorbers/td-p/361640
- Canon Community — **G6020 5B00 code (waste tank counter d=100).** https://community.usa.canon.com/t5/Desktop-Inkjet-Printers/G6020-5B00-Code-Waste-Tank-Empty-absorber-dry-clogged-black/td-p/542067
- resetter.net — **STV6300 supported list includes G6020; resets 5B00/1700/1701.** https://resetter.net/canon-service-tool-version-6-300-v6300
- resetter.net — **V5610 G6000-series support.** https://resetter.net/canon-service-tool-5610
- chiplessprinter.com — **V5610 supported-model list (G6020 listed).** https://chiplessprinter.com/canon-service-tool-v5610.html
- YouTube — **"NEW Service Tool Version!" ST v6.310, Canon G-series.** https://www.youtube.com/watch?v=99hWbeVUMg4
- YouTube — **"Reset Canon + Service mode G6010 G6020 …" 5B00.** https://www.youtube.com/watch?v=je6lvKDTYeg
- github.com/datvietcomputer/Canon-service-tool- — **community ST mirror (v5302/v5306).** https://github.com/datvietcomputer/Canon-service-tool-
- github.com/shpgn/service_tool_canon/releases — **community ST release mirror.** https://github.com/shpgn/service_tool_canon/releases
- copytechnet.com — **Canon tech forum, ST/SST version discussion.** https://www.copytechnet.com/forum/tech-support/canon/1595742-new-canon-service-support-tool-sst-version-5-1
- scribd easyFIXS — **Canon Service Tools & supported printers tables.** https://www.scribd.com/document/630960408/easyFIXS-Canon-Service-Tools-and-Supported-Printers-pdf
- tonercom — **5B00 reset guide, "Method B: Service Tool via USB" (Main/Platen/Waste Ink reset, power-cycle).** https://tonercom.net/2025/08/canon-5b00-reset-guide/
- printerpotty — **G6000/G7000 MegaTank waste-ink fix.** https://support.printerpotty.com/2023/waste-ink-fix-for-canon-g6050-g7050-megatanks
- Canon official — **Support Code 5B00 (absorber full, "service required").** https://support.usa.canon.com/kb/s/article/ART143380
- Canon official — **Reset the Ink LEVEL counter, G5020/G6020/G7020 (note: ink-level, NOT the waste/absorber WIC — do not confuse).** https://support.usa.canon.com/kb/s/article/ART183658
- PrinterKnowledge — **MegaTank G5000–G7000: this generation's service mode lacks the built-in waste-counter reset.** https://www.printerknowledge.com/threads/canon-megatank-resetting-waste-counter-help-needed-g5000-g7000-series.16041/
- OctoInkjet (octoink.co.uk) — **WICReset instructions/access/troubleshooting.** https://www.octoink.co.uk/docs/kb/wicreset-instructions-access-troubleshooting/
- OctoInkjet (Facebook) — **G5 Printer Potty kit now covers G6020/G6050 with waste-counter reset video guide.** https://www.facebook.com/octoinkjet/posts/the-g5-printer-potty-kit-now-covers-the-g6050-g6020-canon-megatank-printers-with/725658642896527/
- wicresetconnect.com — **G6020 ink-absorber-full reset (paid cloud resetter).** https://wicresetconnect.com/en/canon-g6020-ink-absorber-full-reset/

---

*Provenance note: live web search (DuckDuckGo, SearXNG, WebSearch) and WebFetch
all functioned for this research; cited URLs are from those live results. The two
load-bearing factual claims — (a) V5103 lacks G6020 / V6.300+/V5610 advertise it,
and (b) Canon disabled service-mode WIC reset on the G6020 generation — are each
multiply corroborated above. The literal G6020 counter bytes and the
clear-vs-disabled question are NOT settled by public text and require a USB
capture of a tool that actually clears.*
