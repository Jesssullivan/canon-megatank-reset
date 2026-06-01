# SOTA Lane 1 — PIXMA lineage + OctoInkjet/Printer Potty + open-source reimplementations

> Public reading only. **No contact was made** with leecher1337, OctoInkjet,
> Printer Potty, or any upstream maintainer — the operator handles those
> relationships manually; this file only *proposes* collaboration asks.
> Every load-bearing claim is cross-checked across ≥2 sources and flagged for
> confidence. Compiled 2026-05-31.

---

## TL;DR for the fleet G6020 effort

1. **leecher1337/pixma is NOT a reset tool.** It is a firmware-*unpacking/
   analysis* toolkit (decrypt, SREC→bin, unpack payloads, decrypt `sdata.bin`).
   The author started it to chase a waste-ink reset, **"soon gave up,"** and it
   has **no service-mode, no waste-counter, no USB-command, and no G-series/
   MegaTank code at all.** Its forks (incl. the operator's own `Jesssullivan/
   pixma`) add only compile fixes — zero reset capability. (High confidence.)
2. **Printer Potty's G6020/G6050 reset IS WICReset-driven, not independent.**
   Their own G6000/G7000 support page states the G5 Printer Potty kit **"provides
   the necessary reset key to clear the waste ink counter"** and references the
   **"current 5.70 WICReset instructions shown by the app."** The kit is a
   *bundle* of (a) the physical external-tank waste hardware + (b) a **WICReset
   key**. They do **not** ship an independent counter-reset method. (High
   confidence — Printer Potty + OctoInkjet KB both.)
3. **The WICReset path is CLOUD-GATED at reset time.** OctoInkjet's own WICReset-
   key product page: **"An active internet connection is required for the key to
   be validated as part of the reset process."** Corroborated by iWICKey and
   wicresetutility ("connects to the server to confirm whether the Reset Key is
   valid"). This is the **strongest public evidence that the G5/G6/G7 reset is
   cloud-validated, not a free-standing local replay** — it tilts the project's
   central open question toward **cloud-nonce-gated** for the *vendor* path.
   (Medium-high confidence; see §4 caveats — "key validation online" is proven;
   whether the *device write itself* additionally carries a per-reset nonce is
   not separately proven from public text.)
4. **No open-source Canon waste-reset reimplementation reaches G-series.** The
   only "open" Canon repos are **mirrors of the closed ServiceTool `.exe`**
   (datvietcomputer, shpgn, filipegsilva88, Malcolm/Print_Tools). The one genuine
   open-source RE effort (BCH Technologies blog) is an **ideation post, not a
   project**. By contrast the **Epson** world has 4+ mature open resetters
   (Zedeldi, Ircama, reinkpy, jmbento) via SNMP — a sharp asymmetry: **Canon's
   maintenance channel has resisted open reimplementation where Epson's has
   not.** (High confidence.)
5. **The free local path exists ONLY for the OLD G1000–G4000 generation.**
   OctoInkjet: *"Canon Megatank G1000–G4000 series printers may be resettable
   using the printer's own keypad."* The G5/G6/G7/GM generation is exactly where
   that free keypad path stops and the paid cloud key begins — independently
   matching the established `g6020-servicetool` finding that Canon disabled the
   in-printer WIC reset on this generation. (High confidence.)

---

## (1) leecher1337/pixma + forks — Canon maintenance / service-mode / waste-counter capability

**Verdict: none.** `leecher1337/pixma` is "some little tools to unpack firmware
of Canon PIXMA series for analysis." Scope (from its readme):

- decrypt firmware files; decode SREC→binary; unpack firmware payloads; decrypt
  certificate data (`sdata.bin`).
- Built on the **Context IS 2016** "hacking Canon PIXMA printers" research.
- **Motivation explicitly was** a stuck waste-ink counter — but the author
  **"soon gave up on it."** No reset, no service mode, no USB command framing,
  **no G-series / MegaTank / waste-counter code.** (High confidence.)
  Source: https://github.com/leecher1337/pixma/blob/master/readme.txt

**Forks (via GitHub API `repos/leecher1337/pixma/forks`):**
- **`paulschreiber/pixma`** — compile-portability PRs only (include `string.h`,
  declare `compress` void, longs-vs-ints format strings). No reset work. These
  PRs were merged back into the operator's fork.
- **`Jesssullivan/pixma`** (the operator's own fork, created 2026-05-28, pushed
  2026-05-29) — at survey time its commit graph = upstream + the three
  paulschreiber compile fixes. **No service-mode / G6020 / waste-counter
  additions yet.** (This is the operator's active staging fork, not an upstream
  capability.) (High confidence — `gh api repos/Jesssullivan/pixma/commits`.)

**Implication for the project:** pixma is useful as a **firmware-introspection**
lever (e.g. to locate the WIC-clear opcode / commit routine inside G6020
firmware), NOT as a runtime reset path. If the lane wants pixma to contribute,
it would be as an *offline firmware-analysis* aid to find the genuine clear
sequence — complementary to the USB-capture approach, not a substitute.

---

## (2) OctoInkjet / Printer Potty — what their G6020/G6050 reset actually is

### The G5 Printer Potty kit = hardware tank + WICReset key (NOT an independent reset)
- Printer Potty G6000/G7000 support page (tagged `g6020 g6050 g6060 g7020 …`):
  *"The G5 printer Potty kit provides the **necessary reset key** to clear the
  waste ink counter along with the physical waste kit…"* and *"the current
  **5.70 WICReset instructions** shown by the app."* → their reset = **a WICReset
  key bundled with the tank**, period. (High confidence.)
  Source: https://support.printerpotty.com/2023/waste-ink-fix-for-canon-g6050-g7050-megatanks
- OctoInkjet KB "WICReset: Instructions, Access, Troubleshooting" frames the
  whole thing for *"customers who have already purchased a WICReset key either as
  a single item or as part of a Printer Potty kit+key bundle."* (High confidence.)
  Source: https://www.octoink.co.uk/docs/kb/wicreset-instructions-access-troubleshooting/
- The reset **is single-use / re-buy each time the absorber refills** ("The
  counter reset software is single use, so you will need to re-purchase that
  activation code every time"). This single-use-per-printer economic model is
  itself a signature of **server-side metered consumption** (see §4). (High
  confidence — OctoInkjet KB.)

### Their service-mode entry for G6000/G7000 (matches our device-side findings)
*"Press and hold the power button; press & release the stop (red triangle) button
5×… release the power button; the printer shows a block of grey/black across the
whole LED screen; WICReset can then refresh the detected device list and see the
printer in service mode."* — i.e. the same panel-entered service mode that
re-enumerates to `04a9:12fe`. Their explicit note: this differs from the
**"established guides (including the current 5.70 WICReset instructions shown by
the app)."** (High confidence; corroborates the in-repo transport doc.)

### IMPORTANT secondary find — Printer Potty's "possible manual button-only reset"
The same page lists a **button-only candidate reset for G6000/G7000** (5B00):
power off → hold **Black**, hold **Power**, release Black, **Stop ×5**, release
all, wait, **Stop ×5**, **Power** → prints a sheet with **"D value = 000.0"** →
power-cycle. They hedge it ("Possible manual way…"). **This is worth a lab
attempt** because, if it genuinely clears, it would be a **free local path that
contradicts the "fully disabled" framing** — but community evidence elsewhere
(Reddit/PrinterKnowledge) is that button-only methods do *not* clear on G6020,
so treat as **unverified / low-medium confidence** and test on the lab unit
with EEPROM read-back. Source: same Printer Potty page above.

### Is OctoInkjet's reset WICReset-driven or independent? — **WICReset-driven.**
Cross-checked: Printer Potty page (their own product) + OctoInkjet KB + the
WICReset-key product page all describe the *same* WICReset utility + cloud key.
There is **no evidence of an OctoInkjet-proprietary reset algorithm.** (High
confidence.)

---

## (3) Open-source Canon service-tool / waste-reset reimplementations + captures — catalog

| Project / artifact | What it is | How far it gets on G-series | URL |
|---|---|---|---|
| **leecher1337/pixma** (+forks) | Firmware unpack/decrypt only | **0** — no reset, no service mode | https://github.com/leecher1337/pixma |
| **datvietcomputer/Canon-service-tool-** | **Mirror of closed Canon ServiceTool `.exe`** (v5302/v5306 era) | Only as far as that closed `.exe` build's model table — not open code | https://github.com/datvietcomputer/Canon-service-tool- |
| **shpgn/service_tool_canon** (releases) | Mirror of closed ServiceTool releases | Same — closed binary redistribution | https://github.com/shpgn/service_tool_canon/releases |
| **filipegsilva88/Software_Canon_Service_Tool_V4906** | Mirror of closed ST v4906 | Old gen; no G6020 | https://github.com/filipegsilva88/Software_Canon_Service_Tool_V4906 |
| **Malcolm-GITHub/Print_Tools** | Bundle of closed Epson + Canon ST tools + procedures | Redistribution, not RE | https://github.com/Malcolm-GITHub/Print_Tools |
| **BCH Technologies blog** | *Ideation post* on building an OSS Canon ST alt; one contributor "sniffed USB control transfers" | **No repo, no capture published, no reset code** — concept only | https://bchtechnologies.com/blogs/blog/developing-an-opensource-alternative-to-canon-service-tool |
| **imatasic gist (G3000 WIC)** | Button-sequence note for **G3000** (old gen) | Old MegaTank only; not G6020 | https://gist.github.com/imatasic/5882ad193e30e9b9e4d7c3ce4d968777 |

**Adjacent (Epson, not Canon) — proves the technique is doable when the channel
isn't cloud-locked, and is a model worth porting *if* a local Canon path exists:**
| Project | Method | URL |
|---|---|---|
| **Zedeldi/epson-printer-snmp** | SNMP read/reset of waste counters; **explicitly derived parameters by packet-sniffing WICReset's requests** | https://github.com/Zedeldi/epson-printer-snmp |
| **Ircama/epson_print_conf** | Full Epson config + waste-reset tool, broad model coverage | https://github.com/Ircama/epson_print_conf |
| **atufi/reinkpy** | Open Epson waste resetter | https://codeberg.org/atufi/reinkpy |
| **jmbento/epson-ink-pad-resetter** | SNMP Epson resetter, "no subscriptions, no paid utilities" | https://github.com/jmbento/epson-ink-pad-resetter |

**Key asymmetry (high confidence):** Epson's waste counter lives in **SNMP/EEPROM
addresses that are locally readable/writable**, so the community has fully
reimplemented it open-source. **No equivalent exists for Canon G-series** — every
"open" Canon repo is a closed-binary mirror. That gap is consistent with the
Canon G5/G6/G7 reset being **gated** in a way the Epson one is not (cloud key
validation + disabled in-printer path).

**On captures specifically:** no *public* USB capture of a tool clearing 5B00 on
a G6020 (`04a9:12fe`) was found. The Zedeldi project's method note ("parameters
can be found using tools such as wicreset and checking the requests it sends") is
the closest published capture-based methodology, but it targets **Epson SNMP**,
not the Canon service-mode control channel. The authoritative G6020 capture
remains **un-published and must be produced in-lab** (consistent with the
established transport doc). (High confidence.)

---

## (4) Local-replay vs cloud-nonce gating — public evidence assessment

**Direction of the evidence: the vendor (WICReset) reset for the G5/G6/G7
generation is CLOUD-VALIDATED at reset time.** Specifics:

- **Direct (OctoInkjet, the seller):** *"An active internet connection is
  required for the key to be validated as part of the reset process."*
  https://www.octoink.co.uk/products/WICReset-Key(s).html (High confidence.)
- **Corroboration 1 (iWICKey):** *"WICReset requires an active Internet
  connection… you also need a valid key to be able to use the reset."*
  https://iwickey.com/troubleshooting (High confidence.)
- **Corroboration 2 (wicresetutility):** *"Wic Reset Utility will connect to the
  server to confirm whether the Reset Key is valid… you need an Internet
  connection while resetting."* (Medium — third-party WIC site.)
- **Economic tell:** the key is **single-use, per-printer, re-bought each
  refill** (OctoInkjet KB) — a metered, server-accounted consumable, which only
  makes sense if the server is in the loop **per reset**, not just per download.
  (Medium-high confidence inference.)
- **Architectural tell (from the established in-repo RE, MEMORY):** WICReset's
  binary carries **zero G6020 strings**; the per-model reset definition is pulled
  from **"WIC Reset Connect" cloud**. A tool that fetches its reset payload from
  the cloud per-model is the same architecture that can require the cloud
  per-*reset*. (High confidence on "definition is cloud-fed"; that it's *per
  reset* nonce-gated is the inference under test.)

**What this does and does NOT settle (the project's central question):**
- **Settled:** the **WICReset *key/authorization*** is online-validated. You
  cannot run the *vendor tool* offline. → A naive "replay WICReset's bytes with
  no internet" will fail at the **key-check** step. (High confidence.)
- **NOT settled by public text:** whether the **actual device-side write** that
  clears the EEPROM counter carries a **per-reset cryptographic nonce that the
  printer firmware verifies**, vs. whether the cloud check only gates the
  *software UX* and the **final USB control transfer to the printer is itself a
  static, replayable command**. These are very different worlds for the native
  fleet tool:
  - *If* the cloud only authorizes the **software** and then the tool sends a
    **static clear+commit sequence** to the printer → **local replay is possible**
    once that sequence is captured (native key-free fleet tool viable). The fact
    that older Canon ST resets were static IOCTL frames, and that WICReset reuses
    the *same usbscan IOCTL family* (established RE), keeps this door **open**.
  - *If* the printer firmware demands a **fresh server-signed token per reset**
    (challenge/response over the control channel) → **local replay is impossible**
    natively; you'd be forced to proxy the vendor cloud.
- **No public source resolves which of these two it is for G6020.** Resolving it
  requires the in-lab USB capture already prescribed: capture a *successful*
  WICReset Connect clear on `04a9:12fe` **with a network capture running in
  parallel**, then test whether **replaying only the USB control transfers
  (network unplugged) still clears** with EEPROM read-back. That single
  experiment is the decisive, currently-missing datum. (High confidence this is
  the right experiment; outcome unknown.)

**Net assessment (confidence: medium):** the weight of public evidence leans
**cloud-gated** for the vendor path on this generation — but "cloud-gates the
*key*" is proven while "cloud-gates the *device command itself*" is not, and the
shared-IOCTL/static-frame heritage leaves a real chance the on-wire clear is
**locally replayable** once captured. Treat "local replay impossible" as **not
yet established** — it is exactly what the capture-and-replay experiment must
falsify.

---

## (5) Concrete collaboration asks — PROPOSE ONLY (do not contact)

Routed to the operator's **leecher** and **Octo** contacts. The operator decides
whether/how to reach out.

**To the leecher1337 / pixma contact (firmware-analysis depth):**
1. Ask whether their pixma unpacker handles the **G6000/GM-generation firmware
   container** (newer SREC/crypto than the 2016 Context IS gen) — i.e. can it
   decrypt a G6020 firmware blob at all, as the lever to **locate the WIC-clear
   opcode + EEPROM-commit routine** statically.
2. Ask if they ever located, in any unpacked PIXMA firmware, the **service-mode
   command dispatch table** mapping the `bRequest`/cmd byte → handler — that
   table is the Rosetta stone for the `0x85 / 00 03 01 03 07` frame and whether a
   genuine clear handler exists (vs. accept-and-ignore) on this generation.
3. Ask whether the **per-reset value is firmware-signed**: does the unpacked
   firmware contain a public key / signature check on the maintenance command
   path (→ would confirm/deny the cloud-nonce hypothesis from the *device* side,
   independent of any capture).

**To the OctoInkjet / Printer Potty contact (they sell the working reset daily):**
4. Confirm the **G6020 reset specifically** goes through **WICReset Connect cloud
   key validation at reset time** (their product copy says internet-required;
   confirm it's per-reset, per-printer-serial, for the G6 generation).
5. Ask whether they have ever seen a **G6020 reset succeed fully offline** (or
   whether the WICReset app hard-fails without internet at the clear step) — this
   directly answers the local-replay question from operational experience.
6. Ask about their **"possible manual button-only reset (D=000.0 sheet)"** for
   G6000/G7000: have they confirmed it **actually clears 5B00** on a G6020 with
   the error already latched, or is it the ink-level/non-WIC path? (Their own
   page hedges it.)
7. Ask whether the **MC-G02 maintenance-box models vs. fixed-absorber models**
   split applies to the fleet's exact G6020 SKU — their page warns newer units
   have user-replaceable MC boxes; the fleet's reset strategy differs entirely
   between the two (chip-reset à la the Arduino MC-G02 hack vs. internal 5B00
   absorber-counter reset). Confirming which the fleet has prevents chasing the
   wrong reset.

---

## Sources (with relevance)

- **leecher1337/pixma readme** — firmware-unpack only; author "soon gave up" on the reset; no G-series. https://github.com/leecher1337/pixma/blob/master/readme.txt
- **GitHub API forks of pixma** — paulschreiber (compile fixes) + Jesssullivan (operator fork, compile fixes only). https://github.com/leecher1337/pixma
- **Printer Potty — G6000/G7000 waste-ink fix** — G5 kit "provides the necessary reset key"; "current 5.70 WICReset instructions"; service-mode entry; hedged button-only manual reset (D=000.0). Tagged g6020/g6050. https://support.printerpotty.com/2023/waste-ink-fix-for-canon-g6050-g7050-megatanks
- **OctoInkjet KB — WICReset instructions/access/troubleshooting** — kit+key bundle framing; single-use re-buy. https://www.octoink.co.uk/docs/kb/wicreset-instructions-access-troubleshooting/
- **OctoInkjet — WICReset Key product page** — "active internet connection is required for the key to be validated as part of the reset process"; "G1000–G4000 may be resettable using the printer's own keypad." https://www.octoink.co.uk/products/WICReset-Key(s).html
- **iWICKey troubleshooting** — "WICReset requires an active Internet connection… need a valid key to reset." https://iwickey.com/troubleshooting
- **wicresetutility** — "connect to the server to confirm whether the Reset Key is valid." https://wicresetutility.com/download/
- **wicresetconnect / wicreset.info / wicreset.pl** — WIC Reset Connect Canon reset (cloud, paid, 5B00). https://wicresetconnect.com/en/canon-g6020-ink-absorber-full-reset/ ; https://wicreset.info/en/ ; https://wicreset.pl/en/instrukcja-resetu-licznika-wic-reset-connect-canon/
- **BCH Technologies — "Developing an Open-Source Alternative to Canon Service Tool"** — ideation post; one contributor sniffed USB control transfers; no repo/capture/reset code. https://bchtechnologies.com/blogs/blog/developing-an-opensource-alternative-to-canon-service-tool
- **datvietcomputer / shpgn / filipegsilva88 / Malcolm Print_Tools** — closed ServiceTool `.exe` mirrors, not open RE. https://github.com/datvietcomputer/Canon-service-tool- ; https://github.com/shpgn/service_tool_canon/releases ; https://github.com/filipegsilva88/Software_Canon_Service_Tool_V4906 ; https://github.com/Malcolm-GITHub/Print_Tools
- **Zedeldi/epson-printer-snmp** — open Epson resetter; parameters found by sniffing WICReset requests (SNMP, Epson — the porting model). https://github.com/Zedeldi/epson-printer-snmp
- **Ircama/epson_print_conf ; atufi/reinkpy ; jmbento/epson-ink-pad-resetter** — mature open Epson waste resetters (the asymmetry vs. Canon). https://github.com/Ircama/epson_print_conf ; https://codeberg.org/atufi/reinkpy ; https://github.com/jmbento/epson-ink-pad-resetter
- **Arduino Blog / Hackaday — MC-G02 cartridge-chip reset hack** — resets the *cartridge chip* (local, Arduino, direct), NOT the internal 5B00 absorber counter — different problem; don't conflate. https://blog.arduino.cc/2022/04/06/reset-your-canon-printers-maintenance-cartridge-with-this-hack/ ; https://hackaday.io/project/184841-hack-using-using-arduino-uno-reset-your-printer
- **PrinterKnowledge — MegaTank G5000–G7000 waste-counter** — this generation's service mode lacks the built-in clear without a tool. https://www.printerknowledge.com/threads/canon-megatank-resetting-waste-counter-help-needed-g5000-g7000-series.16041/

---

*Provenance: live web search (WebSearch, DuckDuckGo MCP) + mcp__fetch + GitHub
API/gh all functioned. The two most load-bearing claims — (a) Printer Potty's
G6020 reset is WICReset-key-driven, not independent, and (b) the WICReset reset
requires online key validation at reset time — are each corroborated ≥2 sources.
The undecided crux (cloud-gates the **key** [proven] vs. cloud-gates the
**device command** [unproven]) is explicitly flagged and is resolvable only by
the in-lab capture-then-offline-replay experiment.*
