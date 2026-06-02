# Canon service-mode RE field guide — unbricking a 5B00 "waste ink absorber full" printer (PIXMA / MegaTank / G-series), model-agnostic

> **What this is.** A generalized, model-**agnostic** field guide to Canon's
> USB **service-mode** maintenance protocol and how we reverse-engineered it:
> entering service mode, the **vendor control-transfer** transport, the
> session/keyword **handshake**, reading status/**EEPROM**-counter registers, the
> waste-ink absorber counter and its **commit-on-power-button** behavior, the
> cipher/obfuscation you should expect, and the **usbmon ↔ Frida ↔ Ghidra**
> instrumentation trifecta that recovers all of it. It is written for the next
> person trying to **unbrick** or **reset the waste counter** on *their* Canon —
> whether or not it is the G6020 we validated here.
>
> Keywords for the next searcher: **Canon 5B00**, **5B00 ink absorber is full**,
> **waste ink absorber full**, **service mode**, **unbrick Canon printer**,
> **reset waste counter**, **MegaTank / PIXMA / G-series**, **EEPROM counter**,
> **Canon Service Tool / WICReset alternative**, **native Linux / libusb reset**.
>
> **Scope of truth.** Concrete bytes, PIDs, IOCTLs, ciphers, and register
> contents below were validated on a **Canon PIXMA G6020** (the unit this repo was
> built around). They are marked **(G6020-observed)**. The *method* generalizes;
> the *specific numbers* are model-specific and must be re-derived per model.
> Every protocol/byte claim cites a `docs/research/*` evidence note or
> [`../TOOLS.md`](../TOOLS.md). We do **not** assert findings for models we did
> not test.

---

## (a) Orientation — you have a Canon stuck on a service code

If your Canon refuses to print and shows **`5B00`** (or `5B01`, `1700`, `1701`,
`1702`, the flashing-light "absorber full" support code, etc.), the printer's
firmware has decided an internal **waste-ink absorber counter** has crossed a
threshold. That counter lives in **non-volatile memory (EEPROM/NVRAM)** on the
mainboard. Canon's only sanctioned remedy is a service-centre visit; the
unsanctioned ones are a Windows-only **Canon Service Tool** or a commercial
resetter (**WICReset / Printer Potty**) that charges a **single-use key per
printer**. This repo recovered the reset protocol from those tools (used strictly
as **interoperability oracles**) and reimplemented it as open, native Linux code.

This is the **pre-trodden path** for the next reparability effort. You are most
likely here because the absorber is *physically serviceable* (you can fit new pads
or an external waste tank) but a software counter has bricked an otherwise-working
machine.

**Read this first — the safety/right-to-repair framing.** This is a tool for
hardware **you own**:

- **Physically service the absorber before you reset the counter.** Resetting
  lets the printer print again; if the absorber is genuinely full, printing risks
  ink overflow. See [SECURITY.md](https://github.com/Jesssullivan/canon-megatank-reset/blob/main/SECURITY.md) (Responsible use).
- **Why this is legitimate** — the right-to-repair posture, the dual-use line we
  hold, and the "no binary/firmware redistribution; oracles only" rule are in
  [RIGHT-TO-REPAIR.md](https://github.com/Jesssullivan/canon-megatank-reset/blob/main/ETHICS/RIGHT-TO-REPAIR.md) and
  [SECURITY.md](https://github.com/Jesssullivan/canon-megatank-reset/blob/main/SECURITY.md).
- The device-side reset is **cloud-independent**: by decompile, **zero** cloud
  bytes feed the reset payload, the keyword binding, or the completion test
  (G6020-observed). The vendor cloud
  is a *licensing* gate, not part of the repair.

The validated end-to-end procedure for the G6020 specifically is
[`../runbook/g6020-native-reset.md`](../runbook/g6020-native-reset.md); the
methodology/posture record is
[`../adr/0007-canon-tool-reverse-engineering.md`](../adr/0007-canon-tool-reverse-engineering.md).
Everything below is the *generalized* version of how that was reached.

---

## (b) Establishing service-mode comms

### Entering service mode (the button-combo concept)

Service mode is a **device-side firmware state entered by a front-panel button
sequence**, not by any USB request — there is no "enter service mode" opcode.
The general G-series recipe is: power off, hold **Stop/Resume**, press+hold
**Power**, release Stop, then tap **Stop ~5–6×** while still holding Power, then
release Power (G6020-observed; the exact tap count is model-specific — find your
model's sequence in Canon community/service docs). On other PIXMA families the
combo differs but the *shape* is the same: a Power + Stop/Resume button dance.

**You cannot drive this over USB. A human presses the buttons.** Until the panel
sequence succeeds, every resetter is inert ("stays grey", "resets only if in
service mode") — confirmed by community sources and by the tools' own behavior.

### USB re-enumeration — normal PID vs service PID

The decisive, scriptable signal that you actually entered service mode is that the
**printer re-enumerates with a different USB identity**:

| Mode | PID (G6020-observed) | Interfaces |
|---|---|---|
| Normal | `04a9:1865` | 6 interfaces incl. a still-image (usbscan) interface |
| **Service** | **`04a9:12fe`** | a **single printer-class interface**, EP `0x01` OUT / `0x82` IN |

(G6020-observed; [`../TOOLS.md`](../TOOLS.md) §1.) On a **different model** the VID stays
`04a9` (Canon) but the **service PID will differ** — do not hardcode `12fe`.
Discover it by enumerating before/after the button combo (`lsusb`; on Linux watch
`dmesg`/`udevadm monitor`) and noting the *new* PID that appears with a single
printer-class interface. The new identity also means **endpoint and interface
numbers change** — you must re-enumerate fresh after entry, not reuse normal-mode
descriptors.

### Binding / opening the device

- **Linux (recommended):** open the service-PID device with **libusb / pyusb**,
  claim the printer-class interface. If the kernel `usblp`/`usbprint` driver has
  grabbed it, detach the kernel driver first. (The native tool here is pyusb;
  see [`../TOOLS.md`](../TOOLS.md).)
- **Windows:** the device binds to the **`usbprint.sys`** printer-class minidriver
  in service mode (it binds `usbscan.sys` in normal mode). The proprietary tools
  reach it via `CreateFile` + `DeviceIoControl` IOCTLs — see (c).

### How to *discover* the transport on an unknown model

1. Enumerate the service-PID device and read its descriptors — confirm a
   printer-class interface and note the bulk EP pair.
2. Read **IEEE-1284 `GET_DEVICE_ID`** (class control-IN, `bmRequestType=0xA1`,
   `bRequest=0x00`) on EP0 — a valid `MFG:Canon;…;MDL:…` string confirms you have
   the right interface bound (this is also how the tools "detect" service mode).
3. Then probe the vendor transport in (c). Tap the wire with **usbmon** while a
   known-good tool talks to a known-good device — the wire is the arbiter (g).

---

## (c) The transport — vendor control transfers

**The maintenance command channel is USB EP0 VENDOR control transfers**, recovered
authoritatively by static decompile of Windows `usbprint.sys` and confirmed on the
live device. The authoritative mapping is:

| Direction | bmRequestType | bRequest | wValue | wIndex | Data stage |
|---|---|---|---|---|---|
| **SET** (host→device) | **`0x41`** (vendor, interface, OUT) | command byte (`inBuf[0]`) | `(inBuf[1]<<8)\|inBuf[2]` | interface (`0x0000` for the single iface) | **the entire frame**, verbatim |
| **GET** (device→host) | **`0xC1`** (vendor, interface, IN) | command byte | `(inBuf[1]<<8)\|inBuf[2]` | interface | reply of `OutputBufferLength` bytes |

How this maps from the Windows side: the tools never assemble a USB setup packet —
they emit `DeviceIoControl` IOCTLs to the minidriver, which builds the URB. The
decompile of `usbprint.sys` shows IOCTL **`0x220038` (VENDOR_SET) → control-OUT
`0x41`** and **`0x22003c` (VENDOR_GET) → control-IN `0xC1`**, with
`bRequest = inBuf[0]`, `wValue = (inBuf[1]<<8)|inBuf[2]`, and **the whole input
buffer placed in the data stage**. (In service mode the runtime usbprint object may issue these via the
DeviceType-`0x16` family IOCTL `0x16000c`; at Win32 none is a raw control transfer
— all are buffered `DeviceIoControl`.)

**The critical gotcha — do not strip the prefix.** The first three bytes of the
frame seed `bRequest`/`wValue` **and remain the first three bytes of the data
stage**. usbprint sends the *entire* `InputBuffer` as the OUT data with
`wLength = len(frame)`. Earlier native attempts STALLed (libusb "Pipe error")
because they tried to split the frame — sending part as setup and a stripped
remainder as data. **Send the frame verbatim** as the data stage.

**The page-cap / clamp gotcha.** `usbprint.sys` (Win11 26100.8328) caps a control
OUT/IN buffer at **one page (4096 bytes)**; a tool asking for a larger
`GET_1284_ID` read (e.g. 5000) gets `ERROR_CRC`. The capture rig works around this
by clamping `nOutBufferSize` 5000→4096 with a Frida hook
(`frida-1284clamp-hook.js`; [`../TOOLS.md`](../TOOLS.md) §3). On a new model, if a
large read errors, **clamp your request to ≤ 4096** (or read in page-sized chunks).

> **Historical note for cross-readers.** An earlier research lane concluded the
> SEND was a **bulk-OUT on EP `0x01`** with the reply over control-IN, written
> before the `usbprint.sys` decompile. The later, authoritative
> decompile shows the SET is the vendor **control-OUT `0x41`** above, and the live
> reset log used `0x41` SET / `0xC1` GET successfully. On an unknown
> model, **let usbmon settle bulk-vs-control** rather than assuming either — see (g).

---

## (d) Handshake structures — session → keyword → command

The maintenance exchange is an ordered handshake. Recognizing this shape on an
unknown model is the key to talking to it:

```
set_session   SET 0x81 ...      (plain)   ── opens a session
get_keyword   GET 0x82          (read)    ── device returns a LIVE per-session keyword
set_command   SET 0x85 ...                ── the actual maintenance command (operand)
get_command   GET 0x86          (read)    ── poll for the status/completion reply
```

What each does (G6020-observed):

- **`set_session` (`0x81`)** — plain, no keyword yet. Live frame observed:
  `81 00 00 03` (ACK'd `OK(4)`). A genuine WICReset frame also carried a 4-byte
  trailer `… 2d 2d ba 2b`; the bare `81 00 00 03` was accepted on the live G6020.
- **`get_keyword` (`0x82`)** — returns a **fresh per-session keyword** (G6020:
  **3 bytes**, e.g. `e4 7c 5a`, `cc da ea`, `8b 12 d7` — different every session).
  This keyword keys the **read obfuscation** (e), not the write (see below).
- **`set_command` (`0x85`)** — the maintenance command, e.g. waste-row **selector**
  `85 00 00 00 00 10 07 7c` then **clear** `85 00 00 00 00 0d 00 00` (G6020 5B00
  "common" clear). These plain operand frames were **ACK'd `OK(8)`**.
- **`get_command` (`0x86`)** — read/poll for the completion status reply (see (e)).

**Reads are SEND-primed, not free-running.** A read is "prime then read": SEND a
`0x82`/`0x86`/`0x85`-query frame, *then* read the reply. A cold bare RECV with
nothing armed **times out** (errno 110) — there is no unsolicited status stream.

**How to recognize a session/keyword handshake on a new model.** Watch the wire
(g) while a known-good tool resets a known-good unit and look for: (1) an early
plain SET that takes no keyword (the session open); (2) a GET that returns a small
random-looking value that **changes every session with constant device state** —
that is the live keyword; (3) subsequent SETs whose payloads vary with that keyword
(keyed) or stay constant for a given operand (plain). The command bytes
(`0x81/0x82/0x85/0x86/0x8a/0x84/0x8c …`) may differ per model — identify them by
*role*, not by assuming the G6020 numbers.

---

## (e) Buffer / reply examination

**Reading replies = control-IN (`0xC1`) after priming the matching SET.** The read
length is whatever `OutputBufferLength` you ask for (mind the 4096 cap, (c)).

**The empty-completion-read nuance (the `0x86` example).** On the G6020 the genuine
completion path polls **`get_command 0x86`** for up to **600,000 ms (10 min)**,
waiting only on the device's own reply **byte-count** — it exits on the first
**non-empty** length-prefixed reply, or the deadline. In the live run the
`0x85` writes **ACK'd (`ret=1` / `OK(8)`)** but **`0x86` kept returning empty**
(`bytesRet=0`), so "Processing…" hung. This exposes a crucial distinction:

- **"Accepted"** — the device ACKs the control transfer (the write byte was taken
  into the session). An ACK is **not** a commit.
- **"Committed"** — the value is persisted to the absorber EEPROM. On the G6020 the
  in-session write was accepted but **never produced the non-empty `0x86` status
  reply** the genuine path treats as "completed", i.e. the commit happens elsewhere
  (see (f) — the power-button shutdown).

> The adversarial review is honest that "accepted-but-uncommitted" vs
> "silently-rejected/incomplete sequence" is **not yet distinguishable** from the
> single trace in hand. Either way the cause is **local** (framing /
> sequence / commit), not the cloud. Treat an empty completion read as
> *inconclusive*, and confirm the actual outcome with a **post-power-cycle counter
> read**, not the in-session reply.

**How to probe registers safely.** Reads are non-destructive. Distinguish *status/
descriptor* registers from the *live counter* by reading the **same register
before and after** a state change: a register whose decoded plaintext is **identical
before and after** a clear is a descriptor, not the counter (see (f)). Keep probing read-only
until you have positively identified the counter — do not issue write/clear
operands while exploring.

---

## (f) Counter / EEPROM & memory model

The waste-ink absorber counter is a value in the printer's **EEPROM/NVRAM** that
firmware increments as it parks ink in the absorber, and tests against a threshold
to raise 5B00. The reset's job is to write that counter back down.

**The encoded readback registers (G6020-observed).** Service-mode status reads come
back **obfuscated** with the live session keyword (e). On the G6020:

- **`0x84`** — a **constant device/status descriptor**, *not* the live counter:
  decoded plaintext is **byte-identical before and after** an in-session clear, and
  the codec is a simple keyword-XOR stream (fully cracked; (h)).
- **`0x8c`** — the **more likely counter register** (it *does* vary independently),
  but its codec is a **nonlinear** keyword key-schedule and is **not yet cracked**.

**The commit-on-clean-power-button behavior (G6020-observed).** The 5B00 state does
**not** commit on the in-session write alone, and it does **not** commit on a raw
**unplug**. It commits when the printer performs a **clean power-button shutdown**
out of service mode (after which it reboots to the normal PID `04a9:1865`). So the
operator sequence is: enter service mode → SEND the selector + clear operands →
**power off with the power button** → verify with a post-power-cycle counter read
(see [`../runbook/g6020-native-reset.md`](../runbook/g6020-native-reset.md)). **Never
yank power to "save" the reset** — let the firmware shut down cleanly so it flushes
the EEPROM.

**How to find the counter on a new model.** (1) Enumerate the read commands and
read each register over several sessions of constant state — the keyword changes
but a given register's *plaintext* should be constant. (2) Crack the per-register
read codec ((e)/(h)) enough to compare plaintexts. (3) Issue a clear (only once you
trust the write path), power-button cycle, and re-read: the register whose decoded
value **drops** is the counter. (4) Cross-check the operand against the model's
template DB (h) and a cross-validation method.

---

## (g) The instrumentation TRIFECTA as a reusable method

The reliable way to recover any of the above on a new model is three **independent**
evidence lanes, cross-correlated by wall-clock timestamp and the deterministic
payload — no single lane is sufficient; each anchors the others. The full workbench
inventory and reproduction commands are in [`../TOOLS.md`](../TOOLS.md); the loop is
drawn in [`../diagrams/methodology-trifecta.mmd`](../diagrams/methodology-trifecta.mmd).

```
  LANE 1 — usbmon            LANE 2 — Frida                LANE 3 — Ghidra
  (host WIRE truth)          (host IOCTL / DRM)            (offline DECOMPILE)
  dumpcap -i usbmonN         hook DeviceIoControl,         driver IOCTL→URB map,
  over the service PID       read the live keyword,        net-free reset proof,
  + tshark dissect           neutralize cloud gates        cipher/template tables
        │                          │                              │
        └─────────────► CORRELATE by timestamp ◄──────────────────┘
                         + deterministic payload
```

- **Lane 1 — usbmon (the wire, ground truth).** `usbmon` exposes `/dev/usbmonN`;
  `dumpcap` records it; `tshark` dissects URBs. **The wire is the arbiter** — when
  the static model and the wire disagree, the wire wins. Filter on your VID:PID
  (G6020: `04a9:1865` normal / `04a9:12fe` service); for control transfers filter
  `usb.transfer_type` and dissect `bmRequestType/bRequest/wValue/wIndex/data`. The
  turnkey extractor is `scripts/parse-wicreset-capture.py`
  ([`../TOOLS.md`](../TOOLS.md) §1, §6).
- **Lane 2 — Frida (host IOCTL / DRM).** Runtime-hook the proprietary Windows tool
  to see the **plaintext** command frame *before* it hits the wire, read the live
  keyword, clamp the page-cap buffer (c), and — for a genuine-frame capture —
  neutralize the cloud *licensing* gates so a net-free reset runs (the bypass is a
  few `JZ→JMP` patches; it does **not** touch the repair data path)
  ([`../TOOLS.md`](../TOOLS.md) §3).
- **Lane 3 — Ghidra (offline decompile).** Static RE recovers what the wire can
  never show: the IOCTL→URB field map (c), the *net-free* proof of the reset
  subtree, and the cipher/template tables (h). Use `analyzeHeadless` + pyghidra; the
  button→wire recipe is RT_DIALOG control-ID → MFC message map → wire
  ([`../TOOLS.md`](../TOOLS.md) §2).

**The capture rig.** Because Wine cannot surface USB to the closed tools, the rig is
a throwaway **Win11 guest under session-mode libvirt** with **real USB passthrough**
of the printer, while host-side `usbmon` records the bus — full IaC + reproduce-
from-scratch steps in [`../TOOLS.md`](../TOOLS.md) §0.

**Adapting it to other hardware.** The trifecta is hardware-agnostic: any device
with (1) a wire you can tap (`usbmon`, or a logic analyzer for SPI/I²C EEPROM),
(2) a host-side tool you can instrument (Frida on the IOCTL/library boundary), and
(3) a binary you can decompile (Ghidra) can be reversed this way. Substitute the
service-mode entry, the PID, the command bytes, and the cipher for your target;
keep the three-lane cross-correlation discipline.

---

## (h) Cipher / obfuscation note — expect it, here's how we peeled it

Vendor template databases and on-wire readbacks **are obfuscated**. Expect at least
two distinct layers, and do not assume one cipher covers everything:

1. **Template-DB obfuscation (at rest).** WICReset's model DB ships inside an
   encrypted `APP.BIN` container: strip footer → **3DES-EDE3-CBC** (a zero key / IV
   from empty-string construction) → strip pad → zlib inflate → `devices.xml`
   (G6020-observed). The per-model command
   tables come straight from that decrypted DB.
2. **On-wire obfuscation (in motion).** The maintenance frames are run through a
   **functor-3 envelope** XOR-enciphered by a **functor-2** transform seeded by the
   **bound session keyword**. The decisive bug that defeated earlier attempts was a
   **buffer-role swap**: the correct model transforms the *envelope* seeded by the
   *bound keyword* (emitting all 20 bytes), not the keyword seeded by the envelope.
   With that fix the genuine 23-byte `set_command`
   (`85 00 00 || 20-byte ciphertext`) reproduces **byte-exact (23/23)** — and the
   transform is provably invertible, so the firmware decrypts our ciphertext back to
   a legitimate command. The keystream derives from a CANON-SR5 schedule, confirmed
   on the recv side as well.

**Two practical truths that save you effort (G6020-observed):**

- The **write/clear path is NOT keyword-keyed.** The device ACK'd the *plain*
  operand frames `85 00 00 00 00 10 07 7c` then `85 00 00 00 00 0d 00 00` (`OK(8)`)
  with the operand sent verbatim. The keyword gates the **read** obfuscation, not
  the write — so a working clear may need **no cipher at all**.
- The **read codecs differ in difficulty.** `0x84` is a linear keyword-XOR stream,
  cracked from ~40 random-keyword sessions (40/40 byte-exact, validated
  out-of-sample); `0x8c` is **nonlinear** in all three keyword bytes and remains
  open — finish it with a read-path Ghidra decompile **or** controlled-keyword
  captures (keywords differing in a single byte).

**How to peel obfuscation on a new model.** Decrypt the at-rest template DB first
(Lane 3) to read the command tables in clear; then attack the on-wire codec with a
**dataset** of constant-state sessions (the keyword varies, the plaintext doesn't),
testing linearity (GF(2)) before assuming a nonlinear schedule; and always keep a
**ground-truth capture** (Lane 1/2) to validate byte-exact and avoid overfitting a
single sample — be deliberate about how many samples a keystream/block crack needs.

---

## See also

- **Validated G6020 procedure:** [`../runbook/g6020-native-reset.md`](../runbook/g6020-native-reset.md)
- **Workbench / instrumentation inventory:** [`../TOOLS.md`](../TOOLS.md)
  · [`../diagrams/methodology-trifecta.mmd`](../diagrams/methodology-trifecta.mmd)
- **Methodology / posture record:** [`../adr/0007-canon-tool-reverse-engineering.md`](../adr/0007-canon-tool-reverse-engineering.md)
- **Ethics / safety:** [RIGHT-TO-REPAIR.md](https://github.com/Jesssullivan/canon-megatank-reset/blob/main/ETHICS/RIGHT-TO-REPAIR.md)
  · [SECURITY.md](https://github.com/Jesssullivan/canon-megatank-reset/blob/main/SECURITY.md)
