---
title: "Clearing Canon's 5B00 Lock: A Native, Key-Free MegaTank Waste-Ink Reset over USB"
date: "2026-06-02"
description: "A complete technical reference for resetting the Canon G-series MegaTank '5B00 ink absorber full' lock from Linux — recovering the usbprint vendor-control maintenance protocol, the per-session keyword-bound write cipher, and the finding that the commercial tool's cloud is licensing-only and the reset bytes are entirely local."
tags: ["canon", "megatank", "g6020", "5b00", "usb-protocol", "reverse-engineering", "right-to-repair", "ghidra", "frida", "usbmon"]
published: true
slug: "clearing-canon-5b00-lock-native-key-free-megatank-reset"
category: "hardware"
feature_image: "/images/posts/canon-5b00-lifecycle.png"
source_repo: "Jesssullivan/canon-megatank-reset"
source_path: "docs/blog/canon-5b00-native-reset.md"
publish_to: "blog"
---

## Introduction

If you own a Canon MegaTank — a G6020, G6050, G7020, or any of the G5000/G6000/G7000-generation
refillable-tank printers — there is a fair chance you will one day power it on and find it dead
with a single code on the panel: **5B00**, "the ink absorber is full." Canon's official position
on 5B00 is one sentence: *service is required.* There is no menu, no key combination, no user
reset. For a printer whose entire selling point is cheap, refillable ink, the sanctioned repair
path is to throw it away and buy another one.

The absorber in our unit was not even saturated. 5B00 is not a hardware failure; it is a counter
in EEPROM crossing a threshold, and firmware refusing to print until that counter is reset — a
service-mode operation Canon's field tools perform and the consumer firmware hides. On this
printer generation, the classic in-firmware reset combo was *removed*: the printer enters service
mode but accept-and-ignores the clear. The only tools that actually clear a G6020 are commercial,
per-unit, cloud-licensed resetters.

So we did it the other way: figure out what the maintenance lock actually *is*, recover the
protocol, and clear it ourselves — on Linux, over `libusb`, with **no vendor cloud, no Windows,
and no per-unit key**. This post is the complete technical reference for that work. It covers the
service-mode USB device, the `usbprint` vendor-control transport, the four-step reset session, the
per-session keyword-bound write cipher, the (surprisingly thin) role of the commercial tool's
cloud, and the one nuance — *how the write commits* — that separated "the device ACKs everything
and stays bricked" from "it reboots clean." Everything here is implemented in the open-source
[canon-megatank-reset](https://github.com/Jesssullivan/canon-megatank-reset) (zlib code,
CC-BY-4.0 docs); the repo carries the full protocol spec, the reverse-engineering trail, and the
diagrams behind every claim.

> **Warning.** This manipulates an EEPROM write path on a printer in service mode. The waste-ink
> counter exists for a reason — a genuinely saturated absorber will spill ink inside the chassis.
> **Install a fresh waste-ink pad kit before you reset**, and only apply any of this to hardware
> you own. This is right-to-repair and interoperability research, not a license to touch a printer
> that is not yours.

### When You Need This

- Your G-series MegaTank is stuck on **5B00** ("ink absorber full" / "support code 5B00")
- You have installed (or are installing) a fresh waste-ink absorber kit
- You want an offline, key-free, fleet-reproducible reset rather than a per-unit cloud license
- You are comfortable entering service mode and issuing USB control transfers as root on Linux

### Prerequisites

- **Linux** with `libusb`/`pyusb` (tested on Rocky Linux 10, kernel 6.12.x)
- **Root** or membership in a group your udev rule grants `04a9` device access
- A G-series MegaTank in **service mode** (see below) — it enumerates as a *different* USB device
- Basic familiarity with USB control transfers and hex

---

## The Lock: Two Devices, One Printer

A MegaTank presents **two completely different USB identities** depending on mode:

| Mode | USB ID | Interfaces | The maintenance lane |
|---|---|---|---|
| Normal | `04a9:1865` | 6 (print, scan, `usbscan` iface 4, …) | iface 4, bulk `0x03`/`0x86` |
| **Service** | `04a9:12fe` | 1 printer-class iface (EP `0x01` OUT / `0x82` IN) | **vendor control transfers** |

Service mode is entered with the Canon button dance: power off, hold **ON**, tap **Stop/Resume
five times**, release. The LCD goes to a flat block-color field and the printer re-enumerates as
`04a9:12fe`. That `12fe` device is where the waste-counter reset lives — and it speaks a protocol
that does *not* look like the normal-mode `usbscan` lane at all.

The first trap is here. On `12fe`, the printer-class **bulk-IN endpoint `0x82` is silent**: every
bulk read returns zero bytes. You can send bulk-OUT frames all day and the device will take them;
it will never answer on bulk-IN. That dead bulk channel sent more than one prior effort down a
rabbit hole.

**Lesson: when an endpoint is silent, suspect the transfer *type*, not the endpoint.**

---

## The Transport: usbprint Vendor Control Transfers

The maintenance protocol is not bulk at all. On Windows, Canon's tooling talks to the printer
through `usbprint.sys`, and its IOCTL frames map onto **USB control transfers**. Decompiling
`usbprint.sys` and correlating it against a `usbmon` capture of the genuine tool pinned the exact
mapping:

| Direction | `bmRequestType` | `bRequest` | `wValue` | data stage |
|---|---|---|---|---|
| **VENDOR_SET** (write) | `0x41` (OUT, vendor, interface) | frame byte 0 (the command) | `(frame[1] << 8) | frame[2]` | the **entire** frame, verbatim |
| **VENDOR_GET** (read) | `0xC1` (IN, vendor, interface) | the command byte | — | response bytes |

So a maintenance "frame" like `81 00 00 03` becomes a control-OUT with `bRequest=0x81`,
`wValue=0x0000`, carrying `81 00 00 03` as its data stage. The reply to a read command comes back
on the **control-IN** pipe (`0xC1`), never on bulk-IN. Once we moved reads from bulk `0x82` to
control-IN `0xC1`, the device started answering.

```mermaid
flowchart LR
    H["Linux host<br/>pyusb / libusb"] -->|"ctrl-OUT 0x41<br/>bReq=cmd, data=frame"| D["G6020 (12fe)<br/>service mode"]
    D -->|"ctrl-IN 0xC1<br/>bReq=cmd → bytes"| H
    style H fill:#2d3748,color:#fff
    style D fill:#4ecdc422,stroke:#4ecdc4
```

---

## The Session: Four Steps and a Power Button

The reset is a short, ordered, **keyed** session. Three frames go out, one value comes back, and
the whole thing commits on a clean power-off:

```mermaid
stateDiagram-v2
    [*] --> SetSession: VENDOR_SET 0x81  "81 00 00 03" (PLAIN)
    SetSession --> GetKeyword: VENDOR_GET 0x82 → live 3-byte keyword
    GetKeyword --> SetCmdSelector: VENDOR_SET 0x85  23B (SELECTOR, op 10 07 7c)
    SetCmdSelector --> SetCmdClear: VENDOR_SET 0x85  23B (CLEAR, op 0d 00 00)
    SetCmdClear --> Commit: release USB handle → POWER-BUTTON off
    Commit --> [*]: printhead parks → EEPROM flush → 5B00 cleared
```

1. **`set_session`** — send `81 00 00 03` **in the clear**. The device length-validates the `0x81`
   command; an *enciphered* `set_session` (a longer frame) STALLs. This frame is the only one that
   stays plaintext.
2. **`get_keyword`** — `VENDOR_GET(0x82)` returns a **live, per-session 3-byte keyword**. Pad it to
   four bytes and "bind" it; this value seeds the cipher for the rest of the session, which is why
   the reset is device-bound and cannot be replayed as a static byte string.
3. **`set_command`** — two 23-byte frames, `85 00 00 || payload(20)`. The first selects the target
   (operand `10 07 7c`); the second is the actual `waste:common` clear (operand `0d 00 00`). The
   20-byte payload is enciphered (next section).
4. **`get_command`** (`0x86`) returns **empty** — and that is correct, not a failure. There is no
   "finalize" command in this protocol. **Do not gate on a `0x86` reply.**

Then the part that cost a full day:

5. **Commit.** Release the host USB handle (exit the process), then perform a **clean
   power-button shutdown**. You will hear the printhead park — that mechanical settle *is* the
   EEPROM flush. Power back on and 5B00 is gone; the printer re-enumerates as `04a9:1865`.

---

## The Write Cipher

The reset payload is not sent in the clear, and getting the encoding right was the last missing
piece. The genuine `set_command` is a two-layer construction:

- An inner **functor-3 envelope**: a deterministic 20-byte structure, `00 12 01 <op>` followed by
  16 fixed bytes from an MSVC `rand()` stream seeded at `0x12345678`. This is template data — the
  G6000-series "CANON-SR5" maintenance family uses functor/method 3.
- An outer **functor-2 transform** with the buffer roles **swapped** from the obvious reading: the
  *subject* is the 20-byte functor-3 envelope, and the *seed* is the 4-byte **bound keyword** from
  step 2. (An earlier pass had subject and seed reversed, which only ever emits 4 bytes and silently
  fails.)

The wire frame is `85 00 00 || functor2(envelope3(85 00 00 || op), bound_keyword)` — 23 bytes
total. Validated **23/23** against ground truth captured from the genuine tool: e.g. for the
SELECTOR operand `10 07 7c` with a known keyword, the encoder reproduces
`85 00 00 db bb 00 67 59 a1 b0 1f 84 2f d5 83 04 4a 3a c3 51 d2 b1 ef` byte-for-byte. The full
keystream tables (`command.index`, `command.codes`, the operator-VM `command.shift` programs) are
in the repo's spec and the recovered `devices.xml`; this post gives the shape, the repo gives every
byte.

### Where the template comes from

The per-model template is not fetched from anywhere at reset time — it ships *inside* the commercial
tool as a PE resource named `APP.BIN` (~558 KB). "Encrypted," in the loosest sense:

```
APP.BIN  --3DES-EDE3-CBC (all-zero 24-byte key, all-zero IV)-->  ZIP
   └─ devices.srs  --same zero-key 3DES-->  devices.xml  (2.5 MB cleartext)
        └─ "Canon G6000 Series"  class="canon.printer.std.standard"  specs="CANON-SR5"
```

A zero key and a zero IV is not encryption; it is obfuscation. Once decrypted, `devices.xml` hands
you the entire per-model maintenance template in cleartext — opcodes, the keyword table, and the
cipher tables. **The reset bytes are bundled and trivially recoverable, not cloud-sourced.**

---

## The Cloud Is Licensing, Not Logic

The commercial resetters (WICReset / Printer Potty) validate a paid, per-unit key against a server
before they will run. The obvious worry for an offline reimplementation is that the *device write*
itself carries a server-signed nonce — in which case no offline tool could ever work. It does not.

Pulling the genuine tool apart two ways — statically in Ghidra, and dynamically by neutralizing its
online checks under Frida and watching what still functioned — gave a clear verdict. The reset
orchestrator reaches the device-write path through cloud round-trips that are pure **gates**: a
key-entitlement boolean before, and an accounting report after. A call-graph trace of the
counter-clear routine and everything it calls is **network-free** — sockets only appear one level
up, in the licensing orchestrator. The server gates *whether you may run the tool*; it sources
**none** of the bytes that go to the printer.

```mermaid
flowchart TD
    start["ClearCounters orchestrator"] --> g1{"key entitlement?<br/>(cloud)"}
    g1 -->|"yes"| emit["clearCounters subtree<br/>(NET-FREE: builds + sends<br/>the device frames locally)"]
    emit --> g2["accounting report<br/>(cloud, after the write)"]
    g1 -->|"no"| err["abort"]
    style emit fill:#51cf6622,stroke:#51cf66
    style g1 fill:#ff6b6b22,stroke:#ff6b6b
    style g2 fill:#ffa50022,stroke:#ffa500
```

This is the whole right-to-repair point: because the device bytes are built locally from a bundled,
trivially-decryptable template plus a per-session keyword you read off your own printer, a native
tool needs **no key and never spends one**. Our reset is not a way to use someone else's resetter
for free — it is an independent reimplementation built from the protocol itself.

---

## The Recovery Procedure

```bash
# 0. Install a fresh waste-ink pad kit FIRST. The counter is not lying about its job.

# 1. Enter service mode: power off → hold ON → tap Stop/Resume x5 → release.
#    The printer re-enumerates as 04a9:12fe (flat block-color LCD).

# 2. Dry run (default). Reads the live keyword, builds the enciphered frames,
#    prints exactly what it WOULD send — and writes nothing.
canon-megatank reset-native            # dry-run is the default

# 3. Execute, behind the gates (test-unit UUID, EEPROM pre-dump, write budget, lockfile):
canon-megatank reset-native --execute

# 4. Release the handle (the command exits) and POWER-BUTTON the printer off.
#    Listen for the printhead to park — that is the EEPROM flush.

# 5. Power on. 5B00 is gone; the printer comes back as 04a9:1865 and prints.
```

The tool refuses to write unless the printer's IPP UUID matches the configured test unit, an EEPROM
pre-dump succeeds, the write budget is intact, and a lockfile is held. None of those gates protect
Canon; they protect *you* from running a destructive EEPROM write against the wrong unit.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Bulk reads on `0x82` return 0 bytes | Maintenance replies come over control-IN, not bulk | Read via `VENDOR_GET` (`0xC1`), not bulk `0x82` |
| `set_session` STALLs | You enciphered it | `set_session` (`81 00 00 03`) is **plaintext**; only `set_command` is enciphered |
| Frames ACK but 5B00 persists after reboot | You unplugged instead of power-buttoning | Release the USB handle, then clean power-button shutdown |
| Power button "hangs" (slow green blink) | Host still holds the USB session | Exit the tool first, *then* press power |
| Encoder emits 4 bytes, not 20 | functor-2 subject/seed reversed | Subject = 20-byte functor-3 envelope; seed = bound keyword |
| 17/20 frames validate, not 23/23 | Cipher tables drifted from the decrypted source | Re-sync `command.*` tables from `devices.xml` |
| `get_command` (`0x86`) returns empty | By design — no finalize command exists | Ignore it; the commit is the power-off |

---

## How We Got Here: The Dead Ends

The path was not a straight line, and the failures are as instructive as the fix.

### Dead End 1: The Bare Reset Frame
Early on, the obvious-looking reset `85 00 00 00 03 01 03 07` was sent over both the normal-mode
lane and service mode. Every byte ACKed. Power-cycle: 5B00, unchanged. The frame was the wrong
opcode family, with no session and no cipher — and the firmware accept-and-ignores well-formed
writes on a gated path.

**Lesson: a device that ACKs is not a device that obeyed. Verify the *effect*, not the transport status.**

### Dead End 2: The Silent Bulk-IN
Days went into characterizing why bulk-IN `0x82` only ever returned zero-length packets. It was not
a bug to fix; it was the wrong pipe. The maintenance reply is a control-IN transfer.

**Lesson: check the transfer type before you debug the endpoint.**

### Dead End 3: Plaintext set_command
Sending the logically-correct reset payload in the clear got it rejected. The firmware honors the
*enciphered* form and ignores the plaintext one. The gate was never a different opcode — it was the
session cipher.

**Lesson: "the device ignores my correct command" sometimes means "my command is correct but unsigned."**

### Dead End 4: Unplug as a Commit
Pulling power "to be safe" never committed the reset — it skipped the EEPROM flush entirely. The
commit is a *graceful* shutdown: the printhead-park routine is what writes the counter back.

**Lesson: the commit can be a side effect of a clean shutdown. Cutting power is not the same as turning off.**

---

## The Methodology: A Trifecta

None of this came from one tool. It came from three, in a loop:

```mermaid
flowchart LR
    U["usbmon / Wireshark<br/>(what crosses the wire)"] <--> F["Frida<br/>(what the genuine tool builds<br/>before the driver)"]
    F <--> G["Ghidra<br/>(what the code means)"]
    G <--> U
    style U fill:#4ecdc422,stroke:#4ecdc4
    style F fill:#ffa50022,stroke:#ffa500
    style G fill:#51cf6622,stroke:#51cf66
```

`usbmon` shows the bytes; Frida shows the application frame *before* it is enciphered and handed to
the driver; Ghidra explains why. Trace, decompile, correlate, repeat — until all three agree on the
same story. They eventually did, and the story was reproducible enough to rebuild from scratch.

---

## Security & Right-to-Repair Considerations

- **The "lock" is a policy, shipped as firmware.** 5B00 is a counter and a threshold, not a broken
  part. On this printer generation the in-firmware reset was deliberately removed and pushed to
  paid, cloud-licensed tooling.
- **The device bytes are local.** The cloud in the commercial path is a licensing gate, not a
  signing oracle; the per-model template is bundled and zero-key "encrypted." Offline reset is
  therefore computable without a key.
- **This is interoperability on owned hardware.** The native tool resets a waste-ink counter on a
  printer you own, after you have installed fresh pads. It does not circumvent a content-protection
  scheme and it does not pirate the commercial tool — it reimplements the protocol.
- **Install the pads first.** The one genuinely destructive failure mode here is resetting a *truly*
  full absorber and spilling ink. Respect the counter's actual job.

---

## References & Credits

- **[leecher1337/pixma](https://github.com/leecher1337/pixma)** — the Canon firmware-unpack lineage
  (`pixma_decrypt`, `pixma_unpack`), built on the Context Information Security 2016 talk *"Hacking
  Canon PIXMA Printers — Doomed Encryption."* The firmware-decrypt cross-check builds on this work.
- **Context IS, "Hacking Canon PIXMA Printers — Doomed Encryption" (2016)** — the original public
  analysis of Canon's firmware obfuscation; the zero-key pattern rhymes with what `APP.BIN` uses.
- **OctoInkjet / Printer Potty** — the waste-ink absorber kits that make a reset safe to perform,
  and public documentation of the MegaTank waste-counter problem.
- **Frida, Ghidra, Wireshark/`usbmon`, pyusb/`libusb`** — the reverse-engineering and reset toolchain.
- **[canon-megatank-reset](https://github.com/Jesssullivan/canon-megatank-reset)** — this work: the
  native tool, the protocol spec, the full RE trail, the diagrams, and the paper. Code is zlib;
  docs/paper are CC-BY-4.0.

---

## Appendix: Quick Reference Card

### Service-mode entry
```
power off → hold ON → tap Stop/Resume x5 → release   (LCD = flat block color, USB = 04a9:12fe)
```

### Control-transfer mapping (usbprint)
```
VENDOR_SET (write):  bmRequestType=0x41  bRequest=frame[0]  wValue=(frame[1]<<8)|frame[2]  data=whole frame
VENDOR_GET (read):   bmRequestType=0xC1  bRequest=cmd                                       → response bytes
```

### The session
```
1. set_session   VENDOR_SET 0x81   data = 81 00 00 03            (PLAINTEXT)
2. get_keyword   VENDOR_GET 0x82   → live 3-byte keyword → pad to 4, bind
3. set_command   VENDOR_SET 0x85   data = 85 00 00 || payload(20)   SELECTOR  (op 10 07 7c)
4. set_command   VENDOR_SET 0x85   data = 85 00 00 || payload(20)   CLEAR     (op 0d 00 00)
5. get_command   VENDOR_GET 0x86   → empty (by design; do not gate on it)
6. commit        release USB handle → clean POWER-BUTTON shutdown → power on
```

### Write cipher
```
inner: envelope3 = 00 12 01 <op> + 16 fixed LCG bytes (MSVC rand, seed 0x12345678)   [functor/method 3]
outer: payload   = functor2(subject = envelope3, seed = bound 4-byte keyword)         [buffer roles swapped]
wire:  85 00 00 || payload(20)   = 23 bytes   (validated 23/23 vs ground truth)
```

### Template recovery
```
APP.BIN (PE resource) --3DES-EDE3-CBC, zero key, zero IV--> ZIP --> devices.srs --(same)--> devices.xml
"Canon G6000 Series"  class=canon.printer.std.standard  specs=CANON-SR5
```
