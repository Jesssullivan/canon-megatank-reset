# docs/ — canon-megatank-reset documentation index

The front door for the next debugger landing cold. This is the open, native-Linux,
key-free, cloud-free reset of the Canon MegaTank **5B00** waste-ink / ink-absorber
counter — recovered from vendor tools used as RE oracles, formally modelled, and
**hardware-validated** on a real G6020.

## Fixing another Canon? Start with the field guide

If you landed here trying to unbrick a **different** Canon (any PIXMA / MegaTank /
G-series stuck on **5B00 / "waste ink absorber full"** or another service code),
read the model-agnostic
[**Canon service-mode RE field guide**](research/canon-service-mode-field-guide.md)
first. It generalizes this repo's validated G6020 work — service-mode entry, the
vendor control-transfer transport, the session/keyword handshake, the EEPROM
counter and commit-on-power-button behavior, the cipher you should expect, and the
usbmon↔Frida↔Ghidra method — into a reusable guide for *your* model, cross-linking
the concrete G6020 evidence below.

## Start here

1. **What is true today** — the native libusb 5B00 reset is recovered and
   **hardware-validated** (transport + session protocol + write cipher cracked, 23/23
   byte-exact; cleared 5B00 on a real G6020). Read
   [`runbook/g6020-native-reset.md`](runbook/g6020-native-reset.md) — the validated,
   end-to-end reference procedure with the safety gate ladder.
2. **Why / how it was done** — [`adr/0007-canon-tool-reverse-engineering.md`](adr/0007-canon-tool-reverse-engineering.md)
   for the methodology and posture, and the academic write-up in
   [`paper/`](paper/canon-megatank-reset.tex).
3. **The contract** — `../AGENTS.md` (operating contract) and `../CONTRIBUTING.md`
   (entrypoints, secret guard, traceability, safety). Everything runs via `just`.
4. **Productionization** — [`PRODUCTIONIZATION.md`](PRODUCTIONIZATION.md) for the path
   from validated tool to fleet-deployable.

## Map of `docs/`

| Area | What's in it | Start file |
|---|---|---|
| [`research/`](research/) | The **RE evidence** — every trace↔decompile↔correlate finding: WICReset static RE, the usbprint vendor transport, the wire codec, the write cipher, the reset derivation, firmware/lineage cross-checks. Generalized entry point: the **field guide** (see list below). | **`canon-service-mode-field-guide.md`** (start here), `g6020-wire-codec-crack.md`, `g6020-reset-completion.md` |
| [`runbook/`](runbook/) | The **validated + experimental procedures** — capture harnesses, live hardware experiments, and the reference reset. | **`g6020-native-reset.md`** (validated), `live-hardware-validation.md` |
| [`spec/`](spec/) | The **formal protocol model** — the megatank maintenance protocol, property-tested in code (`just model`). | [`spec/README.md`](spec/README.md), `spec/megatank-maintenance-protocol.md` |
| [`adr/`](adr/) | **Architecture decision records** — the RE approach, scope, and safety/ethics decisions. | `adr/0007-canon-tool-reverse-engineering.md` |
| [`paper/`](paper/) | The **academic paper** (IEEEtran LaTeX, vendored classes) documenting the reproduction. CC-BY-4.0. | [`paper/README.md`](paper/README.md), `paper/canon-megatank-reset.tex` |
| [`diagrams/`](diagrams/) | **Diagram sources** (`.mmd` / `.dot`) — state machine, exploit dataflow, methodology trifecta; SVG is built via `just diagrams`. | [`diagrams/README.md`](diagrams/README.md) |

## Map of `docs/research/` — the RE evidence (so it's findable, not buried)

The hex, payloads, serial/exploration flows, handshake structures, and EEPROM/memory
maps are a first-class artifact for the next reparability effort. Start with the
**field guide** (model-agnostic), then dig into the concrete G6020 evidence it cites.

| Doc | One-line |
|---|---|
| [`canon-service-mode-field-guide.md`](research/canon-service-mode-field-guide.md) | **START HERE** — model-agnostic guide to Canon service-mode RE (entry, transport, handshake, EEPROM counter, cipher, method), generalized from the G6020 work. |
| [`usbprint-vendor-urb-mapping.md`](research/usbprint-vendor-urb-mapping.md) | **Transport (authoritative):** `usbprint.sys` decompile → VENDOR control transfers `0x41` OUT / `0xC1` IN; the don't-strip-the-prefix gotcha. |
| [`canon-servicemode-transport-research.md`](research/canon-servicemode-transport-research.md) | Layered control-vs-bulk analysis + service-mode entry / re-enumeration (`1865`→`12fe`); superseded on the SET pipe by the usbprint mapping. |
| [`servicemode-ioctl-0x16000c.md`](research/servicemode-ioctl-0x16000c.md) | The three maintenance IOCTLs decoded (`0x220038`/`0x22003c`/`0x16000c`); native result: control IN works, bare bulk-IN dead. |
| [`servicetool-v5103-servicemode-reset-re.md`](research/servicetool-v5103-servicemode-reset-re.md) | Canon Service Tool v5103 static RE: usbscan(normal) vs usbprint(service); service-PID discovery; reset payload. |
| [`servicetool-v5103-read-re.md`](research/servicetool-v5103-read-re.md) | Read = SEND-primed (`0x86` prime → 20-byte RECV); cold bare RECV times out (errno 110). |
| [`servicetool-v5103-reset-handshake.md`](research/servicetool-v5103-reset-handshake.md) | Ordered session handshake before the reset payload; runtime-sourced bytes flagged. |
| [`g6020-wire-codec-crack.md`](research/g6020-wire-codec-crack.md) | Readback wire codec: `0x84` cracked (keyword-XOR stream, 40/40); `0x8c` nonlinear/open; the plain unkeyed clear ACK'd `OK(8)`. |
| [`g6020-genuine-setcommand-decode.md`](research/g6020-genuine-setcommand-decode.md) | Three-lane analysis of the 23-byte `set_command`; write path not keyword-gated; how many samples a crack needs. |
| [`g6020-reset-completion.md`](research/g6020-reset-completion.md) | Decisive verdict: COMMIT-gated not cloud-gated; the empty-`0x86` completion nuance; 23/23 byte-exact cipher. |
| [`g6020-reset-derivation.md`](research/g6020-reset-derivation.md) | CANON-SR5 cipher derivation + the G6020 `waste:common` enciphered clear (Lane A). |
| [`g6020-reset-crossval.md`](research/g6020-reset-crossval.md) | Cross-validation of the absorber reset + live-run risk assessment (Lane C). |
| [`g6020-recv-transport-re.md`](research/g6020-recv-transport-re.md) | RECV transport + functor-2/3 cipher re-confirmation (Lane B). |
| [`wicreset-drm-bypass.md`](research/wicreset-drm-bypass.md) | Cloud-DRM bypass + genuine-frame capture plan; proof the reset takes zero cloud bytes. |
| [`wicreset-g6020-reset-template.md`](research/wicreset-g6020-reset-template.md) | G6020 reset frame template + on-wire encryption recovered from `printerpotty.exe`. |
| [`wicreset-appbin-container.md`](research/wicreset-appbin-container.md) | The `APP.BIN` container model (PE resource, mount pipeline). |
| [`wicreset-appbin-cipher.md`](research/wicreset-appbin-cipher.md) | `APP.BIN` decrypt: 3DES-EDE3-CBC (zero key/IV) → inflate → `devices.xml` template DB. |
| [`canon-tool-ghidra-notes.md`](research/canon-tool-ghidra-notes.md) | Ghidra static-analysis notes; the single transport choke point + button→wire recipe. |
| [`sota-dynamic-instrumentation.md`](research/sota-dynamic-instrumentation.md) | SOTA dynamic-instrumentation tradecraft (Frida) for capturing the real reset. |
| [`sota-eeprom-waste-counter-model.md`](research/sota-eeprom-waste-counter-model.md) | SOTA model of how Canon/G-series store the waste-ink counter in NVRAM/EEPROM. |
| [`sota-academic-eeprom-re.md`](research/sota-academic-eeprom-re.md) | SOTA academic/whitepaper survey on printer/inkjet NVRAM counter RE. |
| [`sota-pixma-octo-lineage.md`](research/sota-pixma-octo-lineage.md) | SOTA PIXMA lineage + OctoInkjet/Printer Potty + open-source reimplementations. |

The complete RE/tooling inventory (the usbmon↔Frida↔Ghidra rig) is in
[`TOOLS.md`](TOOLS.md). The full file list is in [`research/`](research/).

## Evidence → code traceability

Every protocol claim is traceable from RE finding to running, tested code. The chain:

```
RE finding ─► docs/research/<file>.md ─► src/canon_megatank/<module> ─► tests/<test>
```

Worked example (the write that clears 5B00):

```
write cipher cracked
  → docs/research/g6020-wire-codec-crack.md  +  docs/research/g6020-reset-completion.md
  → src/canon_megatank/protocol/  +  src/canon_megatank/ops.py / usb.py
  → tests/  (incl. the protocol-model property tests — `just model`)
  → docs/runbook/g6020-native-reset.md  (the validated end-to-end procedure)
```

The SSOT for what the tool will actually do on hardware is
`../printers/canon-g6020/maintenance.yaml` (fingerprint, supported ops, write budget,
recovered protocol, validation status). When the SSOT status is `derived-unvalidated`
the reset path hard-stops on `--execute` unless `--accept-derived` is passed for a
single run on the locked debug unit.

## Before you run anything

This tool **writes to a real printer EEPROM**. It is dry-run by default; `--execute` is
gated (test-unit UUID isolation, mandatory EEPROM dump, write budget, lockfile, status
gate). Run it only on the locked debug unit, only with **waste pads installed**, and
commit a clear with a clean power-button shutdown. See `runbook/g6020-native-reset.md`
and `../ETHICS/RIGHT-TO-REPAIR.md`.
