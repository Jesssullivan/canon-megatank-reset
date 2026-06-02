# docs/ — canon-megatank-reset documentation index

The front door for the next debugger landing cold. This is the open, native-Linux,
key-free, cloud-free reset of the Canon MegaTank **5B00** waste-ink / ink-absorber
counter — recovered from vendor tools used as RE oracles, formally modelled, and
**hardware-validated** on a real G6020.

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
| [`research/`](research/) | The **RE evidence** — every trace↔decompile↔correlate finding: WICReset static RE, the usbprint vendor transport, the wire codec, the write cipher, the reset derivation, firmware/lineage cross-checks (34 notes). | `g6020-wire-codec-crack.md`, `g6020-reset-completion.md`, `wicreset-appbin-cipher.md` |
| [`runbook/`](runbook/) | The **validated + experimental procedures** — capture harnesses, live hardware experiments, and the reference reset. | **`g6020-native-reset.md`** (validated), `live-hardware-validation.md` |
| [`spec/`](spec/) | The **formal protocol model** — the megatank maintenance protocol, property-tested in code (`just model`). | [`spec/README.md`](spec/README.md), `spec/megatank-maintenance-protocol.md` |
| [`adr/`](adr/) | **Architecture decision records** — the RE approach, scope, and safety/ethics decisions. | `adr/0007-canon-tool-reverse-engineering.md` |
| [`paper/`](paper/) | The **academic paper** (IEEEtran LaTeX, vendored classes) documenting the reproduction. CC-BY-4.0. | [`paper/README.md`](paper/README.md), `paper/canon-megatank-reset.tex` |
| [`diagrams/`](diagrams/) | **Diagram sources** (`.mmd` / `.dot`) — state machine, exploit dataflow, methodology trifecta; SVG is built via `just diagrams`. | [`diagrams/README.md`](diagrams/README.md) |
| [`legacy/`](legacy/) | Pre-extraction notes carried over from `printstack` (history context). | `legacy/service-README.md` |

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
