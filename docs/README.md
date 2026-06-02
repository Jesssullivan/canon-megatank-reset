# docs/ — canon-megatank-reset documentation index

The open, native-Linux, key-free, cloud-free 5B00 waste-ink reset for the Canon
G-series MegaTank — recovered from vendor tools used as RE oracles, formally modelled,
and **hardware-validated** on a real G6020.

## Start here

- **Fixing a different Canon?** The model-agnostic
  [Canon service-mode RE field guide](research/canon-service-mode-field-guide.md):
  service-mode entry, the vendor control-transfer transport, the session/keyword
  handshake, the EEPROM counter + commit-on-power-button, the cipher to expect, and
  the usbmon ↔ Frida ↔ Ghidra method.
- **Resetting a G6020?** The validated end-to-end procedure + safety-gate ladder:
  [runbook/g6020-native-reset.md](runbook/g6020-native-reset.md).
- **Non-technical owner?** [user-guide.md](user-guide.md).

## Map of `docs/`

| Area | What | Start file |
|---|---|---|
| [research/](research/) | The consolidated, model-agnostic RE field guide. (The full RE journey lives in git history.) | `canon-service-mode-field-guide.md` |
| [runbook/](runbook/) | The validated reset procedure. | `g6020-native-reset.md` |
| [spec/](spec/) | Formal protocol model, property-tested (`just model`). | `spec/megatank-maintenance-protocol.md` |
| [adr/](adr/) | The RE approach, scope, and safety/ethics decision. | `adr/0007-canon-tool-reverse-engineering.md` |
| [paper/](paper/) | The academic paper (IEEEtran, CC-BY-4.0). | `paper/canon-megatank-reset.tex` |
| [diagrams/](diagrams/) | Lifecycle, exploit dataflow, methodology trifecta. | `diagrams/README.md` |
| [TOOLS.md](TOOLS.md) | The usbmon ↔ Frida ↔ Ghidra tooling + methodology. | — |
| [blog/](blog/) | Narrative writeup. | `blog/canon-5b00-native-reset.md` |

## Evidence → code → tests

Each protocol claim is traceable: the field guide documents the finding,
`src/canon_megatank/` implements it, `tests/` (incl. the protocol property tests —
`just model`) assert it, and
[runbook/g6020-native-reset.md](runbook/g6020-native-reset.md) is the validated
end-to-end procedure. The single source of truth for what the tool does on hardware is
[`printers/canon-g6020/maintenance.yaml`](https://github.com/Jesssullivan/canon-megatank-reset/blob/main/printers/canon-g6020/maintenance.yaml)
(fingerprint, supported ops, write budget, recovered protocol, validation status).

## Before you run anything

This tool **writes to a real printer EEPROM**. It is dry-run by default; `--execute` is
gated (test-unit UUID isolation, mandatory EEPROM dump, write budget, lockfile, status
gate), and while the SSOT status is `derived-unvalidated` it additionally requires
`--accept-derived` for a single run on the locked debug unit. Run only on hardware you
own, **with waste pads installed**, and commit a clear with a clean power-button
shutdown. See [runbook/g6020-native-reset.md](runbook/g6020-native-reset.md) and
[ETHICS/RIGHT-TO-REPAIR.md](https://github.com/Jesssullivan/canon-megatank-reset/blob/main/ETHICS/RIGHT-TO-REPAIR.md).
