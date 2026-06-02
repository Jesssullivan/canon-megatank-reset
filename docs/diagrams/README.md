# Diagrams — Canon G6020 5B00 reset lifecycle + exploit flow

Source diagrams for the RE-to-native-reset story. Every claim in these diagrams is
traceable to a validated finding (see the per-file header comment for the exact
doc + line). The native reset they describe was **validated on real hardware**
(2026-06-01, commit `d2f3c81`).

## Files

| File | Engine | What it shows |
|---|---|---|
| `lifecycle.mmd` | Mermaid | RE-to-native-reset lifecycle: service-mode → transport → session → keyword → cipher → set_command → clean-power-off commit. |
| `maintenance-state-machine.mmd` | Mermaid | The service-mode maintenance protocol as a state machine (set_session / get_keyword / set_command / get_command + the register reads + the empty-0x86 + the commit). |
| `methodology-trifecta.mmd` | Mermaid | The trace ⟷ decompile ⟷ correlate loop (usbmon ⟷ Frida ⟷ Ghidra). |
| `exploit-dataflow.dot` | Graphviz | Full data-flow: APP.BIN decrypt → devices.xml template → functor-3 envelope + bound keyword → functor-2 → 23-byte set_command → usbprint VENDOR_SET → EEPROM. |
| `drm-bypass-controlflow.dot` | Graphviz | WICReset's reset orchestrator with the 3 cloud gates patched (JZ→JMP) → clearCounters → genuine emit. |

Sources are the **single source of truth**; rendered SVG/PNG are build artifacts
(gitignored — render locally with `just diagrams`). On the docs site the Mermaid
diagrams below render **client-side** from these same sources; the Graphviz diagrams
are prerendered to SVG at build time.

## The diagrams

### Lifecycle — RE to native reset (Mermaid)

```mermaid
--8<-- "lifecycle.mmd"
```

### Service-mode maintenance protocol — state machine (Mermaid)

```mermaid
--8<-- "maintenance-state-machine.mmd"
```

### Methodology trifecta — trace ⟷ decompile ⟷ correlate (Mermaid)

```mermaid
--8<-- "methodology-trifecta.mmd"
```

### Exploit / data-flow (Graphviz)

![Canon G6020 5B00 exploit / data-flow](exploit-dataflow.svg)

### Cloud-DRM bypass — control flow (Graphviz)

![WICReset cloud-DRM bypass control flow](drm-bypass-controlflow.svg)

## Rendering

```sh
just diagrams        # render every .mmd + .dot in this dir to SVG
just diagrams png    # also emit PNG
```

The recipe resolves the renderers at run time so nothing extra is vendored:

- **Mermaid** (`.mmd`) via the Mermaid CLI `mmdc`. If not on `PATH`, the recipe
  falls back to `npx --yes @mermaid-js/mermaid-cli`.
- **Graphviz** (`.dot`) via `dot`. Install with `nix profile install nixpkgs#graphviz`
  (or your platform package manager) if it is not already present.

Manual one-offs (what the recipe runs under the hood):

```sh
mmdc -i docs/diagrams/lifecycle.mmd -o docs/diagrams/lifecycle.svg
dot -Tsvg docs/diagrams/exploit-dataflow.dot -o docs/diagrams/exploit-dataflow.svg
```

## Accuracy notes (so the diagrams stay honest)

- **Transport** is usbprint VENDOR control on EP0, never bulk: `VENDOR_SET`
  (IOCTL `0x220038`) = `bmRequestType 0x41` OUT, `bRequest = frame[0]`, data = the
  whole frame verbatim; `VENDOR_GET` (`0x22003c`) = `0xC1` IN. Decompiled from
  `usbprint.sys` 10.0.26100.8328 (`docs/research/usbprint-vendor-urb-mapping.md`).
- **set_session is PLAIN** `81 00 00 03` (4 bytes); the enciphered 8-byte form
  stalls. **get_keyword** returns a live **3-byte** keyword — the only runtime
  input.
- **set_command is one 23-byte frame** `85 00 00 || payload(20)`, NOT a
  `prefix || 4-byte-keyword` form and NOT a select+clear concatenation. The write
  cipher is functor-2 with roles **swapped**: SUBJECT = the 20-byte functor-3
  envelope, SEED = the 4-byte bound keyword. Reproduces WICReset's genuine frame
  **23/23 byte-exact** (`docs/runbook/g6020-native-reset.md` §8).
- **get_command (0x86) is EMPTY by design** — there is no finalize command. Do not
  gate on it.
- **The commit is a clean power-BUTTON shutdown** (printhead park + EEPROM flush),
  NOT an unplug.
- **Cloud is licensing-only.** The reset is cloud-INDEPENDENT: `clearCounters` and
  its whole subtree are net-free; `QUERY_KEYS` collapses to one bool; no cloud byte
  feeds the payload, keyword, or completion (`docs/research/wicreset-drm-bypass.md`).
- The **3 DRM gates** patched in `drm-bypass-controlflow.dot` are exact VAs/bytes
  for `printerpotty.exe` sha256 `a199447db…564b3e8` only: `0x44012d` (RESET_GUID),
  `0x44054a` (QUERY_KEYS transport), `0x440563` (valid-bit) — each `74 → EB`.
