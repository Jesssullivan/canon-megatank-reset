# Canon ServiceTool staged-build model-table analysis (strings only)

**Question:** which staged Canon ServiceTool build knows the **G6020** (USB PID
`04a9:1865`, Canon's "G6000 series" in NA naming), so we know which build could
actually drive the fleet printer for the absorber / ink-counter reset?

**Method:** static analysis only — **no executables were run**. Each staged zip
was inspected and extracted on **mbp-13** (Rocky/EL10; GNU strings
2.41-58.el10_1.2, `unzip`, `7z`, `python3`). Every real `.exe` was scanned with
`strings -a` (ASCII) **and** `strings -a -el` (UTF-16LE) and grepped
case-insensitively (fixed-string) for the model/absorber tokens, then
re-verified with raw-byte, zlib-inflate, and direct PE `.rsrc` resource-section
walks.

## TL;DR

- **No staged build exposes the G6020 — or ANY G-series model name — as a
  string.** All four real binaries return **zero** hits for `G6000`, `G6020`,
  `G6040`, `G7000`, `G7020`, `G5000`, `G3000`, `G2000`, `G1000`, and
  `"G6000 series"` — in ASCII, UTF-16LE, raw bytes, inflated zlib streams, and
  the PE `.rsrc` section. There is **no `Gxxxx` model token of any kind** in any
  binary, including the full 22.9 MB v4718 and the 5.1 MB v6310.
- These are **native MFC PE32 apps** (the v4718 zip bundles `MFC40.DLL`,
  `MFC42D.DLL`, `mfco42d.dll`, `MSVCRTD.DLL`). The model dropdown is
  **populated at runtime** — the only model-related resource is the dialog
  literal `"Select model."`. The model **list is not embedded as plaintext**, so
  **static `strings` cannot answer the G6020 question for these artifacts.**
- Two zips are AES-encrypted; both were successfully decrypted here with the
  password **`1`** (the `pass 1.txt` zero-byte filename was the hint). So **all
  four versions were analyzed.**

**Best candidate to actually drive the G6020: none staged is strings-confirmed.**
Strings give no positive G6020 evidence for any build, and there is no negative
evidence either (the model table simply isn't in the executable). To get a build
that *provably* knows the G6020 we must go past strings — read the runtime model
picker in the capture VM, or find an external model table. See "Next steps".

## Source artifacts

| version | zip encryption | resolved real exe | size (B) | sections | analyzed |
|---|---|---|---|---|---|
| **v4718** | AES (pw `1`) | `ServiceTool_v4718.exe` | 22,929,506 | 12 | **yes (decrypted)** |
| **v4906** | store (open) | `ServiceTool_v4906.exe` | 633,856 | 4 | yes |
| **v5103** | AES (pw `1`) | `ServiceTool_v5103.exe` | 652,288 | 4 | yes (also `win-payload` twin) |
| **v6310** (bonus) | n/a (loose) | `~/canon-tool-staging/TOOL0006V6310.exe` | 5,131,264 | 4 | yes |

`TOOL0006V6310.exe` was not in the task's named set but is staged loose in
`~/canon-tool-staging/`; as the highest build number available it was analyzed as
the strongest bonus candidate. The AES-encrypted v5103 zip member is byte-size
identical to the decrypted twin at `~/canon-tool-staging/win-payload/`
(652,288 B), and both produce identical results.

Zip member listings (`unzip -l`):

- `ServiceTool_v4718.zip` (AES) → `ServiceTool_v4718.exe` (22,929,506),
  `MSVCRTD.DLL`, `MFC40.DLL`, `MFC42D.DLL`, `mfco42d.dll`, `pass 1.txt` (0 B).
- `ServiceTool_v4906.zip` (store) → `ServiceTool_v4906.exe` (633,856),
  `pass 1.txt` (0 B).
- `ServiceTool_v5103.zip` (AES) → `ServiceTool_v5103.exe` (652,288),
  `pass 1.txt` (0 B).

`pass 1.txt` is a zero-byte **filename hint** (the AES password is `1`), not a
README.

SHA-256 (verified stable across runs):

| version | sha256 |
|---|---|
| v4718 `ServiceTool_v4718.exe` | `8d9bb586724aac6c93f5dab266d8c41e51d3b9af1f48f1eb9ab1de96a6c1ae3c` |
| v4906 `ServiceTool_v4906.exe` | `ff3314edb763b7a670d2a2eb330fbdd633727d8cdb7e53534075d9c32eb8e991` |
| v5103 `ServiceTool_v5103.exe` | `98ca97b37a36a73d1a91630b8bde455b7dd109960073a0369295e34be6317c48` |
| v6310 `TOOL0006V6310.exe` | (re-hash on box — the value transferred corrupted over this channel) |

## Per-version token results (strings -a / strings -a -el)

Counts are `grep -i -c -F` against the ASCII and UTF-16LE corpora.

### v4718 — `ServiceTool_v4718.exe` (22,929,506 B; ascii 88,431 / utf16le 39,127 lines)

| token | ascii | utf16le |
|---|---|---|
| G6000 | 0 | 0 |
| G6020 | 0 | 0 |
| G6040 | 0 | 0 |
| G7000 | 0 | 0 |
| G7020 | 0 | 0 |
| G5000 | 0 | 0 |
| G3000 | 0 | 0 |
| G2000 | 0 | 0 |
| G1000 | 0 | 0 |
| "G6000 series" | 0 | 0 |
| absorber | 0 | 0 |
| Ink Absorber | 0 | 0 |
| Device | 3 | 8 |
| MDL | 5 | 21 |

No `Gxxxx` token anywhere. Only reset-/identity-relevant literals: `ResetThread`,
`ServiceTool`. (`Device`/`MDL` are generic symbol fragments, not a model table.)

### v4906 — `ServiceTool_v4906.exe` (633,856 B; ascii 1,846 / utf16le 4,117 lines)

All 14 tokens = **0 / 0**. No `Gxxxx` token. Only reset literal: `ResetThread`.

### v5103 — `ServiceTool_v5103.exe` (652,288 B; ascii 2,118 / utf16le 4,823 lines)

All 14 tokens = **0 / 0**. No `Gxxxx` token. Only reset literal: `ResetThread`.

### v6310 — `TOOL0006V6310.exe` (5,131,264 B; ascii 24,291 / utf16le 8,064 lines)

All 14 tokens = **0 / 0** (including `Device`/`MDL`). No `Gxxxx` token. No model
or absorber context.

## G-series rollup

| version | G6000 | G6020 | G6040 | G7000 | G7020 | G5000 | G3000 | G2000 | G1000 | G6000 series |
|---|---|---|---|---|---|---|---|---|---|---|
| v4718 | no | no | no | no | no | no | no | no | no | no |
| v4906 | no | no | no | no | no | no | no | no | no | no |
| v5103 | no | no | no | no | no | no | no | no | no | no |
| v6310 (bonus) | no | no | no | no | no | no | no | no | no | no |

`no` = string absent in ASCII + UTF-16LE + raw bytes + zlib + `.rsrc`.

## PE resource (`.rsrc`) inspection

Direct PE section walk + resource-string extraction:

| version | model tokens in rsrc | Gxxxx in rsrc |
|---|---|---|
| v4906 | only `"Select model."` | NONE |
| v5103 | only `"Select model."` | NONE |
| v6310 | none | NONE |

The `"Select model."` dialog label confirms a runtime-populated model picker —
the list is **not** stored in the executable. This is why every strings pass is
empty and why strings is the wrong instrument here.

## Absorber / EEPROM / idx / group-7 strings

**None found.** Across all four binaries, in ASCII + UTF-16LE + raw bytes +
`.rsrc`, there were zero hits for `absorber`, `Ink Absorber`, `ink counter`,
`EEPROM`, `idx`, `waste`, `maintenance`, `group 7` / `grp 7`, or `counter`. The
only reset-adjacent literal anywhere was the worker-thread symbol **`ResetThread`**
(present in v4718, v4906, and v5103) — a thread name, not a payload descriptor.

The group-7 payload semantics and the idx table are therefore **not** recoverable
from these binaries via strings. That intelligence already lives in this repo's
dynamic RE notes and remains the source of truth:

- `docs/research/servicetool-v5103-servicemode-reset-re.md`
- `docs/research/servicemode-ioctl-0x16000c.md`
- `docs/research/servicetool-v5103-reset-handshake.md`
- `docs/research/servicetool-v5103-read-re.md`

The wire bytes are also obfuscated by `EncCommService`
(`canon-tool-ghidra-notes.md` Finding F), reinforcing that the reset payload
is not legible at the strings layer.

## Why strings found nothing (and what it means)

- These are **native MFC apps**, not data tables. The model dropdown is built at
  runtime; the only resource hint is `"Select model."`.
- Confirmed by every independent method: ASCII strings = 0, UTF-16LE strings = 0,
  raw whole-file byte search = 0, **0 inflatable zlib streams**, and a direct
  `.rsrc` walk = 0 model tokens — even after decrypting the full 22.9 MB v4718.
- **Absence of token hits is NOT evidence a build lacks the G6020.** It is
  evidence the model table is not plaintext in the executable. Strings cannot
  distinguish "knows the G6020" from "doesn't" for these artifacts.

## Next steps (to actually determine G6020 support)

1. **Go dynamic — read the model picker.** Boot a real build
   (`win-payload/ServiceTool_v5103.exe`, or v6310/v4906/v4718) in the
   `canon-capture-win11-headless` capture VM and read the populated
   "Select model" dropdown directly. This is the definitive way to see whether a
   build offers the **G6020** (US/CA) / **G6080** (JP) / **G6050** (EU) MegaTank,
   and it also exposes the group-7 reset wiring strings can't.
2. **Find the model table.** If the list comes from an external file, locate it
   alongside each exe; if it comes from USB device enumeration (PID `1865`), the
   service-mode transport is already described in the dynamic RE notes above.
3. **Do not infer from build number.** Even v6310 (highest build, 5.1 MB)
   carries no model strings, so "newer build = knows G6020" is unverifiable from
   strings alone.

## Provenance

- Host: mbp-13 (Rocky/EL10); GNU strings 2.41-58.el10_1.2, unzip, 7z, python3.
- Extraction temp dir recorded in `mbp-13:/tmp/svc-stage-dir.txt`.
- AES zips (`ServiceTool_v4718.zip`, `ServiceTool_v5103.zip`) decrypted with
  password `1` via `7z x -p1`.
- Raw artifacts: `~/canon-tool-staging/ServiceTool_v4718.zip`,
  `ServiceTool_v4906.zip`, `ServiceTool_v5103.zip`,
  `~/canon-tool-staging/win-payload/ServiceTool_v5103.exe` (v5103 twin),
  `~/canon-tool-staging/TOOL0006V6310.exe` (bonus).
- No executable was run; static `strings`, raw-byte, zlib, and PE-`.rsrc`
  inspection only.
