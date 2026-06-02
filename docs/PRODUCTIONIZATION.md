# Productionization roadmap — canon-megatank-reset

> **✅ SHIPPED (2026-06-02).** Lanes G1–G5 are complete: the repo is public and
> released as `v0.1.0`, and its canonical home was **transferred to
> `Jesssullivan/canon-megatank-reset`** (the TIN-213 Jesssullivan-canonical
> topology). Shared-infra **authorities remain on `tinyland-inc`** (CI templates,
> RBE/cache, package registry — see `tinyland.repo.json`). The "tinyland-inc is
> canonical" framing in the historical sections below predates that transfer; the
> realized canonical is Jesssullivan. The embedded `gh` command logs are kept as a
> record of how the release was executed.

**Status:** the native G6020 5B00 reset is **hardware-validated** (commit `d2f3c81`,
2026-06-01; reference procedure `docs/runbook/g6020-native-reset.md`). This document
is the roadmap that took the tool from "validated on one debug unit" to a
**state-of-the-art, open, native-Linux FOSS release** — the first open Canon G-series
waste-counter resetter (`docs/research/sota-pixma-octo-lineage.md`: every other open
Canon repo is a closed-binary mirror; open resetters exist only for Epson).

It covers six lanes:

1. The multi-repo span (where this lives and what it touches).
2. A Linear epic + issue breakdown, **drafted as text only** (do not create in Linear).
3. The GitHub publish / mirror plan (visibility, LICENSE, SECURITY, the mirror).
4. The CI plan (Python lanes via ci-templates + the LaTeX paper build).
5. The secret-guard allowlist fix (the exact `.gitleaks.toml` + hook entries for the
   cipher hex in `docs/research/`).
6. The SOTA repo-hygiene + traceability plan (RE-evidence → code links, a docs index,
   the "next debugger" on-ramp).

> **Doc-truth gap to close first (P0).** `README.md` and `AGENTS.md` still describe the
> repo as *"early … reset payload/key derivation is the open target … Do not point this
> at a printer yet."* That was true before `d2f3c81`; it is now stale. The native reset
> is recovered, cracked (write cipher validated 23/23), and cleared 5B00 on real
> hardware. The status banners in `README.md` (the `> **Status:** early …` blockquote)
> and `AGENTS.md` (the *"reset payload + key/derivation is the open RE target"* line)
> must be updated to point at `docs/runbook/g6020-native-reset.md` and the
> `derived-unvalidated`→`verified-captured` promotion gate as the *only* remaining
> safety ceremony. This is issue **TIN-cmr-04** below and blocks the public release.

---

## 1. The multi-repo span

`canon-megatank-reset` is the **home** of the native reset and all of its RE evidence.
It was extracted (history-preserving) from `printstack` on 2026-05-29 and now owns the
reset end-to-end. The surrounding repos and their boundaries:

| Repo | Role w.r.t. this work | Direction |
|---|---|---|
| **`Jesssullivan/canon-megatank-reset`** | **Home (canonical, public).** Native pyusb tool, safety gates, SSOT (`printers/canon-g6020/maintenance.yaml`), RE research, runbooks, the paper. The `origin` remote points here (transferred from `tinyland-inc` 2026-06-02). | — |
| `printstack` (tinyland) | The **boundary** the reset was carved out of. printstack keeps **only** the CUPS `office`/`epson` print queue + email-to-print for the G6020; it has **no** reset code. The split is intentional and final — reset never returns to printstack. | upstream-of-extraction (frozen) |
| `jesssullivan/pixma` (← `leecher1337/pixma`) | **Interop / firmware cross-check.** The "doomed encryption" decrypt lineage (`pixma_decrypt`, `pixma_unpack`, `dec_sdata`) decodes MegaTank firmware, which carries the on-printer dispatch table. Our working fork adds a reproducible `Makefile` (branch `tin-1698-pixma-build-tooling`). We **reference** it (clone-alongside / future `third_party/pixma/` submodule), never vendor it. See `INTEROP.md`. | downstream consumer + upstream contributor |
| `tinyland-inc/ci-templates` | **CI authority.** `setup-nix@v2` + the `secrets-scan@v2` composite + the `PRIMARY_LINUX_RUNNER_LABELS_JSON` runner routing. Already consumed correctly by `.github/workflows/ci.yml`. | authority (consumed) |
| `tinyland-inc/site.scaffold` | The house repo-contract reference: `tinyland.repo.json` manifest shape, the canonical↔mirror topology, the `authorities` block. We mirror its manifest convention (§3). | convention source |
| `hiberpower-ntfs` | The **paper-build reference.** `docs/paper/` (IEEEtran + bytefield + cleveref + balance, vendored `.cls`/`.bst`/`.sty`) and `.github/workflows/build-paper.yml` (tectonic). We mirror both verbatim (§4). | convention source |
| `rules_tectonic` (jesssullivan) | The Bazel-native paper-build path **if/when** this repo adopts bzlmod. Not adopted yet (no `MODULE.bazel`), so the tectonic-CLI lane is the lower-friction productionization. | optional future authority |

### Publish topology (Jesssullivan-canonical)

**Realized topology (2026-06-02):** the canonical, public home is
**`Jesssullivan/canon-megatank-reset`** (transferred from `tinyland-inc` to match the
TIN-213 Jesssullivan-canonical convention). Shared-infra **authorities stay on
`tinyland-inc`** (`tinyland.repo.json` `authorities` block): CI templates, the RBE /
cache, and the package registry. The flow is:

```
            authors / RE / release                shared infra (authorities)
  Jesssullivan/canon-megatank-reset  ──uses──►  tinyland-inc/{ci-templates,
   (canonical; public FOSS release)              GloriousFlywheel, bazel-registry}
        │
        ├─► pixma findings ──► Jesssullivan/pixma ──► leecher1337/pixma (operator-driven)
        └─► GH issues mirror the Linear `Tinyland` team
```

A `tinyland-inc/canon-megatank-reset` mirror is optional/future (not currently created).

GH issues are a **mirror** of the Linear `Tinyland` team (the `foss`/`docs`/`security`
labels exist in both). The Linear initiative narrative still points at the pre-split
`Jesssullivan/printstack/services/canon-tool/` location and `PR #2`; those pointers are
**stale** and are corrected to `tinyland-inc/canon-megatank-reset` in the draft below
(issue **TIN-cmr-09**).

---

## 2. Linear epic + issue breakdown (DRAFT — text only, do NOT create in Linear)

> These are **drafts** for an operator to file by hand. No MCP `create` calls, no Linear
> mutations. Identifiers `TIN-cmr-NN` are placeholders for the real `TIN-####` the
> operator will mint. Model exactly on the live initiative
> **"Canon G-series Service Tool replacement"** (id `faa7f1b9-6d0f-4201-9531-8f8a15cd241b`,
> team `Tinyland`, a contextual sub-initiative of "Printstack"), whose projects are
> phase-named `canon-<phase>: <desc>` (canon-r0 … canon-phaseC).

### New project (phase) under the initiative

```
canon-phaseD: open publication — native reset paper + repo
```

A new project in the established phase style, sibling to `canon-phaseB: productionize as
services/canon-tool/` and `canon-phaseC: generalize for G3000/G4000/G7000`. Its issues
are below. Apply the workspace labels **`foss` + `docs` + `release`** to the project,
**`+ security`** to any issue carrying DRM-bypass content.

### Epic

> **Epic — Canon MegaTank native reset → SOTA FOSS release**
>
> Take the hardware-validated (`d2f3c81`) native G6020 5B00 reset from "works on the
> debug unit" to a citable, reproducible, publicly-released open tool: the first open,
> native-Linux, key-free, cloud-free Canon G-series waste-counter resetter. Ship the
> paper, the diagrams, the CI, the public repo, the secret-guard fix, the upstream
> contributions, the fleet role, and a second-unit validation. Inherits the
> initiative's **Safety enforcement** and **Legal posture** (reproduced verbatim at the
> end of this section).

### Issues

Each issue uses the house body convention (`## Why / ## Steps / ## The check / ## Status
as of <date>`), imperative titles, SHA/path-pinned references, cross-links, and the
branch convention `jess/tin-####-<slug>`.

---

**TIN-cmr-01 — Write the recovery paper (`docs/paper/recovery-paper.tex`)**
*Labels:* `foss`, `docs`, `security` · *Deps:* none · *Branch:* `jess/tin-cmr-01-recovery-paper`

- **Why:** The validated reset + the trace↔decompile↔correlate trifecta is novel and
  citable; no open Canon G-series resetter exists. A vendored-hermetic IEEEtran paper is
  the SOTA publication surface, mirroring `hiberpower-ntfs/docs/paper/`.
- **Steps:** new dir `docs/paper/`; `\documentclass[conference]{IEEEtran}`; vendor
  `IEEEtran.cls`/`.bst` + `bytefield.sty` + `cleveref.sty` + `balance.sty` next to the
  `.tex` (copy from `hiberpower-ntfs/docs/paper/`); `references.bib` (BibTeX); sections
  for transport (`usbprint-vendor-urb-mapping.md`), the wire codec
  (`g6020-wire-codec-crack.md`), the write-cipher crack
  (`g6020-genuine-setcommand-decode.md`), the DRM bypass (`wicreset-drm-bypass.md`),
  cloud-independence (`g6020-reset-completion.md`), and the validated procedure
  (`docs/runbook/g6020-native-reset.md`).
- **The check:** `cd docs/paper && tectonic recovery-paper.tex` produces a PDF locally;
  the paper-build CI lane (TIN-cmr-03) is green; every claim cites a tracked
  `docs/research/*.md`.
- **Acceptance criteria:** PDF builds hermetically (no system TeX); each empirical claim
  carries a footnote/cite to a `docs/research` or `docs/runbook` file; legal posture
  section reproduces the DMCA §1201 / *Sega v. Accolade* framing.

**TIN-cmr-02 — Author the wire diagrams (bytefield)**
*Labels:* `foss`, `docs` · *Deps:* TIN-cmr-01 · *Branch:* `jess/tin-cmr-02-wire-diagrams`

- **Why:** The two load-bearing structures — the `0x41` OUT / `0xC1` IN vendor-control
  transport and the 20-byte functor-3 envelope / 4-byte bound-keyword seed — are exactly
  what `bytefield` renders well.
- **Steps:** bytefield diagrams for (a) the VENDOR_SET/VENDOR_GET setup packet
  (`bmRequestType=0x41/0xC1`, `bRequest=frame[0]`, `wValue=(f[1]<<8)|f[2]`); (b) the
  23-byte `set_command` frame = `85 00 00 || payload(20)`; (c) the cipher pipeline
  `app → envelope3(20) → functor2_transform(seed=bound_keyword) → wire`.
- **The check:** diagrams compile inside the paper; byte offsets match
  `docs/runbook/g6020-native-reset.md` §2–§3 and the 23/23 ground-truth frame in §8.
- **Acceptance criteria:** the SELECTOR `850000dbbb…b1ef` and CLEAR `8500004dbb…b1ef`
  byte-exact frames (runbook §8) appear and are annotated against the diagram.

**TIN-cmr-03 — Add the LaTeX paper-build CI lane**
*Labels:* `docs`, `release` · *Deps:* TIN-cmr-01 · *Branch:* `jess/tin-cmr-03-paper-build-ci`

- **Why:** Keep the published PDF reproducible and current without manual builds.
- **Steps:** add `.github/workflows/build-paper.yml` mirroring
  `hiberpower-ntfs/.github/workflows/build-paper.yml` verbatim — `on.{push,pull_request}.
  paths: ['docs/paper/**']` + `workflow_dispatch`; `actions/checkout@v6`;
  `wtfjoke/setup-tectonic@v3` (`github-token: ${{ secrets.GITHUB_TOKEN }}`); `cd
  docs/paper && tectonic recovery-paper.tex`; `actions/upload-artifact@v4`;
  `stefanzweifel/git-auto-commit-action@v5` guarded by `if: github.ref ==
  'refs/heads/main' && github.event_name == 'push'`. **Keep it OUTSIDE the Nix/just
  lanes** (the tectonic action self-installs).
- **The check:** workflow runs on a `docs/paper/**` change; PDF uploaded as an artifact;
  on push-to-main the rebuilt PDF is recommitted.
- **Acceptance criteria:** green run on a no-op `docs/paper` edit; artifact named
  `recovery-paper`; no Nix dependency in the lane.

**TIN-cmr-04 — Reconcile README/AGENTS status to "validated" (P0 doc-truth)**
*Labels:* `docs` · *Deps:* none · *Branch:* `jess/tin-cmr-04-status-reconcile`

- **Why:** `README.md` and `AGENTS.md` still say *"early … do not point this at a printer
  yet"*; `d2f3c81` invalidates that. Publishing with a stale "doesn't work yet" banner is
  a credibility and safety hazard.
- **Steps:** update the `README.md` Status blockquote and the `AGENTS.md` *"reset payload
  + key/derivation is the open RE target"* line to reflect: transport solved, write
  cipher cracked + validated 23/23, native reset cleared 5B00 on hardware
  (`docs/runbook/g6020-native-reset.md`); the *only* remaining ceremony is the
  per-physical-unit `derived-unvalidated`→`verified-captured` SSOT promotion (still gated,
  still requires `--accept-derived`).
- **The check:** README/AGENTS link `docs/runbook/g6020-native-reset.md`; no remaining
  "open target"/"do not point at a printer" language; the SSOT-promotion gate is the
  documented safety ceiling.
- **Acceptance criteria:** `just check` green; the docs index (TIN-cmr-10) lists the
  validated runbook as the entrypoint.

**TIN-cmr-05 — Publish the repo on GitHub (visibility + LICENSE + SECURITY)**
*Labels:* `foss`, `release`, `security` · *Deps:* TIN-cmr-04, TIN-cmr-06 · *Branch:* `jess/tin-cmr-05-gh-publish`

- **Why:** This is the public FOSS release of the first open Canon G-series resetter.
- **Steps:** add a `LICENSE` (see §3 — recommend a permissive license for the tool +
  explicit interop/right-to-repair statement); confirm `SECURITY.md` responsible-use
  policy is current (it exists; extend per §3); add `CONTRIBUTING.md`; flip repo to
  **public** on `tinyland-inc`; tag a release; ensure the `Jesssullivan` working-clone →
  `tinyland-inc` PR mirror is documented.
- **The check:** public repo builds (CI green), LICENSE + SECURITY + CONTRIBUTING present,
  a tagged release with the paper PDF attached.
- **Acceptance criteria:** no Canon/WICReset/firmware binaries in history (`.gitignore`
  enforced; secrets-scan green); the release notes link the paper and the validated
  runbook.

**TIN-cmr-06 — Land the secret-guard allowlist for `docs/research` cipher hex**
*Labels:* `security`, `docs` · *Deps:* none · *Branch:* `jess/tin-cmr-06-secretguard-allowlist`

- **Why:** The RE docs contain 40+-char cipher hex (e.g.
  `g6020-wire-codec-crack.md:72`, `g6020-genuine-setcommand-decode.md:57-58`) that trips
  the global hook's `check_high_entropy` and gitleaks' generic-entropy rules. Past
  commits only landed via `--no-verify`; publishing must not depend on that.
- **Steps:** the two complementary edits in §5 — (a) in-repo `.gitleaks.toml` allowlist
  scoping `docs/research` + `docs/paper`; (b) the **drafted** patch to the home-manager
  hook source `ALLOWED_FILE_PATTERNS` (outside this repo — draft only, operator applies +
  `home-manager switch`).
- **The check:** `just secrets-scan` + the ci-templates `secrets-scan@v2` lane green on a
  fresh commit touching a cipher-hex doc, **without** `--no-verify`.
- **Acceptance criteria:** a test commit adding a 40+-hex line under `docs/research/`
  passes both the global pre-commit hook and CI.

**TIN-cmr-07 — Offer the MegaTank findings upstream to the pixma lineage**
*Labels:* `foss` · *Deps:* TIN-cmr-05 · *Branch:* `jess/tin-cmr-07-pixma-upstream`

- **Why:** `INTEROP.md` T6 commits to upstreaming the firmware-decrypt improvements +
  MegaTank findings rather than a silent fork; SOTA review confirms pixma forks add only
  compile fixes — the dispatch-table cross-check + reproducible `Makefile` are net-new.
- **Steps:** PR the reproducible `Makefile` + portability fix from
  `jesssullivan/pixma` (`tin-1698-pixma-build-tooling`) toward `leecher1337/pixma`; file a
  findings issue linking the G6000-series `devices.xml` template recovery + the cipher
  decompile (no binary redistribution).
- **The check:** an upstream PR/issue exists referencing this repo's research docs.
- **Acceptance criteria:** PR drafted from the personal fork; cross-linked from
  `INTEROP.md`.

**TIN-cmr-08 — Build the T5b fleet-deploy Ansible role**
*Labels:* `release` · *Deps:* TIN-cmr-04 · *Branch:* `jess/tin-cmr-08-fleet-t5b`

- **Why:** The validated reset must roll across the surplus-G6020 refurb fleet under
  Ansible, behind the same safety gates, not just on mbp-13.
- **Steps:** extend `host/` with a fleet-deploy role wiring `canon-megatank reset-native`
  behind the gate ladder (`docs/runbook/g6020-native-reset.md` §5); per-unit UUID gate +
  per-unit EEPROM dump + per-unit write budget; surface the clean-power-button-commit
  instruction (§4½) as an operator step.
- **The check:** `just ansible-lint` + `just yaml-lint` green; a dry-run play renders the
  gated sequence without touching a device.
- **Acceptance criteria:** role refuses any UUID ≠ that unit's locked `test_unit`;
  documents the manual `verified-captured` promotion per physical unit.

**TIN-cmr-09 — Correct the stale repo/PR pointers in the Linear initiative**
*Labels:* `internal`, `docs` · *Deps:* none · *Branch:* n/a (Linear-only)

- **Why:** The initiative narrative still points at
  `Jesssullivan/printstack/services/canon-tool/` and `PR #2`; the post-split home is
  `tinyland-inc/canon-megatank-reset`.
- **Steps (drafted, operator applies in Linear):** update the initiative's repo/PR
  references to `tinyland-inc/canon-megatank-reset`; note the printstack boundary (CUPS
  queue only); add `canon-phaseD` as above.
- **The check:** initiative references resolve to the live repo.
- **Acceptance criteria:** no remaining `services/canon-tool` / `PR #2` pointers.

**TIN-cmr-10 — Second-unit validation + `verified-captured` promotion**
*Labels:* `release` · *Deps:* TIN-cmr-08 · *Branch:* `jess/tin-cmr-10-second-unit`

- **Why:** `d2f3c81` validated **one** debug unit; the SSOT stays `derived-unvalidated`
  by design (`docs/runbook/g6020-native-reset.md` §7). A second independent
  pads-installed clear de-risks the family hypothesis and is the gate to promote.
- **Steps:** on a second surplus G6020 (new pads / Printer Potty kit fitted): fresh EEPROM
  baseline → gated `reset-native --execute --accept-derived` → live-keyword read →
  clean power-button commit → confirm `04a9:1865` re-enumeration + 5B00 gone; then
  manually promote that unit's SSOT entry to `verified-captured`.
- **The check:** 5B00 cleared on a second physical unit; `--execute` no longer needs
  `--accept-derived` for that unit.
- **Acceptance criteria:** captured run logged; SSOT promotion is a deliberate per-unit
  decision, never an automatic flip.

### Dependency graph (text)

```
TIN-cmr-04 (status) ─┬─► TIN-cmr-05 (publish) ─► TIN-cmr-07 (pixma upstream)
TIN-cmr-06 (secret-guard) ─┘
TIN-cmr-01 (paper) ─┬─► TIN-cmr-02 (diagrams)
                    └─► TIN-cmr-03 (paper CI)
TIN-cmr-04 ─► TIN-cmr-08 (fleet T5b) ─► TIN-cmr-10 (second-unit + promote)
TIN-cmr-09 (Linear pointers) — independent
```

### Safety enforcement (reproduce verbatim from the initiative)

1. **Ping-suite baseline** before any write.
2. **EEPROM dump + checksum** pre-flight (rollback baseline).
3. **50-write budget** per unit, persisted; refuse when exhausted.
4. **UUID `test_unit` gate** — refuse any fingerprint ≠ the locked unit.
5. **Walk-up + physical-button confirm** (and, for this reset, the clean
   power-button commit, not unplug — `docs/runbook/g6020-native-reset.md` §4½).

### Legal posture (reproduce verbatim from the initiative)

DMCA §1201 has an explicit diagnostic/maintenance **repair exemption** (renewed
2018+). Reverse-engineering for **interoperability** is fair use under *Sega v.
Accolade* / *Sony v. Connectix*. **No binary / firmware redistribution** — only our own
scripts and curated findings are tracked.

---

## 3. GitHub publish / mirror plan

### Visibility

Flip `tinyland-inc/canon-megatank-reset` to **public** at release (TIN-cmr-05), after
TIN-cmr-04 (status reconcile) and TIN-cmr-06 (secret-guard) land. The repo already lives
on the canonical org; no transfer is needed (and per MEMORY, **do not** transfer between
orgs to reach Flywheel runners — the `PRIMARY_LINUX_RUNNER_LABELS_JSON` routing already
works in both).

### LICENSE (currently MISSING)

Add a top-level `LICENSE`. Recommended posture for an interop/right-to-repair tool:

- A permissive OSI license (**MIT** or **Apache-2.0**) for the tool source
  (`src/`, `scripts/`, `host/`). Apache-2.0 is the stronger choice here — its explicit
  patent grant and NOTICE mechanism suit a tool that exercises a §1201 interop exemption.
- A short **interop / no-redistribution** statement in `LICENSE` or `NOTICE` reaffirming
  `SECURITY.md`: the repo carries **no** Canon Service Tool / WICReset / Canon firmware /
  Ghidra-DB binaries; only independently-authored scripts + curated findings; RE is for
  interoperability and repair.
- The research prose + paper (`docs/research/`, `docs/paper/`) may carry a separate
  **CC-BY-4.0** note so the findings are citable/reusable as documentation. State the
  split explicitly in `LICENSE`.

### SECURITY.md (EXISTS — extend)

`SECURITY.md` already covers responsible use, test-unit isolation, the no-binary policy,
the secrets posture, and private-advisory reporting. For release, extend it with: the
**physical-safety-first** ordering (fit new pads / waste-ink kit before any reset — the
counter clear lets a *physically* full absorber overflow; OctoInkjet's instruction), the
**clean-power-button-commit** requirement (`g6020-native-reset.md` §4½), and a pointer to
the §5 secret-guard allowlist so contributors don't `--no-verify`.

### CONTRIBUTING.md (MISSING — add)

State the operating contract: `AGENTS.md` first; **`just <recipe>` is the only
entrypoint** (never raw `pytest`/`ansible-playbook`/`ghidra`/`tshark`); `nix develop`
(auto via direnv) for the shell; `just check && just test` before pushing; the
secret-guard allowlist scope (don't `--no-verify`); no binary/firmware in commits; the
canonical↔`Jesssullivan` PR mirror.

### tinyland.repo.json (MISSING — add, validated by spoke-CI)

Add a root manifest mirroring `ci-templates/tinyland.repo.json` and
`site.scaffold/tinyland.repo.json`:

```json
{
  "$schema": "./schemas/tinyland-repo-manifest.schema.json",
  "schema_version": 1,
  "repo": {
    "name": "canon-megatank-reset",
    "github": "tinyland-inc/canon-megatank-reset",
    "description": "Open, native-Linux, key-free, cloud-free Canon MegaTank (G-series) waste-ink (5B00) absorber-counter reset, recovered by reverse engineering and validated on hardware.",
    "linear": { "initiative": "TIN-<canon-initiative>", "issue": "TIN-<tracking>" }
  },
  "taxonomy": {
    "primary_role": "right-to-repair-tool",
    "layers": ["org-wide-repo-contract", "reverse-engineering-tool", "right-to-repair-tool"]
  },
  "contracts": {
    "agent_contract": "AGENTS.md",
    "just": "Justfile",
    "nix": "flake.nix",
    "github_actions": ".github/workflows",
    "secrets_scan": "gitleaks",
    "conformance": "just check"
  },
  "boundaries": {
    "owns_runtime_backend": false,
    "owns_auth": false,
    "owns_payments": false,
    "owns_activitypub_delivery": false,
    "owns_live_broker_fetch": false,
    "owns_static_projection_ingest": false,
    "owns_gitops_apply": false,
    "owns_cloudflare_mutation": false,
    "owns_bazel_module_authority": false
  },
  "authorities": {
    "content_authority": "tinyland.dev",
    "gitops_receiver": "tinyland-inc/blahaj",
    "ci_templates": "tinyland-inc/ci-templates",
    "cache_rbe_authority": "tinyland-inc/GloriousFlywheel",
    "tofu_module_authority": "tinyland-inc/GloriousFlywheel",
    "package_registry": "tinyland-inc/bazel-registry"
  },
  "supply_chain": {
    "sbom": {
      "status": "not-required",
      "formats": [],
      "notes": "Publishes RE findings + scripts, not application artifacts (same posture as ci-templates)."
    }
  }
}
```

### Canonical home

- **Canonical:** `Jesssullivan/canon-megatank-reset` (origin; public release).
- **Authorities (shared infra):** `tinyland-inc/{ci-templates, GloriousFlywheel, bazel-registry}`.
- **Mirror:** `tinyland-inc/canon-megatank-reset` is optional/future (not currently created).
- **Issues:** GH issues mirror the Linear `Tinyland` team.
- **Upstream:** pixma findings flow `Jesssullivan/pixma` → `leecher1337/pixma`
  (TIN-cmr-07; operator-driven).

---

## 4. CI plan

### Python lanes (already conformant — do NOT rebuild)

`.github/workflows/ci.yml` already runs the house pattern on every job
(`actions/checkout@v6` → `tinyland-inc/ci-templates/.github/actions/setup-nix@v2` →
`nix develop --command just <recipe>`), `runs-on` via `PRIMARY_LINUX_RUNNER_LABELS_JSON
|| ["ubuntu-latest"]` (GloriousFlywheel `tinyland-nix` with fallback), `permissions:
{contents: read, statuses: write}`, cancel-in-progress concurrency. Three jobs:

| Job | Recipe | What |
|---|---|---|
| `secrets-scan` | `just secrets-scan` | gitleaks history scan |
| `check` | `just check` | ruff + mypy(strict) + yamllint + ansible-lint |
| `test` | `just test` | pytest (fingerprint, pcap, protocol property tests) |

**Leave `runs-on` as-is** — already the correct Flywheel routing with graceful fallback.

Optional, low-cost additions (mirror the existing job shape):

- Add `just model` (the offline protocol property tests,
  `tests/test_protocol_model.py`) as a **fast, hardware-free** gate that fails quickly
  before the full `just test` env build.
- Add `just format-check` (`ruff format --check`) to `check`.

### Paper-build lane (NEW — TIN-cmr-03)

Add `.github/workflows/build-paper.yml`, **outside** the Nix/just lanes, mirroring
`hiberpower-ntfs/.github/workflows/build-paper.yml` verbatim:

- `on.{push,pull_request}.paths: ['docs/paper/**']` + `workflow_dispatch`.
- `actions/checkout@v6` → `wtfjoke/setup-tectonic@v3` (`github-token:
  ${{ secrets.GITHUB_TOKEN }}`) → `cd docs/paper && tectonic recovery-paper.tex`.
- `actions/upload-artifact@v4` (name `recovery-paper`, path
  `docs/paper/recovery-paper.pdf`).
- `stefanzweifel/git-auto-commit-action@v5` guarded by
  `if: github.ref == 'refs/heads/main' && github.event_name == 'push'` to recommit the
  rebuilt PDF.

The tectonic action self-installs TeX, so this lane does **not** consume the devshell.
Hermeticity comes from **vendoring** `IEEEtran.cls` + `IEEEtran.bst` + `bytefield.sty` +
`cleveref.sty` + `balance.sty` next to the `.tex` (copy from `hiberpower-ntfs`).

> **Bazel-native alternative (future).** When/if this repo adopts bzlmod (it has no
> `MODULE.bazel` today), `rules_tectonic` gives a self-contained `tectonic_pdf(name, src,
> deps=[*.tex], data=[*.bib, figures/*.pdf])` target. Until then the CLI lane is the
> lower-friction path.

---

## 5. Secret-guard allowlist fix

The cipher hex in the RE docs (40+ hex chars after `=`/`:`) is legitimate evidence, not a
leaked secret, but it trips two scanners. Both must be quieted **without** `--no-verify`.

### 5a. In-repo: `.gitleaks.toml` (apply now)

`.gitleaks.toml` currently has a placeholder allowlist (`paths = ["^$"]`) and
`[extend] useDefault = true` (which pulls gitleaks' generic high-entropy rules onto the
same content). Replace the placeholder with a scoped allowlist:

```toml
title = "canon-megatank-reset"

[extend]
useDefault = true

[[allowlists]]
description = "Reverse-engineering evidence: cipher hex in RE docs and the paper are findings, not secrets."
paths = [
  '''docs/research/.*\.md$''',
  '''docs/paper/.*''',
]
# Optionally also exempt the bare cipher-hex token itself, defensively:
regexes = [
  '''(?i)\b[0-9a-f]{40,}\b''',
]
```

Scope the `regexes` entry narrowly (or drop it and rely on `paths`) so it does not blanket
the source tree. This keeps `just secrets-scan` (`gitleaks git`) and the ci-templates
`secrets-scan@v2` composite (TruffleHog `--only-verified` + gitleaks 8.21.2) green.

### 5b. Home-manager hook (DRAFT — operator applies; OUTSIDE this repo)

The active gate is the global pre-commit hook at `~/.config/git/hooks/pre-commit`
(generated, "DO NOT EDIT"), whose Nix source is
`/Users/jess/git/lab/nix/modules/tools/global-git-hooks.nix`. Its `check_high_entropy()`
regex `([:=]\s*["\x27]?[0-9a-fA-F]{40,}["\x27]?)` fires on the RE docs. There is **no**
env-var escape and `.md` is **not** in `SOURCE_CODE_EXTENSIONS`, so docs are
content-scanned; the **only** clean skip is the `is_allowed()` path allowlist, fed by the
hardcoded `ALLOWED_FILE_PATTERNS=(…)` array at `global-git-hooks.nix:129`. A repo-local
`.git/hook` cannot help — the Phase-2 global content scan always runs after the Phase-1
local hook succeeds.

**Drafted patch** (operator applies, then `home-manager switch` to regenerate the hook):

```nix
    ALLOWED_FILE_PATTERNS=(
      '\.env\.example$'
      '\.env\.template$'
      '\.env\.sample$'
      '\.kdbx$'
      'roles/keepassxc-pretasks/'
      'MODULE\.bazel$'
      'flake\.lock$'
      '\.zig$'
      'docs/research/'      # RE cipher-hex evidence (canon-megatank-reset)
      'docs/paper/'         # vendored .sty/.bbl + paper hex tables
    )
```

This is the cited "allowlist for `docs/research`." It is **outside** the working repo
(`lab` is a grounding repo, read-only here), so it is drafted, not applied — the operator
makes the `lab` edit and runs `home-manager switch`. The in-repo 5a edit lands now and is
sufficient for CI; the hook edit removes the local-commit friction.

---

## 6. SOTA repo-hygiene + traceability plan

The differentiator for a SOTA RE release is that **the next debugger can walk from RE
evidence → code** without the original author. Three deliverables.

### 6a. RE-evidence → code traceability matrix

Every wire fact in the validated reset already has both an evidence doc and a code
landing; make the mapping explicit (add it to the paper and the docs index). The
load-bearing links today:

| RE finding | Evidence (`docs/research` / `docs/runbook`) | Code landing (`src/`, `scripts/`, SSOT) |
|---|---|---|
| Vendor-control transport (`0x41` OUT / `0xC1` IN, `bRequest=frame[0]`) | `usbprint-vendor-urb-mapping.md` §7; runbook §2 | `protocol/servicemode_transport.py` (frame-shape routing) |
| Plain `set_session` + live per-session keyword (`0x82`) | runbook §3 step 2; memory narrative | `ops.py::reset_absorber_wicreset`; `usb.py` keyword read |
| Wire codec (`0x84` model/1284 XOR-stream) | `g6020-wire-codec-crack.md` | `scripts/g6020_wire_codec_crack.py` |
| functor-3 envelope + the swapped-buffer write cipher (functor-2, SUBJECT=20-byte envelope, SEED=4-byte bound keyword) | `g6020-genuine-setcommand-decode.md`; runbook §3 | `protocol/wicreset.py` (`functor3_encrypt`/`envelope3`/`functor2_transform`/`bind_keyword`); `scripts/canon_sr5_cipher.py` |
| 23/23 ground-truth frame match | runbook §8 (SELECTOR `850000dbbb…b1ef`, CLEAR `8500004dbb…b1ef`) | SSOT `maintenance.yaml` `derived_sequence.hardware_validated_frames` |
| Cloud-independence (no cloud byte feeds payload/keyword/completion) | `wicreset-cloud-vs-local-template.md`; `g6020-reset-completion.md`; runbook §6 | n/a (negative result; cipher is fully local) |
| DRM bypass to capture the genuine frame (3 JZ→JMP gates) | `wicreset-drm-bypass.md` | `host/vm-capture/win/frida-drm-reset-hook.js` |
| Template DB is bundled + 3DES-zero-key obfuscation (not cloud) | `wicreset-appbin-cipher.md` | `scripts/appbin_decrypt.py` |
| Clean-power-button commit (not unplug) | runbook §4½ | `ops.py::COMMIT_INSTRUCTION` (echoed as `commit_step`) |

### 6b. A docs index (`docs/README.md` — MISSING, add)

There is no docs index today (53 research/runbook files, unindexed). Add `docs/README.md`
as the on-ramp, structured by the trifecta:

- **Start here:** `docs/runbook/g6020-native-reset.md` (the validated procedure) +
  `docs/adr/0007-canon-tool-reverse-engineering.md` (why/how).
- **Trace lane (host usbmon wire capture):** the `wicreset-linux-capture-*` /
  `g6020-session-capture` runbooks + `usbprint-vendor-urb-mapping.md`.
- **Decompile lane (Ghidra):** `wicreset-printerpotty-static-re.md`,
  `g6020-genuine-setcommand-decode.md`, `wicreset-appbin-cipher.md`.
- **Instrument lane (Frida / Win11 VM DRM bypass):** `wicreset-drm-bypass.md`,
  `sota-dynamic-instrumentation.md`.
- **Correlate / verdict:** `wicreset-cloud-vs-local-template.md`,
  `g6020-reset-completion.md`, `g6020-reset-crossval.md`.
- **The 6a matrix** reproduced so the index *is* the evidence→code map.
- A **dead-ends** section linking the falsified paths (`live-reset-write-2026-05-31.md`,
  the bulk-group-7 / cloud-nonce gambles) so the next debugger doesn't re-walk them.

### 6c. The "next debugger" on-ramp

Codify the reproduction story end-to-end so a stranger can rebuild the result:

1. **Clone + shell:** `direnv allow` → `just check && just test` (no hardware).
2. **Read the trifecta:** the docs index (6b) → the validated runbook → the 6a matrix.
3. **Dry-run the reset:** `canon-megatank reset-native` (no `--execute`) prints every
   wire frame + the commit step without touching USB.
4. **Reproduce the cipher offline:** `scripts/canon_sr5_cipher.py` +
   `scripts/appbin_decrypt.py` re-derive the 23/23 frames from a decrypted
   `devices.xml` — no key, no device, no cloud.
5. **The paper** (`docs/paper/`) is the citable narrative; every claim footnotes a
   tracked `docs/research` file (6a).
6. **Validate on hardware** only behind the gate ladder (runbook §5) on a unit whose
   absorber has been physically serviced first.

**One residual SSOT-hygiene item** (from the validated session, runbook §8 note): the
SSOT `derived_template` shift-table must stay synced with `devices.xml` so both code
paths reproduce 23/23 (a drift gave 17/20 mid-session). Track it as a `just`-checkable
invariant or a regression test asserting the SSOT frames equal the ground-truth frames in
runbook §8. This is the single hygiene gap between "validated once" and "validated
reproducibly by anyone."

---

## 7. Master plan + gated actions

> This section consolidates §§1–6 and the sibling lanes (paper, diagrams, INTEROP,
> ETHICS) into one sequenced plan, a gated external-action checklist, an artifacts index,
> and the single next step. It is the operator's control panel: everything that mutates an
> external system (Linear, GitHub, `git push`, CI enablement, the pixma upstream) is held
> behind an explicit OK with the exact command/MCP call to run on approval.
>
> **State as of 2026-06-01** (verified, not assumed):
> - Branch `feat/g6020-native-reset`; `origin = https://github.com/tinyland-inc/canon-megatank-reset.git` (canonical org, **private**).
> - Working tree (uncommitted): `M .gitignore`, `M INTEROP.md`, `M Justfile`; untracked `docs/paper/`, `docs/diagrams/`, `docs/PRODUCTIONIZATION.md`, `ETHICS/`, `.github/workflows/build-paper.yml.draft`.
> - Paper builds: `docs/paper/canon-megatank-reset.tex` → `canon-megatank-reset.pdf` (115 KiB, 0 errors), with `IEEEtran.cls/.bst`, `bytefield/cleveref/balance.sty`, `references.bib` (8 TODO entries) all vendored next to it.
> - `LICENSE`, `CONTRIBUTING.md`, `tinyland.repo.json`, `docs/README.md` are **MISSING**. `SECURITY.md` and `INTEROP.md` exist.
> - `.gitleaks.toml` still holds the placeholder `paths = ["^$"]` (the §5a allowlist is **not** applied).
> - Paper-build CI is `.github/workflows/build-paper.yml.draft` (authored, **not** enabled).
> - Live Linear initiative: **`faa7f1b9-6d0f-4201-9531-8f8a15cd241b`** (Active, team `Tinyland`, target 2026-07-15). A **stale duplicate** `44799807-2df0-4e46-83a9-a4f679ff53b4` (same name, Completed, **no projects**) should be archived/ignored — file all `canon-phaseD` work under the Active one.
> - **P0 doc-truth gap still open:** `README.md`/`AGENTS.md` still say "early … do not point at a printer yet" (TIN-cmr-04).

### 7.1 Sequenced master plan

Work splits into **in-repo edits** (no gate — safe to make on a branch in the working
clone) and **external actions** (gated — §7.2). The recommended order:

**Wave 0 — Land what already exists locally (in-repo, ungated).**
The four sibling lanes already wrote artifacts into the working tree but nothing is
committed. Stage them on the current branch:

0a. Apply the in-repo `.gitleaks.toml` allowlist (§5a) **first**, so the cipher-hex
    content in `docs/paper/` + `docs/research/` does not block the commit (still needs the
    `--no-verify` local-hook workaround OR the §5b home-manager patch until that lands —
    see G3).
0b. Commit the paper (`docs/paper/`), diagrams (`docs/diagrams/`), `INTEROP.md` rewrite,
    `ETHICS/RIGHT-TO-REPAIR.md`, `Justfile` `diagrams` recipe, `.gitignore` stanzas, and
    `docs/PRODUCTIONIZATION.md` itself.
0c. Add the four MISSING contract files in-repo: `LICENSE` (Apache-2.0 tool + CC-BY-4.0
    docs split, §3), `CONTRIBUTING.md` (§3), `tinyland.repo.json` (§3 full JSON), and
    `docs/README.md` (§6b docs index).
0d. **TIN-cmr-04 (P0):** reconcile `README.md` + `AGENTS.md` status banners to
    "hardware-validated" (§2 TIN-cmr-04). This is the release blocker and is pure in-repo
    text — do it before any publish.
0e. Rename `.github/workflows/build-paper.yml.draft` →
    `build-paper.yml` (the file name in the workflow is already correct:
    `cd docs/paper && tectonic canon-megatank-reset.tex`). Enabling CI only takes effect
    once pushed — so this is staged in Wave 0 but its effect is gated at G4.
0f. Optional hardening before publish: the SSOT-frame regression invariant (§6c residual
    item) and `just model`/`just format-check` CI additions (§4).

**Wave 1 — Secret-guard durability (one gated external step).**
0a quiets CI; the durable local fix is the home-manager hook patch (§5b, **G3**) so future
cipher-doc commits don't need `--no-verify`. Land this before inviting outside
contributors.

**Wave 2 — Publish (gated).**
After Wave 0 is committed and pushed (**G1** push, **G2** Linear epic so work is tracked),
flip the repo public and tag a release (**G5**). Order inside the gate: confirm
secrets-scan green on the pushed branch → merge to `main` → `build-paper.yml` runs and
recommits the PDF (**G4**) → flip visibility → tag.

**Wave 3 — Upstream + fleet + second unit (gated / hardware).**
The pixma upstream PR (**G6**) only after publish (it references the public repo) and only
when its preconditions hold (firmware sourced + leecher LICENSE — currently blocked;
the build-tooling-only PR can go sooner). The T5b fleet role (TIN-cmr-08) and second-unit
`verified-captured` promotion (TIN-cmr-10) are hardware-gated, not external-system-gated,
and proceed on their own track.

**Critical path:** `0a → 0b/0c/0d (in-repo) → G1 (push) → G2 (Linear) → G3 (hook) → G4
(CI on main) → G5 (publish+tag) → G6 (pixma)`. Diagrams/paper polish and fleet/second-unit
hang off the side.

### 7.2 GATED external-action checklist

> Nothing below has been executed. Each is held for the operator's explicit, one-by-one
> greenlight. Run the listed command/MCP call **only** on approval. Defaults assume the
> working clone has `origin = tinyland-inc/canon-megatank-reset`.

---

**G1 — Push the productionization branch to the canonical remote**
*Gate: needs OK (first push of these artifacts).* *Blocks: G2, G4, G5.*

Preconditions: Wave 0 committed; `just check && just test` green; `just secrets-scan`
green (after §5a `.gitleaks.toml` edit).

```bash
# from /Users/jess/git/canon-megatank-reset
git add .gitleaks.toml docs/paper docs/diagrams docs/PRODUCTIONIZATION.md ETHICS \
        INTEROP.md Justfile .gitignore LICENSE CONTRIBUTING.md tinyland.repo.json \
        docs/README.md README.md AGENTS.md .github/workflows/build-paper.yml
git commit -m "docs: native MegaTank reset paper, diagrams, productionization, publish contracts"
git push -u origin feat/g6020-native-reset
```
Then open a PR into `main` (gated separately if desired):
```bash
gh pr create --repo tinyland-inc/canon-megatank-reset --base main \
  --head feat/g6020-native-reset \
  --title "Native MegaTank 5B00 reset: paper, diagrams, publish contracts" \
  --body "Productionization bundle: IEEEtran paper (docs/paper), lifecycle/exploit diagrams (docs/diagrams), INTEROP + ETHICS, gitleaks allowlist, paper-build CI, LICENSE/CONTRIBUTING/manifest/docs-index, README/AGENTS status reconcile (TIN-cmr-04). See docs/PRODUCTIONIZATION.md §7."
```

---

**G2 — Create the Linear phase project + epic + issues (canon-phaseD)**
*Gate: needs OK (Linear mutations).* *Independent of code; do early so work is tracked.*

File under the **Active** initiative `faa7f1b9-6d0f-4201-9531-8f8a15cd241b` (NOT the stale
Completed duplicate `44799807-…`). Drafts are §2 (epic + TIN-cmr-01…10). MCP calls on
approval:

```text
# 1. New phase project
mcp__linear__save_project {
  name: "canon-phaseD: open publication — native reset paper + repo",
  team: "Tinyland",
  initiative: "faa7f1b9-6d0f-4201-9531-8f8a15cd241b",
  description: "<epic body from §2; reproduce Safety enforcement + Legal posture verbatim>",
  labels: ["foss","docs","release"]
}
# 2. One issue per §2 draft (TIN-cmr-01 … TIN-cmr-10). For each:
mcp__linear__save_issue {
  team: "Tinyland",
  project: "<canon-phaseD project id from step 1>",
  title: "<imperative title from §2>",
  description: "<## Why / ## Steps / ## The check / ## Status as of 2026-06-01 body>",
  labels: ["foss","docs", ...("security" if DRM-bypass content)]
}
# 3. Optional: archive the stale duplicate initiative 44799807-… (or leave; it has no projects)
```
Branch convention per issue: `jess/tin-####-<slug>` once real `TIN-####` are minted (the
`TIN-cmr-NN` ids in §2 are placeholders).

---

**G3 — Apply the home-manager secret-guard hook allowlist (lab repo)**
*Gate: needs OK (edit outside this repo + `home-manager switch`).* *Blocks: friction-free
cipher-doc commits.*

The patch is §5b: add `'docs/research/'` and `'docs/paper/'` to `ALLOWED_FILE_PATTERNS` at
`/Users/jess/git/lab/nix/modules/tools/global-git-hooks.nix:129`, then regenerate:

```bash
# operator applies the §5b patch in /Users/jess/git/lab, then:
home-manager switch
# verify the regenerated hook skips RE docs:
git -C /Users/jess/git/canon-megatank-reset commit --allow-empty -m "probe"  # should not trip check_high_entropy
```
The in-repo §5a `.gitleaks.toml` edit (Wave 0a) keeps **CI** green without this; G3 only
removes the **local** `--no-verify` friction. `lab` is read-only in this session, so the
patch is drafted, not applied.

---

**G4 — Enable the paper-build CI lane**
*Gate: needs OK (activates a workflow that auto-commits the PDF on main).* *Depends: G1.*

The effect is realized by Wave 0e (rename `.draft` → `build-paper.yml`) **plus** the push
in G1. The auto-commit step (`stefanzweifel/git-auto-commit-action@v5`) only fires on
`push` to `main`, so it activates when the G1 PR merges. No separate command beyond G1;
the gate is the decision to let CI recommit `canon-megatank-reset.pdf`. To dry-run without
auto-commit first:
```bash
gh workflow run build-paper.yml --repo tinyland-inc/canon-megatank-reset --ref feat/g6020-native-reset
gh run watch --repo tinyland-inc/canon-megatank-reset
```
Note: the draft pins `actions/checkout@v4`; align to `@v6` to match the house `ci.yml`
before enabling.

---

**G5 — Flip the repo public + tag the FOSS release**
*Gate: needs OK (visibility change is irreversible-ish + public exposure).* *Depends: G1,
G2, TIN-cmr-04 landed, G4 green, §5a applied, LICENSE present.* *Do NOT transfer orgs
(MEMORY: fix labels not ownership).*

Preconditions checklist (all must be true): README/AGENTS reconciled; LICENSE +
CONTRIBUTING + SECURITY + tinyland.repo.json present; secrets-scan green; no
Canon/WICReset/firmware binaries in history.

```bash
gh repo edit tinyland-inc/canon-megatank-reset --visibility public --accept-visibility-change-consequences
git tag -a v0.1.0 -m "Open native Canon MegaTank 5B00 reset — hardware-validated (d2f3c81)"
git push origin v0.1.0
gh release create v0.1.0 --repo tinyland-inc/canon-megatank-reset \
  --title "v0.1.0 — native MegaTank 5B00 reset" \
  --notes "First open, native-Linux, key-free, cloud-free Canon G-series waste-counter reset. See docs/runbook/g6020-native-reset.md and the paper (docs/paper)." \
  docs/paper/canon-megatank-reset.pdf
```

---

**G6 — Offer the pixma-lineage upstream contribution (PR + findings issue)**
*Gate: needs OK (external PR/issue to a third-party repo).* *Depends: G5.* *Per INTEROP.md
the PRIMARY recommendation is NOT to push reset/cipher into the unlicensed leecher fork —
G6 is the narrow, sanctioned shape only.*

Two sub-actions, each independently gated:
- **G6a (sooner, low-risk):** PR the reproducible `Makefile` + portability fix from
  `jesssullivan/pixma` (`tin-1698-pixma-build-tooling`) toward `leecher1337/pixma`:
  ```bash
  gh pr create --repo leecher1337/pixma --base master \
    --head jesssullivan:tin-1698-pixma-build-tooling \
    --title "Add reproducible Makefile + portability fixes" \
    --body "Build-tooling only; no functional change. Cross-referenced from tinyland-inc/canon-megatank-reset/INTEROP.md."
  ```
- **G6b (blocked):** the firmware-decrypt-for-G6000-generation extension — **gated on**
  (i) G6020 firmware being sourced (`docs/research/canon-tool-firmware-sourcing.md`) and
  (ii) leecher1337 adding a LICENSE. Open the LICENSE-request issue first; do NOT submit
  derivative code into an unlicensed repo. Draft text lives in INTEROP.md §5.

---

**G-aux — Notify-blog hook (OPTIONAL, default OFF)**
*Gate: needs OK + a `BLOG_DISPATCH_TOKEN` secret.* Only wire if the paper should notify
`jesssullivan.github.io`; mirror `hiberpower-ntfs/.github/workflows/notify-blog.yml`,
gated by `vars.BLOG_DISPATCH_ENABLED != 'false'`. Not recommended for v0.1.0.

### 7.3 Gate summary table

| Gate | Action | External system | Depends on | Reversible? |
|---|---|---|---|---|
| **G1** | Push branch + open PR | GitHub (canonical) | Wave 0 committed | yes (force-push/close) |
| **G2** | Create Linear phaseD + epic + 10 issues | Linear | none | yes (archive) |
| **G3** | Home-manager hook allowlist | lab repo + local system | none | yes (revert + switch) |
| **G4** | Enable `build-paper.yml` | GitHub Actions | G1 | yes (re-`.draft`) |
| **G5** | Public visibility + tag + release | GitHub | G1,G2,G4,TIN-cmr-04,§5a,LICENSE | visibility hard to undo |
| **G6a** | pixma build-tooling PR | leecher1337/pixma | G5 | yes (close PR) |
| **G6b** | pixma firmware-decrypt PR | leecher1337/pixma | firmware sourced + upstream LICENSE | yes (blocked anyway) |
| **G-aux** | notify-blog hook | GitHub + blog repo | opt-in + secret | yes |

### 7.4 Artifacts index (written by this productionization effort)

All paths absolute under `/Users/jess/git/canon-megatank-reset/`. **Committed: none yet**
(all Wave-0-pending).

| Artifact | Status |
|---|---|
| `docs/paper/canon-megatank-reset.tex` | IEEEtran paper; builds clean (0 errors) |
| `docs/paper/canon-megatank-reset.pdf` | built artifact, 115 KiB |
| `docs/paper/references.bib` | 32 BibTeX entries (8 TODO-tagged for primary-source confirmation) |
| `docs/paper/{IEEEtran.cls,IEEEtran.bst,bytefield.sty,cleveref.sty,balance.sty}` | vendored for hermetic build |
| `docs/paper/README.md` | build instructions + huskycat allowlist note |
| `docs/diagrams/lifecycle.mmd` | Mermaid: RE→native-reset lifecycle |
| `docs/diagrams/maintenance-state-machine.mmd` | Mermaid: service-mode protocol state machine |
| `docs/diagrams/methodology-trifecta.mmd` | Mermaid: usbmon⟷Frida⟷Ghidra correlation loop |
| `docs/diagrams/exploit-dataflow.dot` | Graphviz: APP.BIN→envelope→cipher→VENDOR_SET→EEPROM |
| `docs/diagrams/drm-bypass-controlflow.dot` | Graphviz: 3 cloud gates JZ→JMP → net-free emit |
| `docs/diagrams/README.md` | render table + `just diagrams` usage |
| `Justfile` (modified) | added `diagrams` recipe (Documentation section) |
| `INTEROP.md` (rewritten, 26→317 lines) | pixma lineage, ranked upstream plan, draft PR/issue texts, citations |
| `ETHICS/RIGHT-TO-REPAIR.md` (new) | authorized-repair / no-DoS / dual-use posture |
| `.github/workflows/build-paper.yml.draft` | tectonic CI mirror (NOT enabled; rename to activate) |
| `.gitignore` (modified) | LaTeX build-intermediates + diagram-render ignore stanzas |
| `docs/PRODUCTIONIZATION.md` (this file) | the roadmap + this master plan (§7) |
| **To be added in Wave 0c/0d:** `LICENSE`, `CONTRIBUTING.md`, `tinyland.repo.json`, `docs/README.md`, README/AGENTS reconcile | MISSING — §3/§6b give exact contents |

Source-of-truth (already in repo, referenced not rewritten): `docs/runbook/g6020-native-reset.md`,
`docs/research/{usbprint-vendor-urb-mapping,g6020-genuine-setcommand-decode,g6020-wire-codec-crack,wicreset-drm-bypass,g6020-reset-completion}.md`,
`printers/canon-g6020/maintenance.yaml`, the validated commit `d2f3c81`.

### 7.5 Single recommended next step

**Do Wave 0a + 0b + 0d now (all in-repo, ungated): apply the `.gitleaks.toml` allowlist
(§5a), commit the already-written paper/diagrams/INTEROP/ETHICS/Justfile artifacts, and
reconcile the README/AGENTS "early — do not point at a printer" banners to
hardware-validated (TIN-cmr-04).** This closes the P0 doc-truth gap, makes the working
tree clean and self-consistent, and unblocks the first gated step (G1 push) — without
touching any external system. Everything in §7.2 stays parked behind its gate until you
greenlight it.
