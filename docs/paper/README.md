# Paper — Canon MegaTank 5B00 native reset

IEEE conference-style writeup of the open, native-Linux, key-free, cloud-free
reproduction of the Canon MegaTank (G6000-series) 5B00 waste-ink reset.

## Contents

| File | Purpose |
|---|---|
| `canon-megatank-reset.tex` | The paper (single-file IEEEtran conference paper). |
| `references.bib` | BibTeX bibliography (IEEEtran style). |
| `IEEEtran.cls`, `IEEEtran.bst` | Vendored IEEE class + bib style (no system TeX needed). |
| `bytefield.sty` | Wire-frame byte diagrams. |
| `cleveref.sty` | `\Cref`/`\cref` cross-references (loaded **after** hyperref). |
| `balance.sty` | Last-page two-column balancing. |

The `.cls`/`.bst`/`.sty` files are vendored (mirroring `hiberpower-ntfs/docs/paper`)
so `tectonic` needs no extra TeX-live install in CI or locally.

## Build

### Simple (recommended) — plain Tectonic

```sh
cd docs/paper
tectonic canon-megatank-reset.tex
# -> canon-megatank-reset.pdf
```

This is exactly what the CI draft runs.

### CI

`../../.github/workflows/build-paper.yml.draft` mirrors the hiberpower
`build-paper.yml` (paths-filter on `docs/paper/**`, `wtfjoke/setup-tectonic@v3`,
build, upload artifact, auto-commit the PDF on push to `main`). It is intentionally
left as `.draft` — **CI is not enabled**. Rename to `build-paper.yml` to activate.

### Hermetic (optional) — rules_tectonic + Bazel

The repo has no Bazel root yet, so the plain-tectonic path above is the
lower-friction default. For a fully hermetic, cache-backed build, bootstrap Bazel:

`MODULE.bazel` (repo root):

```python
bazel_dep(name = "rules_tectonic", version = "0.1.0")
git_override(
    name = "rules_tectonic",
    remote = "https://github.com/Jesssullivan/rules_tectonic.git",
    commit = "89076e07a0f62eb68b2756c0014cd0dcbc04ff8d",
)
```

`docs/paper/BUILD.bazel`:

```python
load("@rules_tectonic//tectonic:defs.bzl", "tectonic_pdf")

tectonic_pdf(
    name = "canon-megatank-reset",
    src = "canon-megatank-reset.tex",
    data = [
        "references.bib",
        "IEEEtran.cls",
        "IEEEtran.bst",
        "bytefield.sty",
        "cleveref.sty",
        "balance.sty",
    ],
)
# -> bazel-bin/docs/paper/canon-megatank-reset.pdf
```

Both the `MODULE.bazel` root and `BUILD.bazel` are drafts above — they are **not**
committed, since the repo's current CI (`ci.yml`) is Nix/`just`-based and does not
yet have a Bazel cache wrapper.

## Pre-commit note (huskycat / high-entropy false positive)

The `.tex` listings contain 40+ character cipher hex (e.g. the 23-byte validated
frames). The global `pre-commit` hook's `check_high_entropy` will false-positive on
these. The durable fix (per project memory) is to extend the hook's
`ALLOWED_FILE_PATTERNS` allowlist to cover documentation paths rather than weaken the
entropy check:

```sh
# in ~/.config/git/hooks/pre-commit, add to ALLOWED_FILE_PATTERNS:
  'docs/paper/'
  'docs/research/'
```

This mirrors the existing `docs/research` cipher-hex situation; the allowlist is a
file-path allowlist (the entropy check is still active for all non-doc files).

## Status

The paper is a **skeleton with grounded prose stubs**: every section is present with
real, citation-backed content drawn from the validated in-repo RE notes
(`docs/research/`, `docs/runbook/g6020-native-reset.md`). References tagged
`TODO:` in `references.bib` need a primary-source bibliographic confirmation before
submission. Figures (bytefield wire frames, the session state machine, the DRM gate
sequence) and tables are populated from the recovered evidence.
