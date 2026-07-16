# scripts/ — agent contract

Read the repo-root `AGENTS.md` first.

Scripts here are **operator-driven tooling**, not service code. They
run by hand (or via Justfile recipes), not under systemd. Different
rules apply.

## Critical rules

1. **Scripts MAY break safety gates** that the service-side code
   (in `src/canon_megatank/`) enforces. Scripts are run by humans
   who know what they're doing during the capture / RE phases.
   Example: `safe-ping-probe.py` stops `ipp-usb` directly without
   going through the lockfile — that's intentional for setup but
   would never be acceptable in the service.

2. **NEVER call vendor-specific bulk-OUT commands from scripts** until
   the protocol bytes are pinned in `maintenance.yaml::supported`.
   Scripts may freely call documented-safe ops (USB descriptors,
   IEEE-1284 device-id) but bulk-OUT to interface 4 endpoint 0x03 is
   gated behind the fingerprint + EEPROM-dump + write-budget check
   in `ops.py`.

3. **Scripts that mutate host state MUST restore it on exit**, even on
   error. `r1-capture.sh` always restarts `ipp-usb` in its trap handler
   even if tshark crashes mid-capture, so CUPS comes back online.

4. **Document the YAML schema in the script output.** Scripts that emit
   yaml (like `safe-ping-probe.py`) should emit operator-readable
   inline comments explaining what each field means. The yaml is meant
   to be commitable as evidence and grep-able by future operators.

5. **Reuse the recovered encoder — never reinvent the cipher.** The
   functor-2/3 transform, keyword bind, and template tables live in
   `src/canon_megatank/protocol/wicreset.py` (loaded from the SSOT via
   `load_method_from_ssot`). Analysis/RE scripts MUST import those
   primitives, not reimplement the keystream loop. **One sanctioned
   exception:** `scripts/canon_sr5_cipher.py` is a *deliberate independent*
   re-implementation (sourced from the decrypted `devices.xml`, not the SSOT)
   whose only job is to cross-check the SSOT encoder byte-exact (23/23) in the
   groundtruth tests — its parallel cipher is load-bearing, not drift; keep it
   independent. Nothing — runtime or analysis — depends on `printerpotty.exe`
   or `/tmp/.../devices.xml` at run time; `devices.xml` is provenance only. The read codecs are both
   solved: `0x84` is a keyword-XOR stream over a constant descriptor;
   `0x8c` is the *write* keystream over a zero plaintext (a keyed echo,
   not the counter) — see `docs/research/canon-service-mode-field-guide.md`.
   Reading the live waste counter needs the `query.normal` select path
   (`[10 07 7C][15]`), not a bare register read.

## Inventory

The full, current script inventory (purpose + privilege + cross-references) lives in
[`../docs/TOOLS.md`](../docs/TOOLS.md) — the single source of truth. Keep it there;
don't maintain a second table here, which only drifts.

## Adding a new script

1. **Naming**: `<phase>-<purpose>.{sh,py}` — e.g. `r2-capture.sh` for
   the QEMU-path equivalent.
2. **Header comment**: one paragraph stating what it does, what it
   requires, and how it interacts with host state.
3. **Set `-euo pipefail` for bash, `from __future__ import annotations`
   for Python.**
4. **Idempotency where reasonable**: if the script can be re-run safely,
   it should be — even if that means a no-op fast path.
5. **Justfile recipe**: every operator-facing script gets a recipe in
   the root Justfile under the canon-tool section.
6. **Add an entry to the inventory in [`../docs/TOOLS.md`](../docs/TOOLS.md).**

## Things scripts NEVER do

- Write to `printers/canon-g6020/maintenance.yaml` programmatically.
  That file is the SSOT; operators edit it by hand after reviewing
  capture/probe output. Scripts emit yaml *fragments* for the human
  to merge in.
- Run during normal printstack operation. These are dev / capture
  tools, not runtime helpers.
- Bypass the udev rule + group membership setup by elevating to root
  permanently. Sudo is for short, well-scoped operations only.
