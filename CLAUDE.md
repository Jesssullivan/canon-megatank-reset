# Claude — canon-megatank-reset

Read `@AGENTS.md` first for the authoritative operating contract.

Quick reminders:

- `just <recipe>` is the **sole entrypoint** for every operation. Do not call
  `pytest` / `ansible-playbook` / `ghidra` / `tshark` directly outside the Justfile.
- `nix develop` (via `direnv`) provides the toolchain — never assume host tools.
- **Safety**: nothing writes to a printer until the protocol model is validated
  against a real captured reset (T4). The single WICReset key is operator-held,
  **never** committed, spent only in T4 after the physical waste-ink kit is fitted.
- **No binary redistribution**: Canon Service Tool / WICReset / firmware blobs +
  the Ghidra project DB are gitignored. Only our scripts + curated findings are tracked.
- Capture host is `mbp-13`; reset target is the locked `test_unit` only.
