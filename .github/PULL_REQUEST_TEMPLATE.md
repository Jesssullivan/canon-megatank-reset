## Summary

<!-- One paragraph: what this PR changes and why. -->

## Linear

<!-- Linear ticket(s). Format: TIN-XXXX -->

## Traceability (required for any protocol claim)

<!-- If this PR asserts or changes a protocol fact (transport, frame layout,
     cipher step, dispatch value, reset operand), complete the chain. See
     CONTRIBUTING.md → Traceability. If no protocol claim changes, say "n/a". -->

- Evidence: `docs/research/…`
- Code: `src/canon_megatank/…`
- Test: `tests/…`
- SSOT impact (`printers/canon-g6020/maintenance.yaml`): n/a / describe

## Validation

- [ ] `just check` is green (ruff + mypy strict + yaml-lint + ansible-lint)
- [ ] `just test` is green (fingerprint, pcap, protocol-model property tests)
- [ ] `just model` is green if the protocol model changed
- [ ] No new gitleaks findings (`just secrets-scan-dir` / `just secrets-scan`);
      the `.gitleaks.toml` allowlist was NOT widened with a blanket hex regex
- [ ] No purchased key, capture credential, or secret added

## Safety posture (this tool writes to a printer EEPROM)

<!-- Does this touch the EEPROM-write path or any gate? -->

- [ ] No safety gate touched, OR the change is described below and the gate
      ladder is preserved/strengthened (UUID isolation → status gate →
      mandatory EEPROM dump → write budget → lockfile → live-keyword guard)
- [ ] Reset stays dry-run by default; `--execute` still gated and, on a
      `derived-unvalidated` SSOT, still requires `--accept-derived`

<!-- If a gate changed, explain why and how it stays safe: -->

## Risk & rollback

<!-- What could break? What's the rollback path? For a live-hardware change,
     note that recovery is a clean power-button shutdown, never an unplug. -->

## Output / evidence

<!-- Relevant `just` output, dry-run wire frames, or a runbook link. -->
