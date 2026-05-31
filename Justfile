# canon-megatank-reset — Linux fleet Canon MegaTank waste-ink reset + protocol RE
# Justfile is the SINGLE SOURCE OF TRUTH for every operation. Always `just <recipe>`.
# Prerequisites: just, direnv (loads the Nix devShell), Nix with flakes.
# Quick start: direnv allow && just check && just test
#
# See AGENTS.md for the operating contract.

set dotenv-load := true
set shell := ["bash", "-euo", "pipefail", "-c"]

root := justfile_directory()
capture_host := env_var_or_default("CMR_CAPTURE_HOST", "mbp-13")

_default:
    @just --list --unsorted

# ─────────────────────────────────────────────
# Development
# ─────────────────────────────────────────────

# Create the local venv + install the package (editable, with dev extras).
setup:
    cd {{ root }} && uv venv .venv && uv pip install -e ".[dev]"
    @echo "Setup complete. Run 'just check && just test'."

# ─────────────────────────────────────────────
# Validation (static gates — run by CI)
# ─────────────────────────────────────────────

# All static gates.
check: lint typecheck yaml-lint ansible-lint

# Python tools run via `uv run --extra dev` so they execute in the project env
# with deps present (mypy needs structlog/pyusb importable to resolve types).
lint:
    cd {{ root }} && uv run --extra dev ruff check src tests

typecheck:
    cd {{ root }} && uv run --extra dev mypy src

format:
    cd {{ root }} && ruff format src tests

format-check:
    cd {{ root }} && ruff format --check src tests

yaml-lint:
    cd {{ root }} && yamllint printers host

ansible-lint:
    cd {{ root }}/host && ansible-lint playbooks/canon-tool-dev.yml || true

# Gitleaks scan of working tree / history.
secrets-scan-dir:
    cd {{ root }} && gitleaks dir --config .gitleaks.toml --redact --verbose .

secrets-scan:
    cd {{ root }} && gitleaks git --config .gitleaks.toml --redact --verbose .

# ─────────────────────────────────────────────
# Test
# ─────────────────────────────────────────────

test:
    cd {{ root }} && uv venv .venv && uv pip install -e ".[dev]"
    cd {{ root }} && .venv/bin/pytest tests/ -v

# Property-test only the formal protocol model (T3) — fast, offline, no hardware.
model:
    cd {{ root }} && uv run --extra dev pytest tests/test_protocol_model.py -q

# ─────────────────────────────────────────────
# Protocol RE + capture (oracles; host-side on the capture host)
# ─────────────────────────────────────────────

# Summarize a captured USB pcap — extract bulk-OUT/IN sequences + Canon headers.
# Usage: just analyze captures/<file>.pcapng.gz
analyze pcap:
    cd {{ root }} && uv run --no-project python -m canon_megatank.pcap {{ pcap }}

# Capture a FREE WICReset "Read waste counters" on the capture host (no key).
# Drives the headless harness; pcap lands on the capture host's staging dir.
# Usage: just capture-read [label]
capture-read label="wicreset-read":
    ssh {{ capture_host }} 'bash -lc "cd ~/git/canon-megatank-reset 2>/dev/null || cd ~/git/printstack-canon; scripts/wicreset-capture.sh {{ label }}"'

# Pull capture-host pcaps into ./captures for analysis.
capture-sync:
    rsync -av {{ capture_host }}:~/canon-tool-staging/captures/ {{ root }}/captures/incoming/

# Intercept the G6020 panel-initiated firmware download (Lane C / approach A).
# Operator drives the printer panel; this captures the plain-HTTP blob URL.
# See docs/runbook/firmware-panel-intercept.md. Override INTERCEPT_IFACE/PRINTER_IP.
firmware-intercept label="firmware-intercept":
    cd {{ root }} && scripts/firmware-intercept.sh {{ label }}

# Ghidra headless static RE of an oracle binary (Canon Service Tool / WICReset).
# Binary + project DB stay gitignored under .ghidra-work/. Usage: just ghidra <script.py> <args...>
ghidra script *args:
    @echo "Run via .ghidra-work harness — see ghidra/README.md. script={{ script }} args={{ args }}"

# ─────────────────────────────────────────────
# Host (Ansible — capture/RE env on the capture host; future fleet deploy)
# ─────────────────────────────────────────────

host-check:
    cd {{ root }}/host && ansible-playbook --syntax-check playbooks/canon-tool-dev.yml

# Apply the canon_tool_dev role to the capture host (wine + usbmon + groups +
# scoped sudoers + GUI-automation tooling). Become pw from $BECOME_PASSWORD_FILE.
# Usage: just host-apply ['--tags sudo,groups' | '--check --diff']
host-apply *flags='':
    @cd {{ root }}/host && \
      if [ -n "${BECOME_PASSWORD_FILE:-}" ] && [ -r "${BECOME_PASSWORD_FILE:-/nope}" ]; then \
        ANSIBLE_BECOME_PASS="$(cat "$BECOME_PASSWORD_FILE")" \
          ansible-playbook -i inventory/hosts.yml playbooks/canon-tool-dev.yml -l {{ capture_host }} {{ flags }}; \
      else \
        ansible-playbook --ask-become-pass -i inventory/hosts.yml playbooks/canon-tool-dev.yml -l {{ capture_host }} {{ flags }}; \
      fi

host-dry:
    @just host-apply '--check --diff'

# ─────────────────────────────────────────────
# Native reset tool (T5 — implemented once the protocol model is validated)
# ─────────────────────────────────────────────

# Read the waste-ink counter over pyusb (read-only; safe).
read *flags='':
    cd {{ root }} && uv run --no-project python -m canon_megatank read {{ flags }}

# Reset the 5B00 absorber counter. DRY-RUN by default (prints the derived frame,
# no USB write). `just reset --execute` attempts the real write behind every
# safety gate; while the SSOT status is derived-unvalidated it hard-stops.
reset *flags='':
    cd {{ root }} && uv run --no-project python -m canon_megatank reset {{ flags }}

# Pre-flight EEPROM dump (mandatory before any write).
eeprom-dump:
    @echo "EEPROM-read (cmd,arg) is PENDING — dump_eeprom refuses to guess (see src/canon_megatank/eeprom.py)"

# Fleet status across known units.
fleet-status:
    @echo "TODO(T5): per-unit fingerprint + counter + write-budget report"
