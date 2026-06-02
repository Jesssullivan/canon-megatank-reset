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
# Pin the venv interpreter to the flake-provided python (pyproject requires >=3.12)
# so `just setup`/`just test` are reproducible regardless of what floats to
# `python3` on PATH. Override with CMR_PYTHON if needed.
py := env_var_or_default("CMR_PYTHON", "3.12")

_default:
    @just --list --unsorted

# ─────────────────────────────────────────────
# Development
# ─────────────────────────────────────────────

# `--clear` makes re-running idempotent (uv errors if .venv already exists).
# Create the local venv + install the package (editable, with dev extras).
setup:
    cd {{ root }} && uv venv --clear --python {{ py }} .venv && uv pip install -e ".[dev]"
    @echo "Setup complete. Run 'just check && just test'."

# ─────────────────────────────────────────────
# Documentation build (paper + diagrams; sources are SSOT, artifacts are built)
# ─────────────────────────────────────────────

# tectonic (one-shot, vendored .cls/.bst/.sty — no TeX Live install needed).
# Mirrors .github/workflows/build-paper.yml.draft. tectonic comes from the flake.
# Build the IEEE paper PDF: docs/paper/canon-megatank-reset.tex → .pdf.
paper:
    cd {{ root }}/docs/paper && tectonic canon-megatank-reset.tex

# Mermaid (.mmd) via mmdc; Graphviz (.dot) via `dot`. Both come from the flake
# devShell (mermaid-cli + graphviz). See docs/diagrams/README.md.
# Render every diagram source in docs/diagrams to SVG (pass `png` to also emit PNG).
diagrams fmt="svg":
    cd {{ root }}/docs/diagrams && \
      mmdc_cmd="$(command -v mmdc || echo 'npx --yes @mermaid-js/mermaid-cli')"; \
      pp="$(mktemp)"; trap 'rm -f "$pp"' EXIT; \
      printf '{"args":["--no-sandbox","--disable-gpu"]}' > "$pp"; \
      for f in *.mmd; do \
        [ -e "$f" ] || continue; \
        echo "mermaid → ${f%.mmd}.svg"; $mmdc_cmd -p "$pp" -i "$f" -o "${f%.mmd}.svg"; \
        if [ "{{ fmt }}" = "png" ]; then echo "mermaid → ${f%.mmd}.png"; $mmdc_cmd -p "$pp" -i "$f" -o "${f%.mmd}.png"; fi; \
      done; \
      for f in *.dot; do \
        [ -e "$f" ] || continue; \
        echo "graphviz → ${f%.dot}.svg"; dot -Tsvg "$f" -o "${f%.dot}.svg"; \
        if [ "{{ fmt }}" = "png" ]; then echo "graphviz → ${f%.dot}.png"; dot -Tpng "$f" -o "${f%.dot}.png"; fi; \
      done

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

# `--clear` keeps re-runs idempotent (uv refuses to reuse an existing .venv).
# Full test suite in an isolated editable venv.
test:
    cd {{ root }} && uv venv --clear --python {{ py }} .venv && uv pip install -e ".[dev]"
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

# Annotated control-transfer + bulk extraction from a usbmon pcap (Lane C
# post-capture pipeline). Pulls EVERY EP0 control transfer to/from the
# service-mode device (bmRequestType/bRequest/wValue/wIndex/data + responses),
# flags the absorber-reset frame, and emits an ordered annotated sequence.
# Pass extra args after the pcap, e.g. `--device-address 42`, `--replay-snippet`,
# `--json`. Requires tshark (lives on the capture host mbp-13).
# Usage: just parse-capture captures/<file>.pcapng [--device-address N]
parse-capture pcap *args:
    cd {{ root }} && python3 scripts/parse-wicreset-capture.py {{ pcap }} {{ args }}

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

# Win11 capture VM lifecycle (Lane B) — capture the real reset handshake from
# the wire. Session-mode libvirt, no root. See host/vm-capture/README.md.
# Subcommands: setup | install | snapshot | capture | start | stop | status | detach
vm-capture *args:
    cd {{ root }} && scripts/vm-capture.sh {{ args }}

# HEADLESS capture VM (Lane B) — fully unattended Win11 (autounattend) + Ansible/
# WinRM provisioning + PowerShell UIAutomation reset. See host/vm-capture/README.md.
# Subcommands: build-iso | define | install | wait-winrm | provision | capture | all
vm-capture-headless *args:
    cd {{ root }} && scripts/vm-capture-headless.sh {{ args }}

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
# Fleet deploy (Ansible — roll the VALIDATED native reset tool to the fleet)
# canon_tool_reset role: install + scaffold ONLY. Installs the tool + a GATED,
# DRY-RUN-by-default, manual-trigger systemd unit (canon-reset@.service). It
# NEVER triggers a reset — the commit is a manual clean power-button press.
# ─────────────────────────────────────────────

# Syntax-check the fleet-deploy playbook (no host contact).
fleet-deploy-syntax:
    cd {{ root }}/host && ansible-playbook --syntax-check playbooks/canon-fleet-reset.yml

# Dry-run the fleet deploy (--check --diff: shows changes, applies nothing).
fleet-deploy-check *flags='':
    @just fleet-deploy '--check --diff' {{ flags }}

# Apply the canon_tool_reset role to the reset_fleet group (install + scaffold:
# isolated venv, udev rule, state dirs, the DRY-RUN systemd unit). Become pw
# from $BECOME_PASSWORD_FILE (sops) or --ask-become-pass. NEVER triggers a
# reset. Usage: just fleet-deploy ['--limit mbp-13' | '--tags systemd']
fleet-deploy *flags='':
    @cd {{ root }}/host && \
      if [ -n "${BECOME_PASSWORD_FILE:-}" ] && [ -r "${BECOME_PASSWORD_FILE:-/nope}" ]; then \
        ANSIBLE_BECOME_PASS="$(cat "$BECOME_PASSWORD_FILE")" \
          ansible-playbook -i inventory/hosts.yml playbooks/canon-fleet-reset.yml -l reset_fleet {{ flags }}; \
      else \
        ansible-playbook --ask-become-pass -i inventory/hosts.yml playbooks/canon-fleet-reset.yml -l reset_fleet {{ flags }}; \
      fi

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

# Replay the captured EP0 control-transfer reset (WICReset service-mode path).
# DRY-RUN by default (resolves the SSOT control_sequence, prints the transfers,
# no USB). `just replay-control --execute` drives them behind every safety gate;
# while the SSOT status is derived-unvalidated (the sequence is a placeholder)
# it hard-stops. See docs/runbook/wicreset-capture-analysis-pipeline.md.
replay-control *flags='':
    cd {{ root }} && uv run --no-project python -m canon_megatank replay-control {{ flags }}

# The VALIDATED native libusb 5B00 clear (the path that cleared hardware
# 2026-06-01). DRY-RUN by default (enciphers + prints the 23-byte frames, no
# USB). `just reset-native --execute` drives the real sequence behind every
# safety gate; while the SSOT status is derived-unvalidated it hard-stops unless
# `--accept-derived` is also passed. After a clear: release the USB handle, then
# a CLEAN POWER-BUTTON shutdown to commit (unplug does NOT commit).
reset-native *flags='':
    cd {{ root }} && uv run --no-project python -m canon_megatank reset-native {{ flags }}

# Pre-flight EEPROM dump (mandatory before any write).
eeprom-dump:
    @echo "EEPROM-read (cmd,arg) is PENDING — dump_eeprom refuses to guess (see src/canon_megatank/eeprom.py)"

# Fleet status across known units.
fleet-status:
    @echo "TODO(T5): per-unit fingerprint + counter + write-budget report"
