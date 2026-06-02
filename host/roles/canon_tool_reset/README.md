# role: canon_tool_reset

Fleet deploy of the **validated native libusb 5B00 absorber-reset** tool
(`canon-megatank reset-native`) plus a **gated, manual-trigger** systemd
template unit.

The native clear was validated on real hardware on **2026-06-01**: a fully
native libusb session cleared `5B00` and the printer rebooted to normal mode
`04a9:1865` — no WICReset, no VM, no cloud, no purchased key. This role rolls
that tool to the fleet.

## Contract: install + scaffold ONLY

This role **never drives a reset**. It:

- installs the in-repo Python package into an isolated, root-owned venv under
  `/opt/canon-megatank-reset`,
- provisions the runtime state dirs the tool expects
  (`/var/lib/canon-tool` write budget, `/run/canon-tool` lockfile — see
  `src/canon_megatank/lockfile.py`),
- installs a udev rule granting the `printstack` group USB access to the G6020
  in both `04a9:1865` (print) and `04a9:12fe` (service) enumerations,
- installs the `canon-reset@.service` **template** unit (one instance per
  physical printer).

Triggering a reset is a **deliberate, manual** `systemctl start
canon-reset@<serial>` performed by an operator **standing at the printer**,
because the commit is a **physical clean power-button shutdown** (below).

## Safety gates (unchanged, authoritative)

The unit is **DRY-RUN by default** — it enciphers + prints the validated frames
and touches no USB. `--execute` is only templated into the unit when the
operator deploys with **both** opt-ins:

```yaml
canon_tool_reset_allow_execute_unit: true
canon_tool_reset_commit_acknowledged: true   # operator will power-cycle by hand
```

Even then, the in-code gates in `ops.reset_absorber_wicreset` still decide and
will hard-stop unless each passes:

1. **UUID isolation** — runtime fingerprint must match the locked `test_unit`.
2. **SSOT validation status** — `absorber_reset.status` must be
   `verified-captured`. It is currently `derived-unvalidated` by repo
   convention (per-physical-unit, pads-installed promotion is a manual
   decision), so `--execute` requires `--accept-derived`
   (`canon_tool_reset_accept_derived: true`), recorded loudly as a one-run
   override that does **not** mutate the SSOT.
3. **Mandatory EEPROM dump** — `eeprom_dump_done` must be true.
   `--accept-derived` does **not** bypass this.
4. **Per-unit write budget** — capped (default 50) and persisted under
   `/var/lib/canon-tool`; refuses when exhausted.
5. **Lockfile** — `/run/canon-tool` in-flight guard prevents a mid-write
   restart.
6. **Live-keyword guard** — a too-short `get_keyword` reply hard-stops before
   any write.

The role also adds a **deploy-time refuse gate**: it will not template
`--execute` into the unit unless `canon_tool_reset_commit_acknowledged` is true.

## The MANDATORY per-unit commit step (operator)

No automation can perform this. After a successful `--execute` clear:

1. The unit exits, which **releases the USB handle**.
2. The operator performs a **CLEAN POWER-BUTTON SHUTDOWN** of the printer so the
   printhead parks and the cleared counter is **flushed to EEPROM**.
3. An abrupt **UNPLUG does NOT commit** the reset — the counter will revert.

This step is surfaced in the unit's `ExecStartPost` journal line and in the
tool's own `reset_native.ok` log (`commit_step`), so the operator always sees it.

## Per-unit instancing

`canon-reset@.service` is a **template**. `%i` is a per-printer label (a
back-panel serial, or the inventory host) so each physical unit gets its own
write-budget file, lockfile, and journal stream:

```sh
# Preview (dry-run, no USB):
sudo systemctl start canon-reset@SERIAL123
journalctl -u canon-reset@SERIAL123 -n 40
```

Set the default label per host with `canon_tool_reset_unit_instance`.

## Invocation

```sh
# From the repo root, via the Justfile (preferred):
just fleet-deploy-check     # syntax-check + --check --diff (no changes)
just fleet-deploy           # apply install + scaffold (dry-run unit)

# Direct:
cd host
ansible-playbook -i inventory/hosts.yml playbooks/canon-fleet-reset.yml -l reset_fleet
```

The role is idempotent and safe to re-run. A source re-sync triggers a venv
re-install so the unit always runs the synced code.

## What it does NOT do

- Does not trigger a reset (manual `systemctl start` only;
  `canon_tool_reset_trigger_now` exists but defaults to false and is
  `never`-tagged).
- Does not promote the SSOT status to `verified-captured` (manual, per-unit).
- Does not install the capture / RE environment (that is `canon_tool_dev`).
- Does not spend the purchased WICReset key — the native path needs no key.
