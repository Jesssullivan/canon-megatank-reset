# Runbook — canon-tool R1 cheap-spike

The "cheap spike" attempts to clear the G6020's 5B00 (ink absorber full)
counter using **Canon Service Tool v5103** running under Wine on `mbp-13`,
with the **G6020 selected in the tool's G3010-series mode**. The
hypothesis: Canon's G-series MegaTank chipset shares maintenance opcodes
across model years; v5103 (which covers G3010) may emit the same byte
sequence that newer Service Tool versions emit for G6020. If true, this
clears 5B00 with the tooling we already have. Worst case: nothing changes
and we still gain a complete USB trace for Ghidra cross-reference.

**Required:** physical presence at `mbp-13` (or X11/VNC forwarding) — the
Service Tool is a Windows MFC GUI app and requires clicks. The capture
itself is headless and runs from any shell.

## Pre-flight

```sh
# Verify the G6020 is connected + in 5B00
ssh mbp-13 'lsusb -d 04a9:1865; /usr/bin/ipptool -tv ipp://localhost:60001/ipp/print get-printer-attributes.test | grep -E "printer-state|printer-firmware|printer-alert"'

# Expected: G6020 detected, printer-state=stopped, marker-waste-full-error in alerts
```

If the printer-firmware-version is **not** `1.070`, **STOP** — the protocol
fingerprint in `printers/canon-g6020/maintenance.yaml` was captured against
fw 1.070. A drift means an undocumented firmware update happened and the
captured byte sequence may no longer be valid.

```sh
# Verify capture environment ready
ssh mbp-13 'which wine && wine --version && ls /dev/usbmon* && groups jess | grep -E "wireshark|printstack"'

# Expected: /usr/local/bin/wine, wine-11.0, usbmon0/1/2, groups include both
```

## R1 capture sequence

### Step 1 — Start tshark capture in the background

```sh
# From your workstation (neo), kick off capture on mbp-13:
just canon-capture-start label=v5103-g3010-mode-attempt-1

# OR directly:
ssh mbp-13 'sudo modprobe usbmon; sudo tshark -i usbmon1 -w ~/canon-tool-staging/captures/v5103-g3010-mode-$(date -u +%Y%m%d-%H%M%S).pcapng -F pcapng'
```

Bus 001 is where the G6020 lives — capture on `usbmon1`. Leave the tshark
process running in the foreground (or in a tmux pane). Press Ctrl-C at
the end to stop.

### Step 2 — Launch Service Tool v5103 under Wine

From a separate session on `mbp-13` (e.g. another ssh -X or a local
terminal at the box itself):

```sh
ssh -X mbp-13   # or run locally
cd ~/canon-tool-staging/extracted/ServiceTool_v5103
wine ServiceTool_v5103.exe
```

The Service Tool GUI will open in your local display (X11 forwarded if
remote). If Wine prefix initialization is needed, it happens automatically
on first launch (~30s).

### Step 3 — Click the absorber-reset path (G3010 mode)

In the Service Tool GUI:

1. **Model selector** — open the dropdown. **Select "G3010 series"**
   (NOT G3000; we want the closest in-family match by chipset generation).
2. **Function selector / Maintenance tab** — find the section labeled
   "Ink Absorber Counter" or "Counter Clear" or similar.
3. **Click "Set" / "OK" / "Execute"** to issue the absorber-counter-clear
   command. The tool will send the USB sequence to the connected printer.
4. Watch for any response messages in the Service Tool window.

If a model-selection error pops up ("Unsupported printer", "USB device not
found", etc.), make a note — that's still useful evidence. The pcap will
contain the full attempted handshake even on rejection.

### Step 4 — Stop capture + verify

Back in the tshark session, **Ctrl-C** to stop. The pcapng lands at:

```
~/canon-tool-staging/captures/v5103-g3010-mode-YYYYMMDD-HHMMSS.pcapng
```

Verify it's non-empty:

```sh
ssh mbp-13 'ls -la ~/canon-tool-staging/captures/'
ssh mbp-13 'capinfos ~/canon-tool-staging/captures/v5103-g3010-mode-*.pcapng | head -10'
```

### Step 5 — Check whether 5B00 cleared

```sh
ssh mbp-13 '/usr/bin/ipptool -tv ipp://localhost:60001/ipp/print get-printer-attributes.test | grep -iE "printer-state|alert"'
```

- If `printer-state = idle` and no `marker-waste-full-error` in alerts → **🎉 5B00 cleared**. The hypothesis was right. Lock the byte sequence in the captured pcap as the v5103-G3010-shared family opcode.
- If still `stopped` with the same alert → hypothesis didn't hold, but we have a clean USB trace for Ghidra to interpret.
- Cycle the printer power (off → on) and re-check; sometimes the state cache is sticky.

### Step 6 — Triage the capture

```sh
# Quick first look at packet count + protocols
ssh mbp-13 'tshark -r ~/canon-tool-staging/captures/v5103-g3010-mode-*.pcapng -q -z io,stat,0'

# Pull just the bulk-OUT packets (host -> printer) for control commands
ssh mbp-13 'tshark -r ~/canon-tool-staging/captures/v5103-g3010-mode-*.pcapng \
  -Y "usb.transfer_type == 0x03 and usb.endpoint_address.direction == 0" -V' | head -100
```

Look for:
- Sequence of short bulk-OUT transfers immediately after model-select click
- Any responses on bulk-IN
- The "Counter Clear" command bytes (typically small, structured)

## What to capture in `printers/canon-g6020/maintenance.yaml` afterwards

Whatever the outcome, fill in:

- `protocol_fingerprint.last_verified_firmware`: `'1.070'` (current — confirms no drift during capture)
- `protocol_fingerprint.last_verified_at`: ISO8601 timestamp of the capture
- Under `supported.absorber_reset` (new entry):
  - `byte_sequence`: extracted from pcap if successful
  - `captured_at`: timestamp + `source: 'wine-v5103-g3010-mode'`
  - `risk`: `write-eeprom`
  - `requires`: `[ping]`

If we have a working byte sequence, write a tiny Python harness in
`services/canon-tool/` that replays it via pyusb against the same G6020,
to confirm we can reproduce the effect without Wine.

## Rollback / safety

- The pre-flight EEPROM dump is NOT yet implemented (Phase A work). For
  R1, we accept the risk that the test unit gets one unprotected write
  attempt. The test unit is the **broken** G6020 — its baseline state is
  5B00 — so a failed attempt can only re-trigger 5B00 (no worse) or
  succeed (clears the counter). A truly malformed write could corrupt
  other EEPROM regions; the cap on this risk is the test-unit-only
  isolation in `maintenance.yaml`.
- If the G6020 enters an unrecoverable mechanical state during the
  attempt (head-lock, carriage jam), unplug USB immediately and power
  down. Re-plug and observe boot behavior before any retry.

## Capture pcaps are committed to git

Once captured, gzip and commit the pcapng under
`services/canon-tool/captures/` with a sidecar `.meta.yaml`:

```yaml
file: v5103-g3010-mode-2026-05-28T23-30-00Z.pcapng.gz
captured_at: '2026-05-28T23:30:00Z'
captured_against:
  uuid: '00000000-0000-1000-8000-00186501807c'
  firmware: '1.070'
service_tool:
  version: v5103
  exe_sha256: '98ca97b37a36a73d1a91630b8bde455b7dd109960073a0369295e34be6317c48'
mode_selected: 'G3010 series'
operation: 'Ink Absorber Counter Clear'
result: 'success' | 'rejected' | 'no_response' | 'mechanical_fault'
notes: |
  Free-form. Anything weird, popup messages, retry counts, etc.
```

The pcap fixtures are how every subsequent capture is regression-tested.
