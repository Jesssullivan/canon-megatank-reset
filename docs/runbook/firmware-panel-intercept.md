# Runbook — intercept the G6020 panel-initiated firmware download (Lane C / approach A)

**Status:** prepared, operator+network-gated. **Goal:** obtain the G6020 firmware
blob (`1865V<ver>AN.bin`) as the *independent device-side cross-check* for the
absorber-reset opcode recovered from the Service Tool RE (Lane A). The firmware's
command dispatch table (opcode → handler) is the second source that confirms (or
corrects) the Lane A bytes before we ever write to EEPROM.

Why this path: the G6020 is panel-/internet-update only — Canon ships **no**
host-side firmware updater for PIXMA consumer models and the legacy `ijdupdate`
PID→manifest index 404s for `1865` (see `canon-tool-firmware-sourcing.md`). The
printer downloads its own firmware over **plain HTTP** from
`gdlp01.c-wss.com/gds/<id>/01/1865V<ver>AN.bin` (confirmed via the `1769`
control), so observing the printer's network traffic yields the blob URL with **no
TLS interception** needed for the blob itself.

## Hard constraints (READ BEFORE RUNNING)

1. **Do NOT let the update INSTALL.** The fingerprint safety gate keys on
   `firmware == 1.070`. A flash invalidates the test-unit baseline AND every
   recovered Ghidra offset. Capture the *download*, then cancel at the panel
   before install — or just grab the URL and `curl` the blob, never confirming the
   panel flow.
2. **The unit may already be current.** If 1.070 is the latest G6020 firmware, the
   panel reports "current version" and downloads **nothing** — no blob to capture.
   The panel "check for update" answers this (read-only, safe). Confirm first.
3. **No Canon redistribution.** If a blob is obtained: SHA-pin it in
   `maintenance.yaml`, do **NOT** commit the binary (ADR 0007). Decrypt/unpack
   locally only.
4. **leecher boundary.** The decrypt tooling is `jesssullivan/pixma` (our fork).
   Do not push to `leecher1337/pixma` from automation — operator handles upstream
   manually (see `INTEROP.md`).

## Capture rig (macOS Internet Sharing → Ethernet)

mbp-13 shares its WiFi uplink to its Ethernet port; the G6020 plugs into that
Ethernet; the printer's HTTP firmware GET crosses the `bridge100` interface in
cleartext, where `tshark` sees it.

```
[Internet] ──WiFi──> mbp-13 ──(Internet Sharing)──> bridge100 ──Ethernet──> G6020
                              tshark -i bridge100  (sees the plain-HTTP GET)
```

### One-time setup (manual, macOS GUI — cannot be scripted headlessly)
1. System Settings → General → Sharing → **Internet Sharing**:
   - *Share your connection from:* Wi-Fi
   - *To computers using:* **Ethernet** (the adapter the G6020 will use)
   - Enable. This brings up `bridge100` (usually `192.168.2.1/24` + DHCP).
2. Plug the G6020 into that Ethernet (via adapter/dongle as needed). Confirm the
   printer pulls a `192.168.2.x` lease (printer panel → LAN settings, or
   `arp -a | grep 192.168.2`).
3. Verify the printer reaches the internet (panel → check for update will fail
   fast if not).

### Run the capture
The helper script handles interface detection, the tshark filter, and post-run
URL extraction:

```sh
just firmware-intercept            # or: scripts/firmware-intercept.sh
```

Then, **on the printer panel**: Setup → Device settings → Firmware update →
**Check for update**. If it offers an update, start the **download** and watch the
script; **cancel before "Install"** once the GET is captured (or as soon as the
script prints the blob URL).

### What the script captures
- A pcap of `bridge100` filtered to the printer IP + HTTP, under
  `~/canon-tool-staging/captures/firmware-intercept-<TS>.pcapng`.
- The extracted `GET …/gds/<id>/01/1865V<ver>AN.bin` line (and the version-check
  request, which may be TLS — if so only the blob GET is in cleartext, which is
  all we need).

### After a successful capture
```sh
# 1) fetch the blob directly over plain HTTP (printer need not finish)
curl -fSL -o ~/canon-tool-staging/fw/1865V<ver>AN.bin '<captured-url>'
# 2) SHA-pin it (record in maintenance.yaml::g6020_firmware; do NOT commit the .bin)
shasum -a 256 ~/canon-tool-staging/fw/1865V<ver>AN.bin
# 3) decrypt → unpack via the jesssullivan/pixma fork (see firmware-decrypt below)
```

## Decrypt-pipeline pre-validation (do this NOW, no printer needed)

De-risk the TIN-1698 pipeline *before* we have the G6020 blob by running it end to
end on the **downloadable `1769` control blob** (older PIXMA, confirmed HTTP 200):

```sh
# control blob is public plain-HTTP, no auth (confirmed 2026-05-29)
curl -fSL -o /tmp/1769V1100AN.bin \
  'http://gdlp01.c-wss.com/gds/4/0400004794/01/1769V1100AN.bin'   # ~34 MB
cd ~/git/pixma && make
./pixma_decrypt /tmp/1769V1100AN.bin /tmp/1769.asc
grep -v -e '^SF' /tmp/1769.asc | srec_cat -o /tmp/1769.bin -binary
./pixma_unpack /tmp/1769.bin /tmp/1769-firmware.bin
file /tmp/1769-firmware.bin   # sanity: should look like a firmware image, not garbage
```

If this produces a clean firmware image, the pipeline + `srecord` dep + key
recovery (`get_key_simple()` known-plaintext `SF0900` / `\r\nSF050000`) all work,
and the only remaining risk for the G6020 is whether its SREC preamble matches
(documented caveat in `canon-tool-firmware-sourcing.md`). **Do not commit the
control blob or its outputs.**

## Cross-check goal (why we do all this)

Once the G6020 firmware is decrypted, locate its **command dispatch table** and
confirm the absorber/group-7 opcode + the `idx` selector independently of the
Service Tool. Agreement → high confidence in the Lane A literal bytes. Divergence
→ the Lane A bytes are model-mismatched (family hypothesis fails) and must not be
written. Either outcome is decisive evidence; record it in
`docs/research/canon-tool-firmware-dispatch.md` (new, on success).
