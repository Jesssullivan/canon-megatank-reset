# services/canon-tool/captures/

Pcap fixture store for canon-tool. Every committed capture comes with
a `.meta.yaml` sidecar that pins the printer firmware, Service Tool
version, operation attempted, and outcome. The metadata is what lets
the regression suite refuse to replay stale captures against drifted
firmware.

## Naming convention

```
<op>-<source>-<service-tool-version>-<mode>-<timestamp>.pcapng[.gz]
<op>-<source>-<service-tool-version>-<mode>-<timestamp>.meta.yaml
```

Examples:

```
absorber-reset-wine-v5103-g3010mode-2026-05-28T23-30-00Z.pcapng.gz
absorber-reset-wine-v5103-g3010mode-2026-05-28T23-30-00Z.meta.yaml

absorber-reset-qemu-v5302-g6020mode-2026-05-29T01-15-00Z.pcapng.gz
absorber-reset-qemu-v5302-g6020mode-2026-05-29T01-15-00Z.meta.yaml
```

Source values:
- `wine`    — captured under Wine via tshark+usbmon (R1 path)
- `qemu`    — captured under Win11 VM via USBPcap (R2 path)
- `replay`  — captured during a pyusb replay session (Phase A regression)

Op values track the operations registered in
`printers/canon-g6020/maintenance.yaml::supported`:
- `ping`               — read-only fingerprint + status check
- `eeprom-dump`        — full EEPROM read (no write)
- `absorber-reset`     — clear ink absorber counter (THE 5B00 fix)
- `head-counter-reset` — head-replacement counter
- ... etc

## Compression

Commit pcapng files **gzipped** (`.pcapng.gz`). USB captures are
extremely repetitive, gzip 80–95%+. Use:

```sh
gzip -9 absorber-reset-wine-v5103-g3010mode-2026-05-28T23-30-00Z.pcapng
```

## Size guidance

If a single pcap exceeds ~5MB compressed, something is wrong — either
the capture was left running too long, or there's a packet flood the
analyzer should detect. Either way, dig before committing. Most
single-operation captures should be < 100KB.

## What never goes here

- Service Tool binaries (those stay in `~/canon-tool-staging/` —
  acquired separately, never redistributed).
- Firmware blobs (decrypted or not — `jesssullivan/pixma` handles those).
- EEPROM dumps with potentially-PII contents (printer serial,
  registered owner name etc) — those go to `/var/lib/canon-tool/<serial>/`
  on the host, NOT to git.

## Analyzing a freshly-captured pcap

```sh
just canon-analyze ~/canon-tool-staging/captures/absorber-reset-wine-v5103-g3010mode-...pcapng
```

The analyzer prints:
- Packet count + duration
- Bulk-OUT byte sequences (host → printer, the commands)
- Bulk-IN byte sequences (printer → host, the responses)
- Heuristic Canon protocol header detection (NCCe / IVEC / BJRaster3)

When the analysis identifies a likely "absorber reset" sequence,
update `printers/canon-g6020/maintenance.yaml::supported` with the
byte sequence and run the regression suite.
