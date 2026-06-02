# canon-g6020

Canon PIXMA G6020 (MegaTank G-series) office MFP. Attached to `mbp-13` via USB
`04a9:1865`. CUPS handles print + scan via the `office` queue; this directory
exists for the **maintenance** surface served by the native tool in
`src/canon_megatank/`.

## Why this directory exists separately from CUPS

The 2D paper printer path (CUPS queue `office`, `ipp-usb` bridge on loopback
`:60001`, sane-airscan for scanning) is wired at the host level and does not
need per-printer SSOT. The **maintenance** path does — every supported op
must be:

1. Tied to a captured byte sequence with provenance metadata.
2. Gated on a matching protocol fingerprint (firmware version, CMD set).
3. Refused on any unit whose UUID is not the named `test_unit`.
4. Audited against the EEPROM write budget cap.

See [`maintenance.yaml`](./maintenance.yaml) for the live schema.

## Test unit

The currently-broken G6020 attached to `mbp-13` (error 5B00, ink absorber
counter full; physical sponge inspected and not actually soiled). Identified
by IPP UUID `00000000-0000-1000-8000-00186501807c` (NIC-MAC-derived;
unique per unit).

It is the **only** unit that may receive an EEPROM write until protocol
discovery is complete and locked.

## Refurb roadmap

See `docs/PRODUCTIONIZATION.md` and ADR
`docs/adr/0007-canon-tool-reverse-engineering.md`.

## Operational notes

- USB device file: `/dev/bus/usb/001/022` (bus 001 device 022 at time of
  initial capture; will change across reboots, do not hardcode).
- udev rule (planned): `/etc/udev/rules.d/50-canon-g6020.rules` matches
  `idVendor=04a9` and grants `MODE=0660 GROUP=printstack`.
- The CUPS queue named `office` IS this printer — print jobs are unaffected
  by canon-tool work as long as `canon-reset@.service` is not
  holding the bulk endpoint when CUPS needs it. The systemd unit's
  `ExecStartPost` releases the device on idle; `ExecStop` always closes.
