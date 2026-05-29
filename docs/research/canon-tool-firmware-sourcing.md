# canon-tool — G6020 firmware sourcing (TIN-1696)

**Ticket:** [TIN-1696](https://linear.app/tinyland/issue/TIN-1696) — source the
Canon G6020 firmware blob. Prerequisite for [TIN-1698](https://linear.app/tinyland/issue/TIN-1698)
(decrypt + dispatch-table extraction) and the [TIN-1699](https://linear.app/tinyland/issue/TIN-1699)
cross-reference gate.
**Date:** 2026-05-29 · **Test unit firmware:** 1.070 · **USB ID:** `04a9:1865`

> Why we want the firmware: it carries the printer's own **command dispatch
> table** (opcode → handler). That is the *independent* reference the Ghidra
> trace ([TIN-1697](https://linear.app/tinyland/issue/TIN-1697)) gets checked
> against before we ever write to the EEPROM. The Service Tool obfuscates the
> wire bytes (`EncCommService`, see `canon-tool-ghidra-notes.md` Finding F), so
> a second static source matters.

---

## The decrypt pipeline (ready, blocked only on the blob)

Tooling lives in the `jesssullivan/pixma` fork (vendored at `~/git/pixma`,
branch `tin-1698-pixma-build-tooling`). `make` builds all three tools.

```sh
cd ~/git/pixma && make
# 1) XOR-decrypt the encrypted blob → SREC (.asc)
./pixma_decrypt 1865V1070AN.bin decoded.asc
# 2) strip the SREC header lines, decode SREC → raw binary  (needs `srecord`)
grep -v -e '^SF' decoded.asc | srec_cat -o decoded.bin -binary
# 3) unpack the payload → firmware image
./pixma_unpack decoded.bin firmware.bin
```

Method origin: Context IS "Hacking Canon PIXMA Printers — Doomed Encryption".
The pixma author **gave up on the absorber reset itself**; we go further than
upstream only at the dispatch-table step.

### Key-recovery caveat (carry into TIN-1698)

`pixma_decrypt.c::get_key_simple()` hardcodes the known-plaintext SREC markers
`SF0900` and `\r\nSF050000` from older PIXMA firmware to recover the 16-byte XOR
key. If the G6020 SREC preamble differs, key recovery yields garbage and the
plaintext assumption must be re-derived from the G6020 blob header. Document the
header bytes if step 1 produces non-SREC output.

---

## The sourcing problem

The leecher/pixma flow fetches firmware from Canon's **legacy CDN index** by USB
PID:

```
http://gdlp01.c-wss.com/rmds/ij/ijd/ijdupdate/<PID>.xml
   → <update_info><version>…</version><url>…AN.bin</url><size>…</size>
```

### Confirmed live (2026-05-29)

| PID | model | manifest | result |
|---|---|---|---|
| `1769` | older PIXMA (control) | `ijdupdate/1769.xml` | **HTTP 200** → v1.100, `http://gdlp01.c-wss.com/gds/4/0400004794/01/1769V1100AN.bin` (34 MB) |
| `1865` | **G6020** | `ijdupdate/1865.xml` | **HTTP 404** (AccessDenied) |
| `1865` | G6020 | `ijdupdate2/1865.xml` and other guessed index paths | **HTTP 404** |

**Conclusion:** Canon kept the *blob* delivery on plain HTTP at
`gdlp01.c-wss.com/gds/<contentId>/01/<PID>V<ver>AN.bin`, but the **G6020 is not
in the legacy `ijdupdate` index**. Newer models are served by a different
update front-end (device-panel / desktop updater), so the PID→manifest shortcut
the pixma readme relies on is dead for us. We must discover the blob's `/gds/…`
URL by another route, then fetch it (the blob endpoint itself is still open HTTP
and needs no auth — see the 1769 control).

---

## Sourcing approaches (ranked for "hardware in hand at mbp-13")

### A. Capture the desktop **Canon IJ Firmware Update Tool** — REUSES THE RIG ★
Canon ships a standalone firmware-update utility (Win/Mac). Run it under the
**existing Wine/QEMU + tshark rig** (the same one R1 uses) pointed at the G6020,
let it phone home for "is there an update," and capture the `/gds/…AN.bin` URL it
resolves. Lowest new setup — the capture environment already exists. The blob is
plain HTTP, so even if the version check is HTTPS we only need the URL string.

### B. Capture the **panel-initiated** update check
G6020 panel: *Setup → Device settings → Firmware update → Check*. The printer
(on WiFi) contacts Canon and resolves a firmware URL. Capture requires the
printer on a network we can observe (router port-mirror, or a laptop AP with
`tcpdump`). Version check is likely TLS; the blob download is historically plain
HTTP from `c-wss.com`, so a DNS-redirect / transparent-proxy that logs the blob
GET is enough. More setup than (A) because the printer is currently USB-attached.

### C. Direct support-page / mirror discovery
Canon regional support pages ("G6020 → Drivers & Downloads → Firmware") and
third-party firmware archives sometimes expose the `…AN.bin` URL or host a copy.
Cheap to try (web search + fetch); validate any blob by feeding it to
`pixma_decrypt` and checking for SREC output.

### D. Brute the `/gds/` content path — NOT RECOMMENDED
We know the filename (`1865V1070AN.bin`) but not the content-id directory
(`0400004794` for 1769). The id space is large and hammering Canon's CDN is
rude; only consider if A–C fail and we find a way to narrow the id.

### E. On-printer extraction — highest effort
Dump flash via service-mode / hardware. The Service Tool's "EEPROM Dump" reads
EEPROM, not the firmware image, so this needs JTAG/teardown. Last resort.

---

## Recommended path

1. **(A)** Acquire the G6020 IJ Firmware Update Tool and capture its resolved
   `/gds/…AN.bin` URL under the existing rig; fetch the blob over plain HTTP.
2. Fall back to **(C)** support-page/mirror discovery in parallel (cheap).
3. **(B)** panel capture if A/C dry up and we can put the unit on a mirrored net.
4. On a blob: SHA-pin it (do **not** commit — no Canon redistribution, ADR 0007),
   run the TIN-1698 pipeline, and document the dispatch table in
   `canon-tool-firmware-dispatch.md`.

## Status

- [x] Legacy CDN behavior confirmed (1769 ✓ / 1865 ✗), blob endpoint shape known.
- [x] Decrypt tooling builds reproducibly (`make`), key-recovery caveat noted.
- [ ] G6020 blob URL discovered (approach A/C).
- [ ] Blob fetched + SHA-pinned.
- [ ] Decrypt → unpack → dispatch table (TIN-1698).
