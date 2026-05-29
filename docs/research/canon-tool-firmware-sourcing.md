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

## Update-mechanism ground truth (confirmed 2026-05-29)

The G6020 is the **"G6000 series"** in NA naming. Two facts kill the easy paths:

- **Panel + internet only.** Canon's manual (G6000 series, `ug-178`) and KB
  `ART183640` document firmware update **only** via *Setup → Device settings →
  Firmware update → Install update*, with "make sure the printer is connected to
  the internet." The printer downloads the firmware **itself** from a Canon
  server. No file is offered to the user.
- **No PIXMA host tool.** Canon's downloadable "Firmware Update Tool" EXEs exist
  only for the **imagePROGRAF** pro line — not PIXMA consumer printers. So there
  is no host-side updater to run under the Wine/QEMU rig and no bundled `.bin`
  to extract. (Verified: every PIXMA G-series result was panel-only.)
- **No public direct `.bin`.** Support pages and third-party "firmware" sites
  (e.g. gofirmware.com — a content farm) expose nothing real.

**Net:** the firmware lives only on Canon's server and on the printer's flash.
We get it by **intercepting the printer's own panel-initiated download**.

## Sourcing approaches (ranked, post-ground-truth)

### A. Intercept the panel-initiated download — THE path ★
Put the G6020 on a network whose traffic mbp-13 can observe, then trigger the
panel firmware update and capture the firmware fetch. The blob download is
**plain HTTP** from `gdlp01.c-wss.com/gds/…AN.bin` (confirmed via the 1769
control), so **no TLS interception is needed to grab the blob** — we only need
to see the GET. Capture options, simplest first:
1. **macOS Internet Sharing → Ethernet.** Share mbp-13's WiFi to its Ethernet,
   plug the G6020 into that Ethernet, run `tshark`/`tcpdump` on the `bridge100`
   interface. The printer's HTTP firmware GET is in cleartext.
2. Logging HTTP proxy / DNS-redirect, if the version *check* (which may be TLS)
   must be observed to learn the URL before any download starts.
3. Managed-switch port mirror, if one is available.

Once the `GET …/<id>/01/1865V1070AN.bin` line is seen, we have the URL and can
`curl` the blob directly over plain HTTP — the printer need not finish.

> ⚠️ **Two hard constraints for approach A**
> 1. **Do NOT let the update INSTALL.** The fingerprint safety gate keys on
>    `firmware == 1.070`; a flash would invalidate the test-unit baseline and
>    the recovered Ghidra offsets. Capture the *download*, then cancel before
>    install — or just re-`curl` the URL and abort the panel flow.
> 2. **The unit may already be current.** If 1.070 is the latest G6020 firmware,
>    the panel will report "current version" and download **nothing** — no blob
>    to intercept. Must confirm the latest version first (see open question).

### B. Brute the `/gds/` content path — NOT RECOMMENDED
Filename is known (`1865V1070AN.bin`) but the content-id dir is not
(`0400004794` for 1769; firmware ids are in the `04xxxxxxxx` range). Large space,
rude to Canon's CDN. Only if A is impossible and we can narrow the id.

### C. On-printer extraction — highest effort
Dump flash via service-mode / hardware. The Service Tool's "EEPROM Dump" reads
EEPROM, not the firmware image, so this needs JTAG/teardown. Last resort.

---

## Recommended path

1. **Confirm the latest G6020 firmware version** (vs our unit's 1.070). If we're
   behind, approach A can trigger a real download to intercept. If current, we
   need a way to force a re-fetch or fall to (C).
2. **Approach A:** observe the printer's network, trigger the panel update,
   capture the plain-HTTP `…AN.bin` GET, `curl` the blob — **without installing**.
3. On a blob: SHA-pin it (do **not** commit — no Canon redistribution, ADR 0007),
   run the TIN-1698 pipeline, document the dispatch table in
   `canon-tool-firmware-dispatch.md`.

## Open question (blocks choosing the trigger)

What is the **latest published G6020 firmware version**? Our test unit is on
1.070. Canon's JS support pages don't expose it to scraping; the panel "check
for update" itself answers it (read-only, safe). Needed to know whether a panel
download can even be triggered for interception.

## Status

- [x] Legacy CDN behavior confirmed (1769 ✓ / 1865 ✗), blob endpoint shape known.
- [x] Decrypt tooling builds reproducibly (`make`), key-recovery caveat noted.
- [ ] G6020 blob URL discovered (approach A/C).
- [ ] Blob fetched + SHA-pinned.
- [ ] Decrypt → unpack → dispatch table (TIN-1698).
