# WICReset APP.BIN in-memory dump (Lane B) — runbook

**Date:** 2026-06-01 · **Lane:** B (dynamic, in-memory decrypt capture) · **Status:**
methodology proven end-to-end; **G6020 template NOT present in this build's APP.BIN**
(decisive negative — corroborates the static RE).

## Goal

Let `printerpotty.exe` (Printer Potty WICReset, 32-bit PE) decrypt + mount its
embedded `APP.BIN` resource tree at startup, then dump the **cleartext** straight
out of process memory with Frida. No reset key spent, no printer device, no cloud
call — the mount happens during startup before any of that. Pure data extraction.

## TL;DR result

- **Lane B mechanically works.** Frida hooks on the decrypt/mount/accessor path
  fire, and we dumped **~5.1 MB of cleartext** from live `printerpotty.exe` memory
  with **no key, no device, no cloud**. The decrypted config tree is a dotted-path
  key/value store read via `FUN_00522ac0`; observed live keys: `service.product`,
  `waste.reset`, `waste.query`, `free.regions`, `free.actions`.
- **BUT the Frida runtime dump captured the wrong buffers** (the app's RSS/news
  cache + the still-ciphertext APP.BIN blocks), so a raw scan of the 5.1 MB showed
  only Epson counter templates and **no Canon**. That was a *capture artifact, not
  the truth.*
- **DECISIVE (the real win): the whole APP.BIN is zero-key 3DES obfuscation, so it
  decrypts STATICALLY — no Frida, no runtime needed.** Per the sibling research docs
  `docs/research/wicreset-appbin-cipher.md` + `wicreset-appbin-container.md` and the
  `scripts/appbin_oracle.py` model, the container is:
  `APP.BIN = DES-CBC(key=0, iv=0)(ZIP) ‖ 4-byte footer`, and the inner `devices.srs`
  is the **same** scheme recursively, yielding `devices.xml` (2.5 MB plaintext).
- **I executed that chain end-to-end and recovered the Canon G6000-family (= G6020)
  command template.** `devices.xml` contains `Canon G6000 Series` (`specs=CANON-SR5`,
  `class=canon.printer.std.standard`), and the live command bytes live in the
  `<CANON-IPL>` spec block. **G6020 is a G6000-family member** (no separate literal,
  exactly as `wicreset-appbin-container.md` predicted).
- So: Lane B proves the in-memory path works AND closes the "is the template hiding
  encrypted inside WICReset?" question — **yes, and here it is, key-free** (the
  earlier static-RE doc's "not in the binary" conclusion was about *plaintext
  strings*; the data is present once you peel the zero-key DES + ZIP layers).

## RECOVERED G6020 / G6000-family values (from `<CANON-IPL>` in devices.xml)

Key-free, capture-free, device-free. These are the actual template bytes.

**Command prefixes** (`<commands>`; matches WICReset RTTI 0x85/0x86/0x82/0x81):
```
set_session  set  prefix 0x81 0x00 0x00 0x03
get_version  get  prefix 0x8A ...
get_keyword  get  prefix 0x82 ...
get_command  get  prefix 0x86 ...
set_command  set  prefix 0x85 ...
```

**Waste reset commands** (`<waste><row>`; each = `0x10 0x07 0x7C` then the selector):
```
away    0x10 0x07 0x7C   0x0D 0x05 0x00
black   0x10 0x07 0x7C   0x0D 0x03 0x00
common  0x10 0x07 0x7C   0x0D 0x00 0x00
platen  0x10 0x07 0x7C   0x0D 0x01 0x00
color   0x10 0x07 0x7C   0x0D 0x04 0x00
(6th)   0x10 0x07 0x7C   0x0D 0x06 0x00
```

**keyword** (`<keyword>`):
```
codes  0x4D 0x49 0x53 0x00   ("MIS\0")
index  0x03 0x01 0x00 0x02
value  0x4D 0xB6 0xAB 0x00
```

**functor**: `0x02`

**command.index** (`<command><index>`, 5 permutation arrays of 20 bytes — the
position permutation of the EncCommService transform), e.g. array 0:
`0x01 0x0B 0x07 0x0F 0x06 0x0A 0x00 0x11 0x13 0x08 0x03 0x0E 0x12 0x0D 0x04 0x02 0x09 0x10 0x0C 0x05`.

**command.codes** (`<command><codes>`, 7 keystream arrays of 20 bytes), e.g. array 0:
`0x23 0x58 0x0C 0x10 0x5A 0xA8 0x36 0x55 0x60 0x02 0x3E 0x4C 0x60 0x17 0x1B 0x0B 0x63 0xB8 0x2B 0xDC`.

**command.shift** (`<command><shift>`, arrays of `<value><action><sign>&|=|%</sign>
<data>N</data>` — the bit op/shift directives), e.g. array 0:
`(&,1) (=,0) (%,5) (=,0)`.

**functions.waste idx/op/cmd** (`<functions><function>` rows = `<code>`/`<special>`/
`<indexes>`), e.g.: `0x00`→special `0x04 0x66`; `0x01`→`0x05 0x22` idx `0x07`;
`0x03`→`0x0F 0x01` idx `0x03`; `0x21`→`0x02 0x12` idx `0x08`; … (full table in the
saved `CANON-IPL.g6000-family.xml`).

Full block: `~/canon-tool-staging/captures/appbin-static-*/CANON-IPL.g6000-family.xml`.

## Environment

- Host: `mbp-13` (Rocky 10.1). SSH in; fish login shell. Author scripts to a local
  file, `scp` to mbp-13, run **one** `bash -lc "bash /tmp/x.sh"` per step (fish does
  not like complex inline quoting; keep logic in a file).
- Guest: `canon-capture-win11-headless` (`virsh --connect qemu:///session`), Win11
  Pro **x86_64 (AMD64)**, autologon user `cap` on the **interactive console
  (session 1)**.
- Control: WinRM via the staged ansible venv —
  `PATH=~/canon-tool-staging/ansvenv/bin ansible -i host/vm-capture/ansible/inventory.yml canon-win11 -m ansible.windows.win_shell -a "<ps>"`.
- Target: `C:\Program Files (x86)\Printer Potty WICReset\printerpotty.exe`
  (8.3 short path `C:\PROGRA~2\PRINTE~1\PRINTE~1.EXE`), 32-bit / WOW64, default
  imagebase `0x00400000` but **ASLR-rebased at runtime** (observed base `0x000e0000`).
- `APP.BIN` is **not a file on disk** — it is embedded in the EXE (overlay/resource)
  and only exists as cleartext in memory after the startup decrypt. This is exactly
  why a static dump is impossible and Lane B is required.

## The five hook addresses (default imagebase 0x00400000)

Rebase at runtime: `target = module.base + (VA - 0x00400000)`. All five are real
function prologues (verified by reading the PE `.text` bytes at their file offsets;
`55 8b ec ...` = `push ebp; mov ebp,esp`).

| VA | role | runtime addr (this run, base 0xe0000) |
|---|---|---|
| `FUN_00530ae0` | decrypt/mount orchestrator | `0x210ae0` |
| `FUN_004d2a10` | header/footer strip | `0x1b2a10` |
| `FUN_004d2510` | buffer-append / resource copy `(dst,src,len)` | `0x1b2510` |
| `FUN_00794130` | inflate (zlib) | `0x474130` |
| `FUN_00522ac0` | **dotted-path accessor (the tree)** | `0x202ac0` |

The **accessor `FUN_00522ac0` is the money hook**: it is the live config-tree
reader. Hooking it shows the dotted keys and lets us dump each returned node.

## CRITICAL gotchas (each one cost a cycle — do not relearn them)

1. **Session 0 vs session 1.** WinRM runs in **session 0**. A `Start-Process` from a
   WinRM shell lands the target in session 0, where **frida's agent bootstrap stalls
   forever** ("Process … refused to load frida-agent, or terminated during
   injection", or a silent hang with zero output). Fix: run the whole
   spawn+attach+hold inside the **interactive console session (1)** via a
   **Scheduled Task** registered with `/RU cap /RP canon-cap /RL HIGHEST /IT`
   (`/IT` = interactive token → session 1). Once in session 1, injection works.
2. **A process spawned in one WinRM PowerShell is reaped when that shell exits.** So
   spawn, attach, AND hold must all live in **one** invocation (the session-1 task
   script does this).
3. **Frida script encoding must be pure ASCII.** Frida's V8/QJS parser rejects
   non-ASCII bytes that node accepts. Em-dashes (`U+2014` = `e2 80 94`) and box-drawing
   chars in comments, and stray `NUL`/control bytes inside string literals, both
   throw `SyntaxError: Invalid or unexpected token` / `unexpected end of string` at a
   misleading line number. Sanitize to 7-bit ASCII before pushing:
   `python3 -c "b=open(f,'rb').read(); open(f,'wb').write(bytes(0x20 if (c<9 or 13<c<32) else (c if c<128 else 0x2d) for c in b))"`
   then `node --check`.
4. **`-f` spawn needs a space-free path.** frida-inject splits on spaces; pass the
   8.3 short path `C:\PROGRA~2\PRINTE~1\PRINTE~1.EXE`. (We ended up using
   spawn-then-attach-by-pid anyway, which is more reliable here.)
5. **frida-inject output is unreliable.** `-e` (eternalize) injects then **exits and
   detaches stdout** → the dump never reaches the redirect. Without `-e`/`-i` the
   injector stays alive but **buffers stdout** until exit (and a `Stop-Process` kill
   never flushes). **Fix: do not rely on stdout at all** — have the Frida script
   write artifacts to guest files via the **`File` API** (`new File('C:\\canon\\...','wb')`).
   That is the authoritative output; the base64 stdout echo is only a live peek.
6. **Defender.** Tamper Protection is on and cannot be disabled remotely
   (`Set-MpPreference` is tamper-locked). We added path exclusions for `C:\canon`
   and `%TEMP%`; with those, no Defender block events fire for the injection — the
   injection problems above were **session-0**, not AV. (Exclusions are still worth
   keeping.)
7. **The 62 MB `frida-inject-x86.exe` staged in the guest is suspect.** We fetched a
   clean **`frida-inject 16.5.9 windows-x86`** (29 MB, `PE32 Intel 80386`) and used
   that. 16.5.9 works; the `-R qjs` and `-R v8` runtimes both run once the script is
   ASCII and the session is 1.
8. **Compute the base at runtime.** Imagebase is `0x400000` but the PE has `.reloc`
   and **ASLR rebases it** (observed `0xe0000`). Always
   `Process.enumerateModules()` → find `printerpotty.exe` → add `(VA - 0x400000)`.

## Procedure (reproducible)

All scripts live on `mbp-13`; push to guest with `win_copy` (use **forward-slash**
dest paths to dodge the `\a`→bell ansible-arg gotcha:
`dest=C:/canon/appbin-dump.js`).

1. **Stage** on the guest in `C:\canon\`:
   - `appbin-dump.js` — the Frida hook (ASCII-sanitized; writes events to
     `C:\canon\appbin-events.log` and raw node/inflate/copy buffers to
     `C:\canon\appbin-out\dump_<id>_<tag>.bin` via the File API).
   - `frida-inject-16-x86.exe` — clean frida-inject 16.5.9 windows-x86.
   - `sess1-dump.ps1` — spawns `printerpotty.exe`, waits ~1.3 s, attaches
     `frida-inject-16-x86.exe -p <pid> -s appbin-dump.js -R v8` (no `-e`), holds ~20 s,
     tears down. Logs to `C:\canon\sess1-dump.runlog`.
2. **Register + run the session-1 task** (so injection actually works):
   ```
   schtasks /Create /TN AppBinDump /TR "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\canon\sess1-dump.ps1" /SC ONCE /ST 23:59 /RU cap /RP canon-cap /RL HIGHEST /IT /F
   schtasks /Run /TN AppBinDump
   ```
   Poll `schtasks /Query /TN AppBinDump /FO LIST /V` until `Status` leaves `Running`.
3. **Collect**: `Compress-Archive C:\canon\appbin-out\*,C:\canon\appbin-events.log
   appbin-bundle.zip`, then `ansible … -m fetch -a "src=C:/canon/appbin-bundle.zip
   dest=<host>/ flat=yes"` (use builtin `fetch`, **not** `ansible.windows.fetch` —
   that module does not exist). Unzip on mbp-13 and parse.

## What the dump captured (run 2, ~5.1 MB cleartext)

- **Event taxonomy:** `HOOK_LOADED` 1, `HOOKED` 5 (all five hooks installed),
  `ACCESS` 2161 (accessor calls), `WROTE_BIN` 1258 (node/buffer dumps written),
  `MARKER_HIT` 8.
- **Accessor key namespace (decrypted tree):** `service.product` (1479),
  `waste.reset` (340), `waste.query` (340), `free.regions` (1), `free.actions` (1).
- **A `service.product` node** decoded to the Epson cleaning/counter template:
  `Manual cleaning counter`, `Timer cleaning counter`, `Power cleaning counter`,
  `First TI received time`, `Normal/Strong/Gentle % Cleaning`, and EEPROM address
  rows `0x1D7 0x1D6 0x1D5 0x1D4`, `0x0F 0x0E 0x0D 0x0C`, `0x100 0x00 0x190 0x08`,
  `0xA7 0xA6 0xA5 0xA4`, `0xAB 0xAA 0xA9 0xA8`, `0x100 0x04 0x190 0x01`, plus the
  Epson fw marker `NE09D9 09/09/2013`.
- **`FUN_004d2510` copy buffers** captured the app's runtime RSS/news cache
  (printerpotty.com support feed: "WICReset v5.95", "waste ink pads", etc.) and the
  **high-entropy 154 KB block** = the still-encrypted/compressed APP.BIN payload
  (random-looking, no readable strings) plus 16 KB ciphertext chunks.

## Decisive finding (corrected — the data IS present)

- A raw ASCII+UTF-16 scan of the **5.1 MB Frida runtime dump** showed 0 Canon / 0
  G-series and many Epson hits. That is a **capture artifact**: the Frida hooks I
  used (`copy.src` on `FUN_004d2510`, the zstream-window inflate heuristic, and the
  per-node accessor dump) landed on the app's RSS/news cache and the **still-
  ciphertext** APP.BIN blocks — not the decrypted tree's Canon records.
- The **static zero-key decrypt** (run on mbp-13 via `uv run --with pycryptodome`)
  recovered `devices.xml` (2,549,646 B) which **does** contain the Canon G-series,
  including `Canon G6000 Series` and the `<CANON-IPL>` command template above. Token
  counts in the plaintext: `Canon`×41, `G6000`×4, `command`×80, `index`×75,
  `functor`×24, `functions`×15, `keyword`×683, `waste`×739.
- Reconciliation with `wicreset-static-re.md` T4 ("Zero G6000/G6020 strings in the
  7.5 MB image"): that was true of **plaintext strings in the raw PE** — the Canon
  data sits inside the **encrypted** `APP.BIN` resource (zero-key 3DES + double ZIP),
  so it never appears as a flat string until the container is peeled. It is **not**
  cloud-only for the G6000 family; it ships locally, encrypted, in this build.

## The faster path than Frida (use this)

Lane B's Frida harness is proven and reusable, but for *extracting the template* you
do **not** need it. Carve `APP.BIN` from `printerpotty.exe` at file offset
**0x638ee8**, size **571596**, then:
```python
from Crypto.Cipher import DES; import zipfile, io
ct = open('APP.BIN','rb').read()
z  = zipfile.ZipFile(io.BytesIO(DES.new(b'\0'*8, DES.MODE_CBC, b'\0'*8).decrypt(ct[:-4])))  # outer ZIP (90 members)
srs= z.read('devices.srs')
xml= zipfile.ZipFile(io.BytesIO(DES.new(b'\0'*8, DES.MODE_CBC, b'\0'*8).decrypt(srs[:-4]))).read('devices.xml')  # 2.5 MB
```
(`scripts/appbin_oracle.py` is the in-repo oracle/validator for this.)

## Consequence for the G6020 effort

- The G6020/G6000-family `command.index/codes/shift`, `keyword.*`, `functor`, the
  `waste` reset selectors, and the `functions` idx/op/cmd table are now **plaintext,
  key-free, capture-free, device-free** (above + saved artifacts).
- Cross-check against the Canon Service Tool RE (`canon-tool-ghidra-notes.md`
  Finding E — `[00,03,flags,03,idx]`, group 7) and a T4 usbmon ground-truth before
  trusting the literals for a live reset; the G6000 series is `method`/`waste:*`
  driven, and a G6020-exact selector should be confirmed once on hardware.
- Lane B's residual value: a working in-memory-dump harness for any future build
  whose resource is **not** zero-key (e.g. a real-keyed container), where static
  decrypt would need the runtime key.

## Artifacts (on mbp-13)

- Frida hook: `C:\canon\appbin-dump.js` (guest); source pushed from
  `/tmp/appbin-dump.js`.
- Session-1 launcher: `C:\canon\sess1-dump.ps1` (guest).
- Run bundles + extracted cleartext:
  `~/canon-tool-staging/captures/appbin-memdump-*/out/` — `appbin-events.log` +
  `dump_<id>_<tag>.bin` (1178 node dumps + 107 copy dumps, ~5.1 MB).
- Saved Epson template node: `~/canon-tool-staging/captures/appbin-memdump-*/`
  (`epson-template-node-dump_101.bin`).
- Clean injector: `~/canon-tool-staging/` → guest `C:\canon\frida-inject-16-x86.exe`
  (frida-inject 16.5.9 windows-x86).
