# WICReset `printerpotty.exe` — WHERE the Canon reset-template DATA comes from (template-source RE)

**Date:** 2026-06-01 · **Binary:** `printerpotty.exe` (PE32, 7.48 MB, the real
extracted app), `sha256 a199447db7d9237d95b11456db6e6d9898ab2eb2cae7918acaa1c700a564b3e8`.
**Tooling:** PyGhidra against **Ghidra 12.0.2**
(`/nix/store/a2rxrq8yxw2cahv9j4gbn9d0m8y2d8sq-ghidra-12.0.2/lib/ghidra`),
venv `.ghidra-work/.pgvenv12`, JDK 21 (zulu via `nix shell nixpkgs#jdk21`). Saved DB
`project-full/wicreset-pp-full` (39 096 functions) opened **read-only by name**
(`open_program(..., analyze=False)`). Tracked scripts (new this pass):
`ghidra/wicreset_tmplsrc_trace.py`, `…_appbin.py`, `…_xfs.py`, `…_crypt.py`,
`…_deckey.py`, `…_inflate.py`, `…_root.py`. Reused: `ghidra/wicreset_decomp.py`,
`ghidra/wicreset_template_extract.py`. Raw dumps (gitignored): `/tmp/pp-tmplsrc-*.txt`,
`/tmp/pp-appbin-*.txt`, `/tmp/pp-xfs*.txt`, `/tmp/pp-inflate*.txt`, `/tmp/APP.BIN`.

This answers the LANE A fork left open by `wicreset-g6020-reset-template.md`
("the absorber idx/op/cmd live in the runtime model template tree, NOT static
.data"). That earlier claim was **half right and half wrong** and is corrected here.

---

## TL;DR — the fork is RESOLVED

1. **The model-template tree is BUNDLED IN THE BINARY**, not cloud-only. It lives
   in an embedded PE resource **`DATA / APP.BIN`** (571 596 bytes), loaded by
   `FUN_00532270` via `FindResourceW(NULL, L"APP.BIN", L"DATA")` →
   `LoadResource` → `LockResource` → `SizeofResource`, and mounted as an in-app
   **`XFSVirtual`** wxWidgets virtual filesystem. The dotted-path keys
   (`functions.waste`, `commands.set_command`, `command.index/codes/shift`,
   `keyword.*`, `functor`) resolve into a property tree whose **root is loaded
   from VFS path `default/userdata`** inside APP.BIN. **No socket / curl / `recv`
   is on the template-load path** (re-confirmed: `recv`/`WSARecv` have zero call
   sites reachable from the loader, and the template-consumer funcs are all the
   local `PrinterCanonSTD::execute_*`/`functor_*` methods). **Verdict:
   `static-in-binary` (bundled resource).** (HIGH)

2. **So a key-free, capture-free full reset is BLOCKED only by one remaining
   layer: APP.BIN is encrypted/obfuscated** (uniform Shannon entropy **7.998
   bits/byte from byte 0**, no plaintext/JSON/XML/zip/gzip header). The decrypt
   is a **custom in-app transform** — **not** WinCrypt (`CryptDecrypt`/
   `CryptDeriveKey` have **zero** call sites; the WinCrypt imports present are
   hashing + TLS cert decoding for libcurl only) — applied over the resource
   bytes before/while the `XFSVirtual` hands out files. The transform's key and
   algorithm are **baked into the .exe** (there is no runtime key input on the
   load path), so it is **decryptable purely statically in principle**, but I did
   **not** finish recovering the exact multi-byte transform in this pass (a
   single-byte-XOR + raw-deflate hypothesis was tested and **falsified**:
   key 0xf8 yields a 2-byte stored block then aborts — false positive). (HIGH on
   "bundled + locally-keyed"; the literal cleartext is **MEDIUM**, pending the
   transform.)

3. **Net effect on the decisive question** — *can we compute the full enciphered
   G6020 reset sequence with ZERO key and ZERO capture?* — **YES IN PRINCIPLE,
   NO YET IN PRACTICE.** Everything needed is inside the binary (the encrypted
   template DB + the decrypt routine + the already-recovered cipher/envelope from
   `wicreset-g6020-reset-template.md`). It is **not** gated on the printer, the
   cloud, or a live keyword *for the table values*. The only work left is to lift
   the APP.BIN container transform and decrypt the blob; once decrypted, the
   G6020 `idx/op/cmd` rows, the `command.index/codes/shift` keystream tables, and
   the `functor` index are **all readable as static data**. (The live **device
   keyword** is still a per-session runtime value — that is the one genuinely
   device-bound input and is out of scope for "table source".)

> Correction to prior doc: the tables are **NOT "runtime/cloud-only / fetched at
> runtime"**. They are **static, shipped in `APP.BIN`, behind an in-binary
> cipher.** The prior "no inline JSON / no G6020 strings in the image" observation
> was correct *for the plaintext .rdata/.data* — it missed that the data lives
> **encrypted in the `.rsrc` resource**, which the string scan did not cover.

---

## 1. The decompiled loader/parser — what the template actually is

### 1a. The resource loader (RECOVERED, HIGH)

`FUN_00532270` (a method in the App/XFS class vtable @ `0x0098b584`):

```c
undefined4 FUN_00532270(int param_1) {
  *(undefined4 *)(param_1 + 8) = 0;
  hResInfo = FindResourceW((HMODULE)0x0, L"APP.BIN", L"DATA");   // <-- embedded blob
  if (hResInfo) {
    hResData = LoadResource((HMODULE)0x0, hResInfo);
    if (hResData) {
      pvVar1 = LockResource(hResData);
      if (pvVar1) {
        DVar2  = SizeofResource((HMODULE)0x0, hResInfo);
        FUN_004d2510(0, pvVar1, DVar2, 1);     // copy/append resource bytes into a buffer
        return 1;
      }
    }
  }
  return 0;
}
```

PE-resource directory walk (verified directly on the image, `wicreset_tmplsrc_*`):

| resource | type | size | role |
|---|---|---|---|
| **`APP.BIN`** | `DATA` (id 1033) | **571 596 B** | **the bundled model-template DB (encrypted)** |
| `CSQUERY` | group 2 | 192 B | a bitmap/cursor (not data) |
| `1..35`, `WX*`, icons | std | ≤67 KB | wxWidgets cursors/icons/bitmaps |

`APP.BIN` is the only application data resource. Image base 0x400000;
`.rsrc` @ VA 0x64e000, the `APP.BIN` bytes start at file offset 0x66c6e8.

### 1b. The mount — APP.BIN becomes a virtual filesystem (RECOVERED, HIGH)

The driver `FUN_00530ae0` (wx app-init) does, after the load:

```c
if (*(code **)(*param_1 + 0xf8) == FUN_00532270) {
   FindResourceW(0,L"APP.BIN",L"DATA"); LoadResource; LockResource; SizeofResource;
   FUN_004d2510(...);                 // raw resource bytes -> buffer
   FUN_004d2a10(...);                 // strip header/footer (substring)
   ...
   local_2b0 = new XFSVirtual;        // *local_2b0 = XFSVirtual::vftable  (RTTI .?AVXFSVirtual@@)
   FUN_00532640(..., XFSVirtual*);    // std::_Ref_count<XFSVirtual> wrap
   // iterate entries; each file's bytes copied via FUN_004d2510 into the FS map
}
```

RTTI confirms the app's own FS classes: **`XFS`, `XFSVirtual`, `XFSGeneral`**
(subclasses of `wxFileSystem`/`wxFileSystemHandler`; `wxFilterInputStream` is also
present). The VFS is then queried by **dotted/slash paths** that appear as plain
strings in the driver and the model loaders:

```
default/userdata     translations/current   runtime/language   default/language
default/platform     default/location       url/action  url/key  splash.png
app.ini   update/last_seen_package   update/skip   ~region~   ~brand~
```

The **model template tree root is `default/userdata`** (string @ `0x0096e290`),
referenced by the device/model init funcs `FUN_004ca290`, `FUN_00528a00`,
`FUN_00528c70`, `FUN_004acbf0` and the mount driver `FUN_00530ae0`. The
`update/*` and `url/*` keys are the **optional self-update / cloud-config**
surface (download a newer package), **separate** from the reset-template data,
which ships complete in the bundled APP.BIN.

### 1c. The dotted-path accessor (RECOVERED, HIGH)

`FUN_00522ac0(key)` is the property-tree lookup the cipher/reset path uses
(`functions.waste`, `commands.set_command`, `command.index`…). It splits `key`
on `.`/`/` (`FUN_0044a6a0` + `FUN_005228c0` walk each component) and descends a
**string-keyed node map** rooted in the model object (`this`). `FUN_0045ee10`
(`command.index/codes/shift`) and `FUN_004ed5e0` (`keyword.*`) are array readers
over the same tree. None of these *build* the tree — they only read it; the tree
is populated from the VFS (`default/userdata`) at model load.

---

## 2. Is it `.rdata` const / PE resource / disk file / network? — DECIDED

| candidate | verdict | evidence |
|---|---|---|
| `.rdata`/`.data` constant table | **NO** (plaintext) | string scan of defined data finds the *keys* but **no values, no `G6000`/`G6020`, no inline JSON** (`wicreset-g6020-reset-template.md`, re-confirmed) |
| **embedded PE resource** | **YES** | `DATA/APP.BIN` 571 596 B loaded by `FindResourceW("APP.BIN","DATA")` (§1a), mounted as `XFSVirtual` (§1b), root `default/userdata` (§1c) |
| file parsed from disk | partial/secondary | only the **optional** `update/` package + a `default/userdata` *override cache* on disk; the **shipped default is the resource** |
| filled from a network response | **NO (for table data)** | `recv`/`WSARecv` zero call sites on the load path; cloud funcs (`QUERY_KEYS 0x0051c700`, `RESET_DATA 0x0051da40`) are a **boolean key gate + post-write report**, never feed the template tree (matches `wicreset-printerpotty-static-re.md`) |

So **`tableSource = static-in-binary`** (the per-model reset template — idx/op
rows + `command.index/codes/shift` keystream + `keyword.index/codes` +
`functor` index — is shipped inside the `APP.BIN` PE resource). A `hybrid-cached`
nuance exists only because the app *may* later download an updated `APP.BIN`
package via `update/*` — but it boots and resets fully from the bundled copy.

---

## 3. The one remaining wall: APP.BIN is enciphered in-binary (not yet lifted)

- **Entropy:** 7.998 bits/byte over the first 64 KB; flat-random from byte 0 ⇒
  encrypted or encrypted-after-compression. No `PK`/`1f 8b`/`78 9c` header; the
  scattered `78 9c`/`1f 8b` byte pairs inside are coincidental (no valid stream).
- **Not WinCrypt:** `CryptDecrypt`, `CryptDeriveKey` → **0 call sites**. Present
  WinCrypt APIs (`CryptCreateHash`, `CryptHashData`, `CryptImportKey`,
  `CryptGetHashParam`, `CryptStringToBinaryW`, `CryptDecodeObjectEx`) are all in
  hashing / TLS-certificate / libcurl helpers (`FUN_00707340`, `FUN_0072eb70`,
  `FUN_0072a100`), not the FS read.
- **zlib 1.2.3 is statically linked** (`inflate` = `FUN_00794130`, error-string
  anchored; wrappers `FUN_006d1dc0`/`FUN_006d2370` = `wxZlibInputStream`), so the
  container is **plausibly `custom-cipher(deflate(files))`** — i.e. a private
  byte transform wrapping standard deflate. The transform is keyed by **constants
  in the .exe** (no runtime key threads into `FUN_00532270`/`FUN_00530ae0`).
- **Empirical falsification:** whole-blob single-byte XOR then raw-inflate does
  **not** work for any key (0xf8 was a 2-byte stored-block false positive). The
  transform is multi-byte / stream / per-file. **Lifting it is the next concrete
  task** and is fully a *static* job (no device, no cloud).

**Therefore the literal G6020 row values (`idx/op/cmd`), the
`command.index/codes/shift` keystream tables, and the `functor` 2-vs-3 index are
RECOVERABLE STATICALLY** — they are bytes inside `APP.BIN/default/userdata` — but
they are **not yet printed here** because the APP.BIN container cipher is not yet
reversed. This is a strictly easier and *offline* problem than the dynamic
keyword capture; it does not need the printer.

---

## 4. Decisive answer + what changes for the fleet plan

**Can we compute the full enciphered G6020 reset sequence with ZERO key and ZERO
capture?**

- **For the TABLE DATA (idx/op/cmd, keystream `command.*`, `keyword.*`, functor):
  YES — it is all static, bundled in `APP.BIN`.** No key, no capture, no cloud
  needed; just finish reversing the APP.BIN container cipher (a pure offline RE
  task) and read the `default/userdata` tree for model `G6020`.
- **For the FINAL on-wire bytes: the cipher + envelope are already recovered**
  (`wicreset-g6020-reset-template.md`: functor-3 envelope `00 12 01 [cmd]` + the
  16 fixed MSVC-rand bytes `e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f`; the
  symmetric XOR keystream over `command.index/codes/shift`). Combined with the
  decrypted tables, the entire `set_session → set_command(per waste idx) →
  get_command` sequence is computable **except** for the XOR of the **live device
  keyword** read via `commands.get_keyword`. That keyword is the **only**
  genuinely runtime/device-bound input — it is NOT a table and NOT in `APP.BIN`.

So: **native, key-free, capture-free generation of the *plaintext* and the *table
parameters* is achievable from the binary alone. A single live keyword read from
the target printer (one service-mode RECV, no WICReset key, no cloud) is required
to finalize the per-session keystream** — that is an intrinsic device handshake,
not a licensing or table dependency.

This *upgrades* the prior plan: items (1)(2)(4) of the four "runtime-only
unknowns" in `wicreset-g6020-reset-template.md` (G6020 idx/op/cmd; the keystream
tables; the functor index) are **reclassified from RUNTIME-ONLY to
STATIC-IN-BINARY-BEHIND-A-CIPHER**. Only item (3), the device keyword, stays
runtime — and it always was, intrinsically.

---

## 5. Confidence + residuals

- **HIGH (RECOVERED):** APP.BIN is the bundled template DB; `FindResource`
  loader + `XFSVirtual` mount; `default/userdata` is the tree root; dotted-path
  accessor `FUN_00522ac0`; net-free load path; no WinCrypt decrypt; zlib linked.
- **HIGH (INFERRED, strong):** the APP.BIN cipher key/algorithm are static in the
  .exe (no runtime key input observed threading into the loader/driver).
- **MEDIUM (open):** the exact APP.BIN container transform (multi-byte cipher over
  deflate) — not lifted this pass; single-byte-XOR falsified. Next task:
  decompile the `XFSVirtual`/`XFS` get-stream filter chain end-to-end and/or
  instrument `FUN_00532270`→VFS once under Wine to dump the first decrypted file,
  then re-derive the transform statically.
- **RUNTIME (intrinsic, unchanged):** the live device keyword (`commands.get_keyword`).

**Lane boundaries respected:** this file does not modify
`wicreset-g6020-reset-template.md`, `wicreset-printerpotty-static-re.md`,
`wicreset-static-re.md`, or the capture/instrumentation runbooks. It only
*reclassifies* their "runtime-only" residuals 1/2/4 and pins the table source.
