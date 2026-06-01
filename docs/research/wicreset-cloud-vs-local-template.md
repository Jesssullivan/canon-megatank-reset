# WICReset `printerpotty.exe` — cloud-vs-local template reconciliation + bundled-resource hunt (static RE)

**Date:** 2026-06-01 · **Binary:** `printerpotty.exe` (PE32, 7.48 MB, the real
extracted app), `sha256 a199447db7d9237d95b11456db6e6d9898ab2eb2cae7918acaa1c700a564b3e8`.
**Tooling:** PyGhidra against **Ghidra 12.0.2**
(`/nix/store/a2rxrq8yxw2cahv9j4gbn9d0m8y2d8sq-ghidra-12.0.2/lib/ghidra`),
venv `.ghidra-work/.pgvenv12`, JDK 21. Saved DB `project-full/wicreset-pp-full`
(39 096 functions) opened **read-only by name** (`open_program(..., analyze=False)`).
New tracked scripts this pass: `ghidra/wicreset_template_load.py`,
`ghidra/wicreset_db_callers.py`, `ghidra/wicreset_dbpath.py`. Raw decompiles
(gitignored): `/tmp/pp-template-load.txt`, `/tmp/pp-db-callers.txt`,
`/tmp/pp-dbpath.txt`. On-host inspection: mbp-13
`~/canon-tool-staging/wicreset/` + the `~/.wine-canon-capture` prefix.

This file **resolves the apparent contradiction** between the two prior RE passes:

- `wicreset-static-re.md` (T4) concluded WICReset *"fetches the per-model reset
  definition from its WIC Reset Connect cloud … the Canon per-model reset
  definition is fetched from the server at runtime"* — based on **zero `G6000/G6020`
  strings in the image + the bundled curl/TLS stack**.
- `wicreset-printerpotty-static-re.md` + `wicreset-g6020-reset-template.md` proved
  the `clearCounters` **reset subtree is net-free** and the device bytes are
  **built locally from a per-model TEMPLATE** with dotted-path keys.

Both were right about their own scope; **both were wrong/incomplete about the
template's provenance.** The template is **neither inline `.exe` constants nor a
mandatory cloud fetch** — it is a **bundled, PE-embedded device database** that is
loaded **at startup from an in-binary resource**, with the cloud providing an
**optional refresh/superset**. This pass located that database, its loader, its
load time, and its source. It does **not** restate the transport, the call graph,
or the cipher (those stand).

---

## TL;DR — the reconciliation in one paragraph

The per-model command **template lives in a device database that ships *inside*
`printerpotty.exe` as the PE resource `APP.BIN` (type `DATA`)** — a compressed
`archive::des` blob containing `devices.xml`. At **startup**, `Core::Main`-init
(`FUN_00423790`) calls **`Core::StartupParseAllDatabases` (`0x00434310`)**, which
**tries a "remote" DB first, then falls back to the embedded/bundled DB**, parses
the `devices.xml` into one in-memory model tree, and that single tree is what the
later `PrinterCanonSTD::clearCounters` reset path walks via its dotted-path keys
(`functions.waste`, `commands.set_command`, `command.index/codes/shift`, …). So
**the G6020 template is embedded and offline-derivable; an internet connection is
NOT required to obtain it.** The prior "fetched from cloud" claim conflated two
real but distinct cloud roles — the **key-validation boolean gate** (`QUERY_KEYS`,
genuinely required to *unlock* a reset) and an **optional online device-list
update** (`network/devices`, gated by the `network/enabled` flag) — neither of
which *supplies the device-bound bytes*. The reset bytes come from the embedded DB
+ the local functor cipher, exactly as the printerpotty pass found.

---

## 1. The contradiction, stated precisely

| claim | source pass | status after this pass |
|---|---|---|
| "no `G6000/G6020` strings ⇒ template fetched from cloud at runtime" | `wicreset-static-re.md` §T4 | **half-right premise, wrong conclusion.** No G6020 *strings* is true; but absence of inline strings does **not** imply network — the DB is a **compressed embedded resource**, so it never appears as plaintext `.data` either way. |
| "`clearCounters` subtree is net-free; bytes built locally from a template" | `…printerpotty-static-re.md`, `…g6020-reset-template.md` | **confirmed + completed.** The template the subtree reads is now sourced: the embedded `APP.BIN` DB, loaded at startup. |

The missing link both passes lacked: **where the template *tree* comes from before
`clearCounters` reads it.** That is the device-database loader, below.

---

## 2. The device database — what it is, RECOVERED

WICReset stores **all** per-model definitions (Epson + Canon, including the G-series
megatank rows) in a single **device database**, distributed two ways and merged
into one in-memory tree:

- **bundled / embedded:** the PE resource **`APP.BIN`** of type **`DATA`** — a
  compressed `archive::des` archive that contains **`devices.xml`** (and the
  default **`app.ini`** config). RECOVERED from `FindResourceW(NULL,L"APP.BIN",
  L"DATA")` in two functions (§4).
- **remote / updatable:** a downloadable **`devices.srs`** archive (same archive
  format, parsed by the **same** parser), fetched/merged when `network/enabled` is
  set (§5). This is the only thing the cloud can add — and it is a *superset
  refresh*, not a *gate*.

Both archives decompress to the same `devices.xml` schema (`<commands><raw>…
</raw></commands>` wraps the raw command frames; the dotted-path keys
`functions.waste`, `commands.set_command`, `command.index/codes/shift`,
`keyword.index/codes`, `functor`, … are XML nodes/paths into this tree). File-name
strings recovered: `devices.xml`, `devices.srs`, `app.ini`; the embedded blob is
`APP.BIN`/`DATA`.

> **RECOVERED vs INFERRED:** that the bundled DB is the `APP.BIN`/`DATA` resource,
> loaded at startup, parsed into the model tree — **RECOVERED** (FindResource call
> sites + logger strings + caller graph). That the embedded DB *contains the G6020
> Canon row specifically* — **INFERRED (high)**: it is the **only** model-template
> store in the program, the Canon class reads exclusively from it, and WICReset
> ships supporting G-series megatanks; but the archive is compressed so the literal
> G6020 row is not directly grep-able from the static `.exe` (decompress `APP.BIN`
> to confirm — see §7).

---

## 3. WHEN + WHERE the template loads — RECOVERED call graph

Logger strings (verbatim, present in the image) name every function:

```
FUN_00423790  (Core init / startup)
   └─ UNCONDITIONAL_CALL → FUN_00434310  "Core::StartupParseAllDatabases"
        ├─ FUN_00433ab0  "Core::StartupTryDatabaseRemote"   (tries devices.srs first)
        │     └─ FUN_004431f0 (archive extract) → FUN_00433300 (parse)
        └─ [fallback] FUN_0051b040 (resource-provider iterator)
              └─ provider whose vtable+0xf8 == FUN_00532270
                    └─ FindResourceW(L"APP.BIN",L"DATA") → archive → FUN_00433300
   FUN_00433300  "Core::StartupTryDatabaseCommon"  (the devices.xml parser;
                  "Document parsed in" / "Data is not found in archive...")
```

**`Core::StartupParseAllDatabases` (`0x00434310`) is called once,
`UNCONDITIONAL_CALL` from `FUN_00423790`** (the Core/startup init). Its body
(decompiled, `/tmp/pp-template-load.txt`):

```c
// FUN_00434310  Core::StartupParseAllDatabases (trimmed)
cVar2 = FUN_00433ab0(this+0xfc);        // StartupTryDatabaseRemote  -> devices.srs
if (cVar2 != '\x01') {                   // remote absent/failed -> fall back:
    FUN_00422380("devices.srs");
    cVar2 = FUN_0051b040(&local_98);     // local provider #1 (cached / on-disk)
    if (cVar2 == '\x01' && FUN_00433300(&local_98) == 1) goto done;   // parse
    cVar2 = FUN_0051b040(&local_98);     // local provider #2 (embedded APP.BIN)
    if (cVar2 == '\x01' && FUN_00433300(&local_98) == 1) goto done;   // parse
    // else log StartupParseAllDatabases failure
}
done: ...
```

So the **load order is: remote → (fall back) cached/on-disk → (fall back)
embedded `APP.BIN`.** The embedded resource is the **guaranteed-present floor**:
if the network is down and no cache exists, the bundled DB still parses and the
program is fully functional offline. **`StartupTryDatabaseRemote` is the
*preferred* source, not the *only* source** — and it is itself a `devices.srs`
archive parsed by the same `StartupTryDatabaseCommon`, i.e. the cloud can only ever
hand WICReset *more of the same kind of template*, never a different mechanism.

**Answer to "startup / on key entry / on device select?":** **startup**, before any
key is entered and before any device is selected. The key-entry (`QUERY_KEYS`) and
device-select flows read from this already-loaded tree; they do **not** load it.

---

## 4. The embedded resource — RECOVERED (the bundled-resource hunt payoff)

PE sections (objdump): `.text 0x49e99d`, `.rdata 0x161774`, `.data 0x18e00`,
**`.rsrc 0xab6e8` @ VMA 0x00a4e000** (700 KB of resources). Wide-char resource
names in the image include **`APP.BIN`** and **`DATA`** (`strings -el`).

Two functions load it (decompiled, `/tmp/pp-dbpath.txt`):

```c
// FUN_00532270  (the device-DB resource provider; vtable slot +0xf8)
hResInfo = FindResourceW((HMODULE)0x0, L"APP.BIN", L"DATA");
hResData = LoadResource((HMODULE)0x0, hResInfo);
pvVar1   = LockResource(hResData);
DVar2    = SizeofResource((HMODULE)0x0, hResInfo);   // -> {ptr,size} handed to archive::des
```

```c
// FUN_00530ae0  (app.ini / config defaults provider) — same resource
hResInfo = FindResourceW((HMODULE)0x0, L"APP.BIN", L"DATA");   // default config too
```

`FUN_00532270` feeds the `{ptr,size}` into the `archive::des` decompressor
(`archive::des::vftable`, UTF-8) that `StartupTryDatabaseCommon` (`FUN_00433300`)
uses, then into the `devices.xml` XML parser ("Document parsed in" on success,
"Data is not found in archive..." on extract failure). So:

> **The full per-model template database is embedded in `printerpotty.exe`** as the
> compressed `APP.BIN`/`DATA` resource. **No file on disk and no network is required
> to obtain it.** (RECOVERED — FindResource/LoadResource/LockResource/SizeofResource
> call sites + the archive→parse chain.)

`app.ini`'s **defaults are also embedded** in `APP.BIN` (`FUN_00530ae0`), then
optionally overridden by an on-disk `app.ini`; `app.ini` is where `network/enabled`
and `network/devices` (the update URL list) live.

---

## 5. The cloud's ACTUAL roles — RECOVERED, and why the prior pass over-read them

Three distinct cloud touch-points exist; **none supplies the device-bound reset
bytes.** Mapping each to the prior "fetched from cloud" claim:

1. **Optional device-list UPDATE** — `network/devices` + `network/enabled`
   (`FUN_0042c340`, `FUN_00472570/00472fa0`). These are **config keys read from
   `app.ini` via `FUN_00422380`**, *not* literal URLs. `FUN_0042c340` builds a
   `NETPipeDiscoveryStatic` HTTP client **only if `network/enabled != 0`**
   (`if (local_65[0] != '\0')`), splits the `;`-delimited `network/devices` URL
   list, and fetches an updated `devices.srs`. The UI verb is **"Update devices
   list."** (`FUN_0049be90`); the ingest is sanity-gated:
   *"Data received from the server do not pass sanity check."* (`FUN_0043cee0`),
   and merged via `NETWORK_DEVICES_INSERT_ID / REMOVE_ID / VALUES_ID`. **This is
   the thing the prior pass saw and mis-read as "the template is fetched at
   runtime."** It is an *optional refresh of an already-embedded DB*, gated off by
   default-able config, with a guaranteed embedded fallback.

2. **Key-validation gate** — `RemoteControl::QUERY_KEYS` (`0x0051c700`). Genuinely
   contacted to *unlock* a reset, returns a **boolean**; carries **no device
   bytes** (established in `wicreset-printerpotty-static-re.md` §2). Required to
   *authorize*, not to *obtain the template*.

3. **Post-reset redemption report** — `RemoteControl::RESET_DATA` (`0x0051da40`),
   after the USB write. Accounting only.

So the cloud **gates** (key) and **can refresh** (device list) and **accounts**
(burn report); it **never sources** the per-model command template at reset time.
There is **no plaintext WIC hostname** in the image (endpoint assembled at runtime
via `RemoteControl::BUILD_*`), which is *consistent with* but does **not imply** a
required template fetch — the prior pass's inference from "cloud stack present + no
G6020 strings" skipped the embedded-resource possibility.

---

## 6. Reconciliation verdict

| question | answer | confidence |
|---|---|---|
| Is the G6020 template inline `.exe` constants? | **No** (no `G6000/G6020` strings; it is compressed in `APP.BIN`). | HIGH |
| Is an internet fetch **required** to obtain the template? | **No.** The full device DB is the **embedded `APP.BIN`/`DATA`** resource, parsed at startup as the fallback floor; the network DB is an *optional* refresh gated by `network/enabled`. | HIGH |
| Does a network response **populate** the template tree? | **Optionally** — `devices.srs` from `network/devices` is parsed by the *same* `StartupTryDatabaseCommon`, but it is a *superset/refresh*, not the only source; sanity-checked before merge. | HIGH |
| Does the reset path read cloud-supplied bytes? | **No** — `clearCounters` reads the in-memory tree built at startup; cloud calls are gate/report only (prior passes, re-affirmed). | HIGH |
| When/where does the template load? | **At startup**, `FUN_00423790 → Core::StartupParseAllDatabases (0x00434310)`, **before** key entry or device select. | HIGH |
| From what source? | **Remote `devices.srs` if available, else cached/on-disk `devices.srs`, else embedded `APP.BIN`/`DATA`** — all decompress to the same `devices.xml`. | HIGH |

**Both prior passes coexist as follows:** the printerpotty/g6020 pass correctly
analyzed the *reset-time* data flow (net-free, template-driven, locally
constructed). The static-re T4 pass correctly observed the *cloud stack + missing
inline strings* but **incorrectly inferred a *required* runtime template fetch**;
in fact the template is **downloaded-and-cached-OR-embedded at startup, then used
locally at reset time** — startup load, local use. The two are not in conflict once
the **startup device-DB loader (this pass)** is inserted between them.

---

## 7. On-disk reality (mbp-13) + how to extract the embedded G6020 row

- **Install dir** `~/canon-tool-staging/wicreset/` holds only `printerpotty.exe`
  (7.48 MB) and the Inno installer `PrinterPotty_WICReset.exe` (3.0 MB) — **no
  loose `devices.xml` / `devices.srs` / `.dat` / `.json`**: consistent with the DB
  being **embedded** (the installer drops just the exe; the bundled DB rides inside
  it as `APP.BIN`).
- **Wine prefix** `~/.wine-canon-capture` is a *fresh* prefix (created 2026-05-31
  23:59) with only the default `Program Files`/`AppData/Microsoft/Templates`
  skeleton — **WICReset has never been installed or run there**, so there is **no
  runtime cache / no written-out `devices.srs` / no `app.ini` override** to inspect.
  This corroborates §3/§4: with no cache and (in an air-gapped run) no network, the
  program still works off the embedded `APP.BIN` floor.
- **Cache/template files WICReset reads/writes (recovered names):** embedded
  `APP.BIN` (resource) → decompresses to `devices.xml`; optional on-disk
  `devices.srs` (remote/cached DB, path from the `DatabasePath` config key,
  `FUN_006e0080`); `app.ini` (config, defaults embedded, on-disk override). No
  SQLite/`.dat` device store — the merge IDs (`NETWORK_DEVICES_*_ID`) operate on
  the in-memory tree.

**To get the literal G6020 idx/op/cmd + `command.index/codes/shift` keystream
tables *offline* (closes the 4 runtime unknowns without a live capture):**
**decompress the `APP.BIN`/`DATA` resource** and read its `devices.xml`. Recipe
(read-only, no run needed):
1. extract the resource bytes from `.rsrc` (e.g. `wrestool -x -n APP.BIN -t DATA`,
   or a Ghidra dump of the `LockResource` blob, or Python `pefile`);
2. decompress with the `archive::des` codec (zlib/deflate envelope per
   `archive::des` + the "UTF-8" path; the "Data error in compressed datastream"
   string confirms a standard inflate);
3. parse `devices.xml`; locate the Canon G6020 `<device>`'s `commands.set_command`
   row + `command.index/codes/shift`. This is the **offline alternative** to the
   Frida/usbmon capture for unknowns #1/#2/#4 (the device *keyword*, #3, is still
   live-only). **This is the recommended next step** — it makes the whole reset
   derivable without the printer and without the cloud.

---

## 8. Confidence + residual unknowns

- **HIGH (RECOVERED from instructions + resource API + verbatim logger strings):**
  the device DB is the embedded `APP.BIN`/`DATA` PE resource; it loads at startup
  via `Core::StartupParseAllDatabases` (remote→cached→embedded fallback); both
  archives parse to the same `devices.xml` tree the Canon reset path reads; the
  cloud's roles are key-gate (boolean) + optional device-list refresh
  (`network/enabled`-gated) + post-reset report — **not** template source.
- **HIGH:** an internet connection is **not required** to obtain the G6020
  template (embedded fallback always present).
- **INFERRED (high):** the embedded `APP.BIN` already contains the **Canon G6020**
  row (it is the sole model-template store and WICReset ships G-series support) —
  pending the §7 decompression to print the literal bytes.
- **RESIDUAL (unchanged, and now offline-recoverable):** the literal G6020
  idx/op/cmd, the `command.index/codes/shift` keystream tables, and the `functor`
  index — all are **rows in the embedded `devices.xml`**, extractable per §7
  (no key, no cloud, no printer). The device **keyword** (cipher seed) remains the
  only genuinely live-only value (read via `commands.get_keyword` in service mode).

**Lane boundaries respected:** this file does not restate or alter the transport
(`wicreset-static-re.md`), the call-graph/local-vs-cloud reset proof
(`wicreset-printerpotty-static-re.md`), the cipher/frame template
(`wicreset-g6020-reset-template.md`), or the Linux-rig/capture docs. Its sole new
contribution is the **device-database provenance** (embedded resource + startup
loader) that reconciles them.
