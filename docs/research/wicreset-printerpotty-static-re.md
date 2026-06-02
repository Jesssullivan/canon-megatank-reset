# WICReset `printerpotty.exe` — static RE & Ghidra↔dynamic correlation map

**Date:** 2026-06-01 · **Binary:** `printerpotty.exe` (the extracted 7.48 MB app,
**not** the 3 MB Inno installer), WICReset / "Printer Potty WICReset",
PE32 / Intel 80386, `sha256 a199447db7d9237d95b11456db6e6d9898ab2eb2cae7918acaa1c700a564b3e8`.
Binary + Ghidra project are **not** committed (no redistribution).

**Tooling (working, reused):** PyGhidra 3.0.2 against **Ghidra 12.0.2**
(`/nix/store/…-ghidra-12.0.2/lib/ghidra`), pyghidra venv at
`.ghidra-work/.pgvenv12`, JDK 21 via `nix shell nixpkgs#jdk21`. The saved,
fully-disassembled program (`project-full/wicreset-pp-full`, **39 096 functions**
after the forced `.text` disassembly from the prior pass) is opened **read-only by
name** (`open_program(..., program_name="printerpotty.exe", analyze=False)`).
Tracked scripts: `ghidra/wicreset_probe.py`, `…_imports.py`, `…_netmap.py`,
`…_canon.py`, `…_resetflow.py`, `…_decomp.py`.

> This document is the **third triangulation leg**: it pre-stages the keyed G6020
> capture so the live trace is interpretable on the first try. It builds on (and
> does not restate) the transport already pinned in `wicreset-static-re.md`. The
> new contribution here is the **Canon device class** (not the Epson builder the
> prior pass decompiled), the **local-vs-cloud verdict from the actual reset-button
> call graph**, and the **strace/usbmon ↔ static correlation table**.

---

## TL;DR — the two load-bearing findings

1. **LOCAL-vs-CLOUD VERDICT: locally constructed device bytes, cloud-validated key
   (boolean gate). Native replay is feasible.** The Canon reset
   (`PrinterCanonSTD::clearCounters` @ `0x004ecae0`) and its **entire call subtree
   — `action_is_permitted`, `service_perform_command_common`,
   `functor_encryption_003`, `service_send_buffer`, down to the
   `DeviceIoControl(0x220038)` SEND — contains ZERO socket calls** (verified by
   BFS over the call graph: `subtree=721, no-net`). The network appears **only one
   level up**, in the Action orchestrator `ActionCanonDeviceClearCounters`
   (`0x0043fbc0`), which calls the cloud key check **`RemoteControl::QUERY_KEYS`
   (`0x0051c700`)** and branches on its **boolean** result
   (`if (cVar9 != '\x01') goto error`) **before** calling `clearCounters` **with no
   server data passed in**. The post-reset `RemoteControl::RESET_DATA`
   (`0x0051da40`) runs **after** the USB write (redemption report), not before. So
   the server **gates** the reset and **records** the key burn; it does **not**
   supply or sign the device-bound bytes.

2. **USB HOOK TARGET (for Frida/strace/usbmon):** the maintenance SEND is
   **`FUN_0052ce40` → `DeviceIoControl(handle, 0x220038, inBuf, nIn, NULL, 0, …)`**;
   the RECV is **`FUN_0052cab0` → `DeviceIoControl(handle, 0x22003c, inBuf, nIn,
   outBuf, 5000, …)`**. The handle is a `CreateFileW(\\?\usb…, GENERIC_RW,
   SHARE_RW, OPEN_EXISTING, OVERLAPPED|NO_BUFFERING)` cached at `this+0x24`.
   **No USB SETUP packet is ever built** in the binary — only the encrypted
   `[cmd][arg][value]` application frame handed to the IOCTL; the bulk/control pipe
   choice is the Windows minidriver's (matches `canon-servicemode-transport-research.md`).

Confidence: **High** on both (direct decompilation + call-graph BFS, the analyzed
program is the real 7.48 MB app). The one residual is which exact `idx/op` literals
the per-model template carries for G6020 — those are template **data**, fetched/keyed
at runtime, and are recovered by the T4 usbmon capture this map pre-stages (or from
the Service Tool offline oracle), not from these `.exe` instructions.

---

## 1. USB transfer call site (the dynamic hook target)

Imports (Ghidra external table): **`KERNEL32!DeviceIoControl` + `CreateFileW`**,
**`SETUPAPI`** (`SetupDiGetClassDevsW`, `SetupDiEnumDeviceInterfaces`,
`SetupDiGetDeviceInterfaceDetailW`, `CM_Get_Device_IDW`…). **No `WinUsb_*`, no
libusb.** So WICReset reaches the printer exactly like the Canon Service Tool:
SetupDi-enumerate → `CreateFileW` handle → `DeviceIoControl`.

`DeviceIoControl` resolves to **exactly 5 caller functions** — the USB I/O
primitives (each lazily opens + caches the handle at `this+0x24`, then issues one
IOCTL). Codes verified in `.ghidra-work/out/pp-forced-iocontrol.c`:

| Function | IOCTL | `DeviceIoControl` call shape | role / hook meaning |
|---|---|---|---|
| **`FUN_0052ce40`** | **`0x220038`** | `(h, 0x220038, inBuf, nIn, NULL, 0, &ret, NULL)` | **SEND** — the reset/command write (no out-buffer) |
| **`FUN_0052cab0`** | **`0x22003c`** | `(h, 0x22003c, inBuf, nIn, outBuf, 5000, &ret, NULL)` | **RECV** — counter/EEPROM read (out-buffer 5000 B) |
| `FUN_0052d110` | `0x220034` | `(h, 0x220034, inBuf, nIn, outBuf, 5000, …)` | read variant |
| `FUN_0052d4f0` | `0x220030` | `(h, 0x220030, inBuf, nIn, outBuf, 5000, …)` | read variant |
| `FUN_0052dae0` | `0x220034` | enumerate (`SetupDiGetClassDevsW`/`…EnumDeviceInterfaces`) + open + probe | **device discovery** (only caller of the SetupDi pair) |

Handle open (shared by all five):
```c
CreateFileW(devicePath, 0xC0000000 /*GENERIC_READ|WRITE*/, 3 /*FILE_SHARE_RW*/,
            NULL, 3 /*OPEN_EXISTING*/, 0xA0000000 /*OVERLAPPED|NO_BUFFERING*/, NULL)
```

**Does it build a USB SETUP packet?** **No.** None of the five primitives assemble
`bmRequestType/bRequest/wValue/wIndex`. They take a 3-word descriptor
`{buf_ptr, alloc_size, byte_count}`; the **`[cmd][arg][value]` application frame is
built upstream** (see §4) and, for Canon, **encrypted by a "functor"** before the
IOCTL. The pipe (bulk-OUT vs control-IN) is selected inside the closed
usbscan/usbprint minidriver — invisible here, settled empirically in
`canon-servicemode-transport-research.md` (SEND = bulk-OUT EP 0x01, RECV reply over
control on the real `12fe` service device).

**Hook recipe:** breakpoint/trace `KERNEL32!DeviceIoControl`; filter on
`dwIoControlCode ∈ {0x220038, 0x22003c, 0x220034, 0x220030}`; dump `lpInBuffer`
(the SEND frame, already functor-encrypted) and `lpOutBuffer` (the RECV reply). The
caller return address discriminates which primitive (`0x0052ce40` = the reset SEND).

---

## 2. Local vs cloud — the make-or-break, answered statically

**The reset button → Canon path is `Core::ActionCanonDeviceClearCounters`
(`FUN_0043fbc0`).** Decompiling it and walking the call graph gives the exact
ordering (line numbers from the tracked decompile `/tmp/pp-action.txt`,
reproducible via `ghidra/wicreset_decomp.py CMR_EAS=0043fbc0`):

```
L377  cVar9 = FUN_0051d7d0()           // RemoteControl::RESET_GUID  — device id/registration (cloud)
L405  local_2d9 = FUN_0047b780(...)    // LOCAL key router/format check (16-char, mode dispatch)
L567  cVar9 = FUN_0051c700()           // RemoteControl::QUERY_KEYS  — CLOUD key validation
L568  if (cVar9 != '\x01') goto error  // <-- pure BOOLEAN gate; abort if not 1
L578  if (local_2d9 != '\x01') ...error
L592  iVar11 = FUN_004ecae0()          // PrinterCanonSTD::clearCounters — LOCAL USB reset (NO server arg)
L700  cVar9 = FUN_0051da40(...)        // RemoteControl::RESET_DATA  — post-reset redemption report (cloud)
```

**Evidence the device bytes are NOT cloud-derived:**

- **`clearCounters` (`0x004ecae0`) and its whole subtree are net-free** (call-graph
  BFS: `subtree=721, no-net`; the same BFS flags the *parent* `0x0043fbc0` as
  net-bearing). The reset write is built and emitted with no socket in scope.
- **`clearCounters` is called as `iVar11 = FUN_004ecae0()`** — it receives only the
  implicit `this`; **no buffer/token from `QUERY_KEYS` is threaded into it.** The
  cloud call's only product consumed by the orchestrator is the `char` boolean
  `cVar9`.
- Inside `clearCounters`: `cVar5 = FUN_004e9d50(...)` (`action_is_permitted`) →
  proceed only if `==1`; then `FUN_004ec120(...)`
  (`service_perform_command_common`) does the per-counter SEND. `action_is_permitted`
  (`0x004e9d50`) is itself **purely local** — it parses a `;`/`:`-delimited device
  **capability** string and string-compares the requested action; **no socket**.
- The command bytes are produced locally by the **encryption functor**
  (`functor_encryption_003` @ `0x004e8410`, *"Command buffer is too small."*) and
  `service_send_buffer` (*"Encryption method does not have functor index."*) — a
  local transform over a local template buffer (§4), not a server payload.

**The cloud's role** (the `RemoteControl::` RPC family — all funnel through the
single dispatcher `RemoteControl::DO_MESSAGE` = `FUN_0051c140`):
`QUERY_KEYS`/`QUERY_STAT`/`QUERY_ECHO` (validate key, check entitlement),
`RESET_GUID`/`BUILD_GUID` (per-device identity), `RESET_DATA`/`BUILD_DATA`
(report/log the burn). The single-use semantics are **server-side**
(string: *"This key has been already used. Please purchase and use a new key."*;
*"Trial key can only be used ONCE for each printer."*). No WIC server **hostname**
appears in plaintext — the endpoint is assembled at runtime
(`RemoteControl::BUILD_GUID`/`BUILD_DATA`), consistent with the obfuscated
cloud client; the verdict does not depend on the hostname.

**Verdict:** **locally replayable.** The server **authorizes** (boolean) and
**accounts** (post-hoc burn report) for the reset; it does **not** sign, nonce, or
supply the device-bound bytes. A native tool that already knows the correct
`[cmd][arg][value]` + functor transform can perform the reset **without** the cloud
(the very reason the offline literals are the remaining unknown, not the protocol
shape). The HTTP stack is **statically-linked libcurl** (curl cookie/HSTS/alt-svc
markers; `WS2_32`+`WSOCK32` imported **by ordinal**; `CRYPT32` cert-chain +
`PFXImportCertStore` for TLS; `BCRYPT!BCryptGenRandom`) — which is why no named
`connect`/`send`/WinHTTP import exists and the sockets sit under curl ordinals.

---

## 3. Key handling

- **Local format pre-check:** `FUN_0047b780` (reached at L405 of the orchestrator)
  is the **key router** — it dispatches on mode tokens (`check_basic`,
  `waste_epson`, `trial_epson`, …) and routes to per-mode handlers
  (`FUN_0047c0b0`/`0047c800`/`0047c470`, the same functions that own the
  *"Enter reset key here."* UI strings). The literal rule is local:
  **"Valid key must contain 16 characters."** The magic word **`trial`** is matched
  locally and routes to the trial path — but the UI explicitly states
  *"Unfortunately, trial reset is not supported for CANON devices, please purchase
  and use a reset key."*, so for G6020 the real (purchased) key path is taken.
- **Entitlement is server-side:** the 16-char key is validated against the cloud via
  **`RemoteControl::QUERY_KEYS` (`0x0051c700`)**, which returns only a boolean
  status (no device bytes). Single-use redemption state lives on the server
  (*"already used"*).
- **Does the key value influence the device-bound bytes?** **No.** The key gates
  the UI/flow (boolean) and is burned server-side; it is **not** an input to the
  command frame or the encryption functor. `clearCounters` builds identical bytes
  regardless of *which* valid key unlocked it. (Local symmetric crypto —
  `ADVAPI32` `CryptImportKey`/`CryptEncrypt`/`CryptHashData`,
  `CryptStringToBinaryW` — is used for the curl/TLS + key-blob handling, not for
  per-reset device-byte derivation.)

---

## 4. Canon vs Epson dispatch (correcting the prior pass)

The prior pass decompiled `service.sendcmd`/`service.readcmd`
(`FUN_004f5820`/`FUN_004f4c40`) and correctly later reclassified them as the
**Epson** builder (they prepend `@BDC PS`/`@BDC ST` Epson remote-mode headers and
have 0 direct callers → Epson virtual class). **This pass locates the Canon class.**

The **`PrinterCanonSTD`** virtual class is the Canon sender. Resolved
method→address (via `__FUNCTION__` string xrefs, `ghidra/wicreset_canon.py`):

| `PrinterCanonSTD::` method | addr | role |
|---|---|---|
| `clearCounters` | `0x004ecae0` | **the absorber/waste reset** (per-counter loop over `functions.waste`) |
| `action_is_permitted` | `0x004e9d50` | local capability gate (string-compare, no net) |
| `service_perform_command_common` | `0x004ec120` | the reset SEND driver (calls the gate then sends) |
| `service_send_buffer` | `0x004ea540` | builds+**encrypts** the command, hands to SEND IOCTL |
| `service_read_buffer` | `0x004ea9c0` | the RECV path |
| `execute_set_command` / `execute_get_command` | `0x004ea540` / `0x004ea9c0` | set/get wrappers |
| `execute_set_session` | `0x004eb430` | open maintenance session (`commands.set_session`) |
| **`functor_encryption_003`** | `0x004e8410` | **Canon command-buffer crypto transform** (the `EncCommService` analogue) |
| `execute_one_command` | `0x004e89c0` | single-command exec |
| Action wrappers | `ActionCanonDeviceClearCounters` `0x0043fbc0`, `…QueryFeatures` `0x00440d22`, `…TestHardLimit` `0x0043f6c0` | orchestrators (own the cloud calls) |

`service_send_buffer` (`0x004ea540`) is the Canon byte-assembly choke point: it
appends the command/value buffers (`FUN_004d2510`), looks up the **`"functor"`
index from the per-model template**, applies the encryption functor, then sends.
Errors: *"Encryption method does not have functor index."* /
*"Could not send printer command. Ecnryption functor call error."* So the Canon
reset bytes are **template + functor-encrypted, assembled locally** — they do
**carry** the (encrypted) absorber command, but the literal `idx/op` for G6020 is
**template data**, not inline code, and **no `G6000`/`G6020` strings exist anywhere
in the image** (re-confirmed). The literals come from the per-model template
(runtime-resolved) → recover them from the **T4 usbmon capture** (this map) or the
**Service Tool offline oracle** (`canon-tool-ghidra-notes.md` Finding E).

---

## 5. Correlation table — expected dynamic event ↔ static function

Pre-stages the keyed capture: each row says what to look for live and which static
function produced it.

| # | Dynamic event (strace ioctl / usbmon URB / Frida) | Static function (addr) | Notes / what to extract |
|---|---|---|---|
| 1 | TLS/HTTPS to WIC server at key entry (`connect`/`send`/`recv` under curl ordinals; URB to no USB device) | `RemoteControl::QUERY_KEYS` `0x0051c700` → `DO_MESSAGE` `0x0051c140` | **boolean** result only; capture request/response to confirm it carries **no device bytes** (just key OK/used) |
| 2 | Earlier HTTPS round-trip (device GUID) | `RemoteControl::RESET_GUID` `0x0051d7d0` / `BUILD_GUID` | per-device identity registration; pre-reset |
| 3 | `CreateFileW(\\?\usb…)` + `SetupDi*` enumerate | `FUN_0052dae0` (+ `0x220034` probe) | device discovery; handle cached at `this+0x24` |
| 4 | `DeviceIoControl(h, 0x22003c, …, out 5000)` — RECV | `FUN_0052cab0` ← `service_read_buffer` `0x004ea9c0` | counter/EEPROM read; **SEND-primed** (see transport doc) |
| 5 | `ioctl`/`DeviceIoControl(h, 0x220038, in, →NULL)` — **SEND (the reset write)** | **`FUN_0052ce40`** ← `service_send_buffer` `0x004ea540` ← `service_perform_command_common` `0x004ec120` ← **`clearCounters` `0x004ecae0`** | **the reset.** `lpInBuffer` = functor-**encrypted** `[cmd][arg][value]`; capture to recover the on-wire bytes for the G6020 template |
| 6 | (in-process, no syscall) command-buffer crypto just before #5 | `functor_encryption_003` `0x004e8410` | Frida-hook here to grab the **plaintext** frame pre-encryption (cleaner than wire) |
| 7 | (in-process) local gate before #5, no I/O | `action_is_permitted` `0x004e9d50` | capability string compare; returns char==1 |
| 8 | HTTPS to WIC server **after** the USB SEND | `RemoteControl::RESET_DATA` `0x0051da40` | post-reset **burn/redemption report**; confirms ordering reset-then-report |

**Triangulation anchor:** if the live trace shows the order **2/1 (cloud) → 5
(USB SEND) → 8 (cloud report)** with the SEND `lpInBuffer` **independent of the
QUERY_KEYS response body**, the cloud-gate-not-cloud-source verdict is confirmed on
the wire. The single most valuable Frida hook is **#6** (`0x004e8410`) — it yields
the **decrypted** G6020 reset frame directly, sidestepping the functor crypto on the
wire.

---

## 6. Confidence + residual unknowns

- **High:** USB transport = 5 `DeviceIoControl` primitives (`0x220038` SEND /
  `0x22003c` RECV / `0x220034`/`0x220030` read), `CreateFileW` handle, SetupDi
  enumeration, **no USB SETUP packet built**; the Canon class is `PrinterCanonSTD`
  with a local encryption **functor**; the reset is **locally constructed** and
  **boolean-gated** by the cloud key check, **not** cloud-derived (call-graph BFS:
  `clearCounters` subtree net-free; cloud calls only in the Action parent, key
  result consumed as a `char` boolean, no server data threaded into the device path).
- **Medium:** that `QUERY_KEYS`/`RESET_DATA` carry **no** device-affecting payload
  — strongly implied by the data-flow (clearCounters takes no server arg) but the
  request/response **bodies** are best confirmed by capturing #1/#8 live (they are
  TLS, so capture in-process via the curl hook or pre-TLS buffer).
- **Residual (recovered by the capture this map pre-stages):** the literal G6020
  `idx/op` template values + the exact `functor_encryption_003` transform output —
  these are runtime template **data**, not in the `.exe` as constants (no
  `G6000/G6020` strings). Hook #6 or wire-capture #5 yields them; cross-check
  against the Service Tool group-7 absorber payload `[00,03,flags,03,idx]`.

**Lane boundaries respected:** this file does not touch the Linux-rig docs
(`wicreset-wine-linux-rig.md`, `…-linux-instrumentation.md`,
`…-capture-analysis-pipeline.md`, `…-linux-capture-RUNBOOK.md`).
