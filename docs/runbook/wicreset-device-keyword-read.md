# Native device-keyword read — `commands.get_keyword` over Linux libusb (Lane B)

**Date:** 2026-06-01 · **Host:** mbp-13 (Rocky 10.1) · **Device:** `04a9:12fe`
(G6020 in **service mode**, Bus 001 Addr 046), iface0 class 0x07/sub 0x01/proto
0x02 (printer, bidirectional), **EP 0x01 OUT BULK / 0x82 IN BULK**, both 512 B.
**Result: the get_keyword TRANSPORT was replicated natively, but the live device
returns ZERO bytes to every maintenance read** — the keyword could **not** be
read, because the firmware gates all maintenance RECVs behind a session-open the
naive libusb path does not satisfy (same wall as
`live-handshake-experiment-2026-05-31.md`, now confirmed for the keyword path
specifically and explained from the decompilation). **Non-destructive: STA
stayed `10`, port-status `0x18`, device left in service mode with usblp
rebound.** No `0x85`/clear/reset write was ever issued.

usbmon evidence: `captures/live/keyword-read-attempt-20260601-003850.txt`.

---

## TL;DR

1. **What `commands.get_keyword` actually is on the wire (RECOVERED from the
   .exe):** it is **NOT** a dedicated class/vendor control transfer with fixed
   `bmRequestType/bRequest/wValue/wIndex`. It is an in-band **SEND-primed read**:
   the app builds a `[prefix…][payload]` frame from the **runtime model template**
   (`commands.get_keyword` node → `prefix`/`action` fields), **functor-encrypts**
   it, hands it to the Canon device object's vtable I/O, which on Windows is
   `DeviceIoControl(0x220038)` SEND / `DeviceIoControl(0x22003c)` RECV. On Linux
   this maps to **bulk-OUT EP 0x01 (the SEND/prime) then a read of the reply**
   (≈20 bytes; the keyword buffer cap is `0x14`).
2. **The command byte is genuinely NOT in the binary** — it is a row in the
   cloud-downloaded/decrypted model template (`FUN_00522ac0`/`FUN_00802ac0`
   dotted-path lookups; `execute_one_command` reads `action` + `prefix` from the
   node). There are no `get_keyword` command-byte literals, no `G6020` strings,
   no inline JSON. Confirmed again this pass.
3. **The native read hits the known Lane-B wall:** every candidate prime
   (`0x86/0x80/0x84/0x83/0x87/0x88/0x8a/0x8c`, with/without an `0x81`
   session-open prime, single-shot and 8× polled) is **ACKed on bulk-OUT** and
   the subsequent **bulk-IN EP 0x82 returns 0 bytes**, every time. A vendor
   control-IN scan (`0xC0`/`0xC1`, bReq `0x00..0x11`) all **STALL**. Only the
   standard printer-class control-INs reply (`0xA1/0x00` GET_DEVICE_ID 120 B;
   `0xA1/0x01` GET_PORT_STATUS `0x18`). So the keyword is **not** retrievable
   without the real, functor-encrypted `set_session` frame whose bytes live only
   in the runtime template.

---

## 1. `commands.get_keyword` transport, decompiled (RECOVERED)

Read-only PyGhidra against the saved DB (`project-full/wicreset-pp-full`,
script `ghidra/wicreset_keyword_extract.py`, raw `/tmp/pp-keyword-extract.txt`).

- **String `commands.get_keyword` @ `0x0098695c` is referenced from exactly one
  function: `FUN_004eb430` (from `0x004eb610`)** — the function whose
  LoggerStrings are `PrinterCanonSTD::service_perform_command_vector` /
  `PrinterCanonSTD::execute_get_keyword`. So `FUN_004eb430` is
  **`execute_get_keyword`** (the prior map's "execute_set_session" label was an
  approximation — this single function runs the whole session+keyword vector):

  ```c
  // FUN_004eb430  (verbatim-trimmed)
  FUN_00429f00("commands.set_session");                 // pull set_session node
  local_149 = FUN_004e8e40(&local_164, &local_2c);      // execute set_session START
  ...  Logger "execute_set_session"  "START."
  FUN_00429f00("commands.get_keyword");                 // pull get_keyword node
  local_149 = FUN_004e8e40(&local_158, &local_2c);      // execute get_keyword (the RECV)
  ...  Logger "execute_get_keyword"
  if (local_150 != 0) {                                 // got keyword bytes
      FUN_00447560(&local_1bc, "encoders");             // build session encoder
      ... FUN_004e72b0(...)  // functor_initialization: XOR keyword into encoder
  }
  ```

- **`FUN_004e8e40` → `FUN_004e89c0` (`execute_one_command`)** is the per-command
  frame builder. It reads the command node's **`action`** and **`prefix`**
  template fields (`FUN_00522ac0("action")`, `FUN_00522ac0("prefix")`), prepends
  `prefix` to the payload, classifies the command type against the literal
  `"VENDOR"`, and dispatches to the Canon device object's vtable:

  ```c
  iVar5 = FUN_00522ac0("action");        // template field -> selects SEND vs RECV
  iVar5 = FUN_00522ac0("prefix");        // template field -> the command byte(s)
  FUN_004d2510(local_c0, *param_2, ...); // concat prefix + payload into the frame
  FUN_00802ac0("VENDOR", 0);             // command-type tag
  if (action == 7)                       // local_44 == 0x700000000
      (**(vtable + 0x18))(&buf,&reply);  // do_send_vendor  -> 0x220038, reply read back
  else
      (**(vtable + 0x1c))(&buf,&reply);  // do_read_vendor  -> 0x22003c (pure RECV)
  ```

  The vtable slots resolve to the IO primitives **`FUN_0052ce40`
  (`DeviceIoControl(handle,0x220038,inBuf,nIn,NULL,0,…)` SEND)** and
  **`FUN_0052cab0` (`DeviceIoControl(handle,0x22003c,inBuf,nIn,outBuf,5000,…)`
  RECV)** — i.e. `USBPipe::do_send_vendor` / `do_read_vendor`. **No USB SETUP
  packet is assembled anywhere** (re-confirmed): the bulk/control pipe is the
  Windows minidriver's choice, invisible in the .exe.

- **`functor_initialization` (`FUN_004e72b0`)** consumes the keyword: it reads
  `keyword.index`/`keyword.codes` (str @ `0x00986534`/`0x0098656c`) and folds the
  **live device keyword** (the bytes get_keyword returns, capped at `local_80 =
  0x14` = 20) into the per-session XOR encoder
  (`out[i] = keyword_codes[keyword_index[i]] ^ device_keyword[i]`, 4 lanes; guard
  strings "Keyword index/codes table size is lower than expected."). This is the
  device-binding — and the reason the keyword matters.

### Linux mapping of the transfer

| WICReset (Windows) | Linux libusb (this host, iface0 `12fe`) |
|---|---|
| `do_send_vendor` → `DeviceIoControl(0x220038, inBuf, nIn, NULL, 0)` | `dev.write(0x01, frame)` — **bulk-OUT EP 0x01** (the prime/SEND) |
| `do_read_vendor` → `DeviceIoControl(0x22003c, inBuf, nIn, outBuf, 5000)` | `dev.read(0x82, len)` — **bulk-IN EP 0x82** (the reply, ≤20 B for the keyword) |
| frame bytes = `prefix` + payload, **functor-encrypted** | same bytes would go OUT verbatim (we cannot build them — runtime template) |
| GET_DEVICE_ID identity (class) | `ctrl_transfer(0xA1,0x00,0,0,…)` — **works natively** |

So `commands.get_keyword` is **a bulk SEND-then-bulk-RECV**, not a standalone
control transfer. The keyword reply is a ≤20-byte bulk-IN read primed by the
encrypted get_keyword frame.

---

## 2. Native replication on the live `12fe` device (the read attempt)

Procedure (each step scp'd to `/tmp`, one `bash -lc` per call; reads + session
prime only):

1. `modprobe usbmon`; capture `/sys/kernel/debug/usb/usbmon/1u` (root, background).
2. Unbind usblp from iface0: `echo -n 1-1:1.0 > /sys/bus/usb/drivers/usblp/unbind`
   (sudo via the sops become password). Raw node `/dev/bus/usb/001/046` is
   `printstack`-group writable; libusb claims iface0 after the unbind +
   `detach_kernel_driver(0)`.
3. **Baseline (non-destructive):** `ctrl_transfer(0xA1,0x00,…)` GET_DEVICE_ID →
   `…STA:10;…` (120 B); `ctrl_transfer(0xA1,0x01,…)` GET_PORT_STATUS → `0x18`.
4. **get_keyword transport replicate:** for each candidate `[cmd][00][00]`,
   bulk-OUT EP 0x01, then bulk-IN EP 0x82 (len 20/64), single-shot **and** 8×
   polled with 0.15 s dwell; plus an `0x81 00 00 00` session-open prime first;
   plus a vendor control-IN scan (`0xC0`/`0xC1`, bReq `0x00..0x11`, len 20/64).
5. Re-read GET_DEVICE_ID + GET_PORT_STATUS (state-after).
6. Rebind usblp: `echo -n 1-1:1.0 > /sys/bus/usb/drivers/usblp/bind`. Stop usbmon.

### Result (usbmon-confirmed)

```
S Bo:1:046:1 4 = 81000000     C Bo:1:046:1 0 4 >     # set_session prime ACKed
S Bi:1:046:2 64 <             C Bi:1:046:2 0 0        # bulk-IN -> 0 BYTES
S Bo:1:046:1 3 = 860000       C Bo:1:046:1 0 3 >     # get_keyword cand 0x86 ACKed
S Bi:1:046:2 20 <            C Bi:1:046:2 0 0         # bulk-IN -> 0 BYTES
  … identical for 0x80/0x84/0x83/0x87/0x88/0x8a/0x8c (single + polled) …
S Ci:1:046:0 a1 01 0000 0000 0001   C 0 1 = 18        # class port-status OK
S Ci:1:046:0 a1 00 0000 0000 0400   C 0 120 = 00784d4647…  # GET_DEVICE_ID OK
```

- **Every bulk-OUT prime completes (status 0, ACKed).**
- **Every bulk-IN read completes with `0 0` (zero bytes).**
- **Every vendor control-IN STALLs** (0 hits across `0xC0/0xC1` × bReq `0x00..0x11`).
- Only standard printer-class control-INs reply (GET_DEVICE_ID, GET_PORT_STATUS).

**Keyword bytes read: NONE.** The transport is correctly replicated (the device
ACKs the SEND/prime), but the keyword RECV returns nothing.

---

## 3. Why — and the boundary this nails down

The device **accepts the writes but will not return read data** in our session.
The decompilation explains it: `execute_get_keyword` first runs
`commands.set_session` **START**, and **every command frame — set_session
included — is built from the runtime template's `prefix`/`action` rows and
functor-encrypted**. Our bare `0x81…`/`0x86…` primers are not the real, encrypted
set_session frame, so the firmware silently accepts the bulk-OUT and treats the
session as un-opened → all maintenance RECVs return 0. This is the **same wall**
`live-handshake-experiment-2026-05-31.md` hit, now (a) shown to apply to the
keyword path specifically and (b) explained from the binary rather than guessed.

There is also a **bootstrap subtlety**: the keyword is read *before* it is known,
so the `set_session`/`get_keyword` frames cannot use the keyword-seeded keystream
— they use the template's static `keyword.index`/`keyword.codes` (and possibly a
non-keyed functor). But those bytes are **still template data**, absent from the
.exe, so we cannot synthesize them here.

**Conclusion:** the live device keyword is **not statically derivable and not
recoverable by naive libusb**. It requires either (a) the exact encrypted
`set_session` + `get_keyword` frames from the runtime model template (cloud
download / decrypt), or (b) a **usbmon/USBPcap capture of one real WICReset (or
Service-Tool) keyword exchange** against this `12fe` device — the Lane-B wire
capture the prior runbooks already scoped as the necessary path. The capture's
get_keyword RECV bytes (≤20 B) ARE the keyword; this doc gives the exact transfer
to anchor on and the `functor_initialization` consumer to validate it.

---

## 4. Non-destructive confirmation

| signal | before | after |
|---|---|---|
| `STA:` (GET_DEVICE_ID) | `10` | `10` (unchanged) |
| GET_PORT_STATUS byte | `0x18` | `0x18` (unchanged) |
| service mode (PID) | `04a9:12fe` | `04a9:12fe` (still service mode) |
| usblp / `/dev/usb/lp0` | bound | **rebound**, lp0 present |

No `0x85`/clear/reset/`set_command` write was issued (reads + session-open prime
only). No cloud key spend, no power-cycle. Device left exactly as found.

---

## 5. Reproduce

```bash
# on neo: helper scripts are scp'd to mbp-13:/tmp; sudo via the sops become pw.
# static RE (read-only Ghidra):
GHIDRA_INSTALL_DIR=<…>/ghidra-12.0.2/lib/ghidra \
CMR_PROJ=$PWD/.ghidra-work/project-full \
  .ghidra-work/.pgvenv12/bin/python ghidra/wicreset_keyword_extract.py
# live read (host): unbind usblp -> uv run pyusb kw_read.py -> rebind usblp,
#   usbmon -> captures/live/keyword-read-attempt-*.txt
```

Tracked: `ghidra/wicreset_keyword_extract.py`. Raw decompiles (gitignored):
`/tmp/pp-keyword-extract.txt`, `/tmp/pp-cmdexec.txt`, `/tmp/pp-framebuild.txt`.
