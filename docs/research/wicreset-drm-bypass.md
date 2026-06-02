# WICReset / PrinterPotty v5.95 — Cloud-DRM Bypass + Genuine-Frame Capture Plan

**Status:** synthesis of three independent Ghidra passes (cloud-gate, reset-emit,
cloud-usage). **Verdict: bypass is feasible and safe.** The WIC cloud gate is a
pure boolean entitlement check; the reset frames are built entirely locally from
the device-supplied session keyword + the embedded APP.BIN template. Forcing the
gate true makes WICReset emit valid, genuine reset URBs.

Binary: `printerpotty.exe`, 32-bit PE, image base `0x00400000`, ~7.48 MB,
sha256 `a199447db…564b3e8`. Ghidra 11.3.2 / 12.0.2 full analysis
(`/Users/jess/git/canon-megatank-reset/.ghidra-work/project-full/wicreset-pp-full`
on neo; project `/tmp/ppproj`, dumps `/tmp/pp-drm-*.txt`, `/tmp/pp-lane2-*.txt`,
`/tmp/pp-lane3-*.txt`). Prior passes:
[`wicreset-printerpotty-static-re.md`](wicreset-printerpotty-static-re.md),
[`wicreset-cloud-vs-local-template.md`](wicreset-cloud-vs-local-template.md),
[`sota-dynamic-instrumentation.md`](sota-dynamic-instrumentation.md).

Confirmed protocol (do not re-derive): usbprint IOCTL `0x220038` = VENDOR_SET
(`do_send_vendor` `FUN_0052ce40`), `0x22003c` = VENDOR_GET (`do_read_vendor`
`FUN_0052cab0`). Reset flow: `set_session(0x81)` → `get_keyword(0x82)` (device
returns 3-byte per-session keyword) → `set_command(0x85` select `10 07 7c)` →
`set_command(0x85` clear `0d 00 00)`. The **device** generates the keyword; the
cloud is not the keyword source.

---

## (a) Is bypass feasible?

**Yes.** The cloud gate licenses only — it does not supply any byte that flows
into the reset frame.

- `RemoteControl::QUERY_KEYS` (`FUN_0051c700`) sends message type 7 / expects
  reply 8 through `DO_MESSAGE` (`FUN_0051c140` → socket to `62.112.10.39:23457`),
  and collapses the entire reply to **one boolean**:
  ```c
  if (param_4 != 0) {
      local_e9[0] = '\0';
      if (1 < local_74)                       // response payload length
          FUN_008039a0(local_e9, local_7c+1, 1);   // memmove of exactly 1 byte
      *(bool *)param_4 = local_e9[0] != '\0';      // single bool to caller out-ptr
  }
  ```
  `local_e9` is never read again; the only other consumer of the reply is the
  `LoggerString` sink (`FUN_00447e70`), diagnostics only.
- The orchestrator `Core::ActionCanonDeviceClearCounters` (`FUN_0043fbc0`) calls
  `iVar11 = FUN_004ecae0()` (`clearCounters`) **with no argument** — no token,
  seed, or buffer from the cloud reply is threaded in. clearCounters and its
  entire subtree are **net-free** (call-graph BFS: subtree=721, no-net).
- `clearCounters` builds the reset bytes from the local template
  (`FUN_004edad0(…, "functions.waste")`) and the local functor cipher
  (`functor_encryption_003` `FUN_004e8410`: 2-byte header `0x1200` + len + cmd
  + 16 LCG-PRNG bytes `x=x*0x343fd+0x269ec3`, then template byte-substitution).
  Device bytes come from `get_keyword(0x82)` off the wire, not the cloud.
- `RESET_GUID` (`FUN_0051d7d0`, codes 3/4) is a pre-reset cloud gate;
  `RESET_DATA` (`FUN_0051da40`, codes 5/6) runs **after** the USB write and only
  uploads a burn report (its reply picks a log string). Neither feeds the frame.

So satisfying the boolean is sufficient. The live VM stall (loops on connect to
`62.112.10.39:23457`, never reaches `0x220038`) is purely the gate not completing
— `DO_MESSAGE`'s retry loop never sets success, `QUERY_KEYS` returns 0, and the
orchestrator aborts before `clearCounters`.

---

## (b) The EXACT Frida patch point

The decisive branch is two adjacent conditionals inside the orchestrator
`Core::ActionCanonDeviceClearCounters` (`FUN_0043fbc0`), verbatim from
`/tmp/pp-drm-disasm3.txt`:

```
00440543  CALL 0x0051c700            ; RemoteControl::QUERY_KEYS (cloud validate)
00440548  CMP  AL,0x1                ; AL = transport-success byte
0044054a  JZ   0x0044055c            ; <-- GATE 1  (74 10)   success -> continue
0044054c  PUSH [EBP-0x44]
0044054f  CALL 0x0080c626            ; failure cleanup
00440557  JMP  0x00440352            ; ABORT (common teardown)
0044055c  CMP  byte [EBP-0x2d9],0x1  ; valid-bit written by QUERY_KEYS out-ptr
00440563  JZ   0x004405c8            ; <-- GATE 2  (74 63)   both-OK -> proceed
00440565  ...                        ; error path ("Could not reset...waste counters")
...
004405ce  CALL 0x004ecae0            ; PrinterCanonSTD::clearCounters  (RESET EMIT, net-free)
004405d3  TEST EAX,EAX
004405d5  JNZ  0x00440610            ; -> per-waste-counter loop -> IOCTL 0x220038
```

Decompiled view (`/tmp/pp-drm-decomp.txt` L563–596) confirms `local_2d9` is
zeroed, then `cVar9 = FUN_0051c700()` (transport success in AL/`cVar9`, valid bit
written into `local_2d9`), gate 1 `if (cVar9 != 1) goto LAB_00440352`, gate 2
`if (local_2d9 != 1) goto error`, then `iVar11 = FUN_004ecae0()`.

**Patch: force both JZ → unconditional JMP (opcode `0x74` → `0xEB`, displacement
unchanged so the target is preserved).**

| VA (= file offset; base 0x400000) | Original | Patched | Effect |
|---|---|---|---|
| `0x0044054a` | `74 10` (JZ 0x44055c) | `EB 10` (JMP 0x44055c) | skip transport-success check |
| `0x00440563` | `74 63` (JZ 0x4405c8) | `EB 63` (JMP 0x4405c8) | skip valid-bit check |

Gate 1 alone is the minimum (skips the whole cloud path); gate 2 is
belt-and-suspenders for a test/trial key whose valid bit comes back 0. For a
purchased Canon key gate 2 already passes, but patch both to be deterministic in
the offline VM.

This proceeds to `clearCounters` regardless of `QUERY_KEYS` — the chosen path
because the clearCounters subtree is net-free and needs nothing from the cloud.
(Forcing `QUERY_KEYS` to return 1 internally — e.g. neutering its
`0x0051c871 JNZ 0x0051c90a` transport-fail bail — also works but is more
invasive; not preferred.)

### Frida snippet (x86, frida-inject-x86-16 v16.5.9 idioms)

```js
// pp-drm-bypass.js — frida -f "...\\printerpotty.exe" -l pp-drm-bypass.js
// (spawn, so the patch is in place before the Reset button is ever clicked)
'use strict';

const IMAGE_BASE = ptr('0x400000');                 // PE preferred base
const mod = Process.getModuleByName('printerpotty.exe');
const slide = mod.base.sub(IMAGE_BASE);             // 0 if no ASLR; nonzero if relocated

function va(addr) { return ptr(addr).add(slide); }  // map static VA -> live address

// Force JZ (0x74) -> JMP (0xEB), keep the rel8 displacement byte intact.
function jzToJmp(addr) {
  const p = va(addr);
  const op = p.readU8();
  if (op !== 0x74) { console.log(`[!] ${addr}: expected 0x74, got 0x${op.toString(16)} — ABORT`); return; }
  Memory.patchCode(p, 1, code => code.writeU8(0xEB));   // page-perms safe; flushes i-cache
  console.log(`[+] ${addr}: 74 -> EB (gate forced), disp=0x${p.add(1).readU8().toString(16)}`);
}

jzToJmp('0x44054a');   // GATE 1: QUERY_KEYS transport-success
jzToJmp('0x440563');   // GATE 2: QUERY_KEYS valid-bit (local_2d9)
console.log('[*] cloud gate neutralized; Reset will proceed straight to clearCounters');
```

Notes:
- Use `Memory.patchCode` (not a raw `writeU8`) so Frida handles W^X page perms and
  the instruction-cache flush on the 32-bit target.
- `slide` covers the (unlikely) relocated-image case; on a fresh non-ASLR run it is
  0 and `va(x) == x`.
- The `op !== 0x74` guard aborts loudly if the binary version drifts — these
  offsets are exact for this sha256 only.
- Equivalent `Interceptor.replace(va('0x51c700'), …)` of `QUERY_KEYS` to return 1
  is intentionally **not** used; the JZ patch is smaller-blast-radius and leaves
  the net client untouched.

---

## (c) Cloud-data risk verdict

**No cloud data reaches the reset frame — bypass is safe to produce genuine
frames.** Decompiled, not inferred:

1. `QUERY_KEYS` reply → exactly 1 byte → 1 bool (shown above). No buffer survives.
2. `clearCounters` is invoked with no cloud-derived argument; orchestrator
   consumes only the booleans `cVar9` and `local_2d9`.
3. The frame builder (`service_send_buffer` → `functor_encryption_003`) reads only
   the local template + LCG PRNG + the device keyword from `get_keyword(0x82)`.
4. `DO_MESSAGE` persists nothing to the Canon path; the only field it caches is
   `*(conn+0x24)=param_2[3]` (an RPC echo/session byte) which the reset path never
   reads.
5. `RESET_DATA` is post-write accounting only.

**Residual risk (single, low):** `QUERY_KEYS`/`RESET_DATA` bodies are TLS on the
wire, so the in-process decompile is the proof, not a wire capture. The empirical
confirmation is already built into the capture plan below: capturing the genuine
`set_session/get_keyword/set_command` URBs **after** the bypass, and observing that
the emitted bytes are byte-identical to the locally-derived G6020 template, closes
the loop. If — contrary to the decompile — any reset byte differed run-to-run with
the cloud reply, the IOCTL capture would expose it. (It will not: clearCounters is
net-free.)

---

## (d) Capture plan — genuine URBs off a patched WICReset

Goal: re-attach the real Canon (`12fe` VID:PID family) to the capture VM, run
WICReset with the cloud gate patched out, and record the genuine
`set_session(0x81)` / `get_keyword(0x82)` / `set_command(0x85)` frames at two
layers simultaneously: the **IOCTL layer** (Frida hook on `DeviceIoControl`, gives
plaintext in/out buffers + IOCTL code + ordering) and the **USB wire layer**
(host usbmon over the QEMU passthrough, Wireshark-decodable). Cross-correlate by
timestamp.

### 0. Device re-attach (capture VM)
- Re-attach the G6020 to the Win11 capture guest via QEMU USB passthrough
  (e1000e NIC + ntlm WinRM per the Win11-VM-capture-networking memo).
- Confirm the guest sees the printer and Windows bound **usbprint** (the minidriver
  path — kernel32!DeviceIoControl, not WinUSB). `pathByHandle` in the hook will
  show `\Device\…USB…12fe…` so we know the captured IOCTLs are the printer.

### 1. Host usbmon (wire ground truth)
On the QEMU host (mbp-13 or whichever box owns the physical bus):
```
sudo modprobe usbmon
# find the bus the printer is on:
lsusb            # note Bus NNN Device MMM for the Canon (04a9:.. 12fe family)
# capture that bus (usbmon<N> where N = bus number), filtered to the device addr:
sudo tshark -i usbmon<N> -w /tmp/g6020-reset-wire.pcapng
```
This pcap is directly usbmon-format and decodes the URBs (bRequest 0x81/0x82/0x85,
in/out payloads) in Wireshark.

### 2. Frida IOCTL hook (in-guest, plaintext buffers) + the bypass
Run WICReset **spawned** so the gate patch is in place before any Reset click, and
the IOCTL hook catches the first SEND:
```
frida -f "C:\Program Files (x86)\PrinterPotty\printerpotty.exe" ^
      -l pp-drm-bypass.js ^
      -l hook-devio.js ^
      -o C:\caps\g6020-reset-ioctl.log
```
`hook-devio.js` is Recipe A1 from
[`sota-dynamic-instrumentation.md`](sota-dynamic-instrumentation.md) (lines
124–160): it resolves the device path via `NtQueryObject`, and for every
`kernel32!DeviceIoControl` logs a pcap-correlatable timestamp, the IOCTL code,
and hexdumps the in-buffer (onEnter) and out-buffer (onLeave). Add a filter so the
log is grep-able:
```js
// in hook-devio.js onEnter, after computing this.ioctl:
this.isVendor = (this.ioctl === 0x220038 || this.ioctl === 0x22003c);
// tag VENDOR_SET / VENDOR_GET lines so set_session/get_keyword/set_command stand out
```
- `0x220038` (VENDOR_SET) in-buffer = `set_session(0x81)` and the two
  `set_command(0x85)` frames (select `10 07 7c`, clear `0d 00 00`), functor-encrypted.
- `0x22003c` (VENDOR_GET) out-buffer = the `get_keyword(0x82)` reply (3-byte
  device keyword) — captured **onLeave**. (Overlapped-I/O pitfall: if a call is
  pending at onLeave, the out-buffer fills later; the usbmon pcap is the backstop
  for those.)

### 3. Drive the reset
In the guest: open WICReset, enter the WIC key, click OK, click **Reset waste
counter(s)**. With the gate patched, execution no longer stalls on
`62.112.10.39:23457`; the orchestrator proceeds: `RESET_GUID`/`QUERY_KEYS` either
complete or are bypassed, then `clearCounters` runs and the IOCTL `0x220038`
SENDs fire. The Frida log shows the patch lines, then the VENDOR IOCTLs; usbmon
shows the matching URBs.

### 4. Cross-correlate + extract
- Align Frida log timestamps (`ts()` is seconds-since-attach) with usbmon frame
  times to pair each IOCTL with its URB.
- Extract from the IOCTL log: the exact `set_session(0x81)` body, the 3-byte
  keyword from the `get_keyword(0x82)` out-buffer, and both `set_command(0x85)`
  bodies (select/clear) in plaintext post-functor.
- Confirm-the-verdict step: re-run the local derivation
  ([`wicreset-g6020-reset-derived.md`](wicreset-g6020-reset-derived.md)) with the
  captured keyword and check the derived `set_command` bytes match the captured
  ones byte-for-byte. Match = cloud-data risk closed empirically; the frames are
  fully local.

### Quick survey (optional, before the real run)
```
frida-trace -i "DeviceIoControl" -i "CreateFile*" -f printerpotty.exe
```
confirms the API families fire and the device handle binds, before committing to
the full simultaneous capture.

---

## Address summary (one place)

| What | Symbol / FUN | VA | Note |
|---|---|---|---|
| Reset orchestrator | `Core::ActionCanonDeviceClearCounters` | `0x0043fbc0` | owns all cloud calls |
| Cloud key validate | `RemoteControl::QUERY_KEYS` | `0x0051c700` | reply → 1 bool |
| Net round-trip / stall | `RemoteControl::DO_MESSAGE` | `0x0051c140` | retry loop → 62.112.10.39:23457 |
| Net-client ctor (cached) | — | `0x0064d950` | global `DAT_00a45db4` |
| **GATE 1** (patch) | — | `0x0044054a` | `74 10` → `EB 10` |
| **GATE 2** (patch) | — | `0x00440563` | `74 63` → `EB 63` |
| Reset emit | `PrinterCanonSTD::clearCounters` | `0x004ecae0` | net-free; called no-arg @0x4405ce |
| Frame builder / cipher | `functor_encryption_003` | `0x004e8410` | local LCG + template |
| SEND IOCTL | `do_send_vendor` | `0x0052ce40` | `DeviceIoControl(…,0x220038,…)` |
| RECV IOCTL | `do_read_vendor` | `0x0052cab0` | `DeviceIoControl(…,0x22003c,…)` |
| Pre-reset cloud gate | `RemoteControl::RESET_GUID` | `0x0051d7d0` | codes 3/4 |
| Post-reset report | `RemoteControl::RESET_DATA` | `0x0051da40` | codes 5/6, after write |

---

## ADVERSARIAL CRITIQUE (2026-06-01, independent verification)

Verdict: **CONDITIONAL GO — the plan is correct on cloud-independence and on the
two named patch bytes, but it is INCOMPLETE: it omits a THIRD upstream cloud gate
(`RESET_GUID`) that is on the mandatory path to the emit and will stall the same
way in the VM. Patching only the two QUERY_KEYS gates is NOT sufficient.**

All claims below were re-derived from the real binary
(`/home/jess/canon-tool-staging/wicreset/printerpotty.exe`,
sha256 `a199447db…564b3e8` — confirmed identical to the plan's hash) and the
decompile `/tmp/pp-drm-decomp.txt` + raw `.text` bytes.

### 1. The named patch point is a REAL gate — bytes verified
- `0x0044054a`: bytes `74 10` = `JZ 0x44055c`. Patch `EB 10` valid (same target).
- `0x00440563`: bytes `74 63` = `JZ 0x4405c8`. Patch `EB 63` valid (same target).
- `0x00440543`: `E8 B8 C1 0D 00` = `CALL 0x51c700` (QUERY_KEYS); `3C 01` = `CMP AL,1`.
  All exactly as the plan states. These are genuine gates guarding
  `clearCounters` at `0x4405ce`; not decoys, not no-ops.

### 2. No frame byte traces to cloud data — CONFIRMED
`QUERY_KEYS` (`FUN_0051c700`) collapses the entire reply to one bool
(`*(bool*)param_4 = local_e9[0] != '\0'`, decompile L1269–1274); `clearCounters`
is called no-arg (L596); the device keyword comes from `get_keyword(0x82)` and the
frame from the local functor — all matches the plan. The live capture corroborates
this independently: the `get_version` (`0x22003c`, prime `8a 00 00`) reply
`e7 90 c1 84 8b a0 47 87 3c 2d 47 41 b0 d8 d6 d4 b3 57 be eb` was DECRYPTED locally
to recognize "Canon G6000 series" with **zero** cloud round-trip in scope. So
forcing the gate true yields genuine, locally-derived frames. **This part of the
plan holds.**

### 3. THE GAP — a third, upstream cloud gate the plan does not patch
`Core::ActionCanonDeviceClearCounters` reaches `clearCounters` only through this
ordered chain inside the same proceed-branch (decompile L329–596):

```
  0x440126  CALL 0x0051d7d0        ; RESET_GUID  (CLOUD round-trip, DO_MESSAGE msg 3/4)
  0x44012b  CMP  AL,1
  0x44012d  JZ   0x440178          ; <-- GATE 0  (74 49)  fail -> LAB_0044012f teardown -> return
  ... local_2d9 / FUN_0047b780 key-router (local) ...
  0x440543  CALL 0x0051c700        ; QUERY_KEYS  (CLOUD round-trip, DO_MESSAGE msg 7/8)
  0x44054a  JZ   0x44055c          ; <-- GATE 1  (74 10)  [plan patches this]
  0x440563  JZ   0x4405c8          ; <-- GATE 2  (74 63)  [plan patches this]
  0x4405ce  CALL 0x004ecae0        ; clearCounters (EMIT)
```

`RESET_GUID` (`FUN_0051d7d0`) runs `cVar2 = FUN_0051c140(&local_8c,3,4)` —
the SAME `DO_MESSAGE` dispatcher, the SAME socket to `62.112.10.39:23457`, the
SAME retry loop that stalls. Its gate at `0x44012d` (`74 49 -> EB 49`, target
`0x440178`) is executed BEFORE QUERY_KEYS and aborts the whole reset
(`goto LAB_0044012f`) if the cloud round-trip does not return `AL==1`. The plan's
two patches sit downstream of it and are never reached if RESET_GUID hangs.

The doc's own prose (§3, "RESET_GUID/QUERY_KEYS either complete or are bypassed")
papers over this: the two prescribed `jzToJmp` calls bypass QUERY_KEYS only;
RESET_GUID is left to "complete" — but the entire premise is that the cloud does
NOT complete in the VM. **KEYED RESET ATTEMPT 2 (2026-06-01 16:50Z) froze the
Frida log at `connect` with `0x220038` count = 0; that `connect` could be the
RESET_GUID call, in which case the plan's patches do nothing.**

**REQUIRED FIX: add a third patch `0x44012d: 74 49 -> EB 49`**
(`jzToJmp('0x44012d')` in `pp-drm-bypass.js`, with the same `0x74` guard). With
all three JZ→JMP, execution skips all three cloud round-trips and falls straight
through to `clearCounters`. (RESET_DATA at `0x0051da40` is post-emit and harmless.)

### 4. Secondary corrections / residual risks
- **Doc error:** "VA (= file offset; base 0x400000)" is FALSE. `.text` has
  VirtualAddress `0x1000` / RawPtr `0x400`, so file offset = VA − 0x400000 − 0xC00
  (e.g. VA `0x44054a` → file offset `0x3f94a`). Irrelevant to the Frida runtime
  patch (which uses live VAs), but a STATIC file patch using VA-as-offset would
  corrupt the wrong bytes. Use Frida, not a hex-edit at those offsets.
- **ASLR is ENABLED** (`DllCharacteristics=0x8140`, DYNAMIC_BASE set), contra the
  plan's "0 if non-ASLR" aside. The Frida `slide = mod.base.sub(IMAGE_BASE)`
  handles this correctly, so the runtime patch is fine — but do NOT assume a zero
  slide.
- **No app-level anti-tamper found.** `IsDebuggerPresent` / `VirtualProtect` /
  `CRC`/`integrity` strings all trace to the statically-linked CRT/libcurl/zlib;
  `OptionalHeader.CheckSum = 0` (not enforced); 5 normal sections, not packed. No
  self-checksum that would detect `Memory.patchCode`.
- **Empirical confirmation still required** that the frozen `connect` is the only
  blocker and that, once all three gates are forced, `0x220038` actually fires —
  the in-process decompile proves cloud-independence, but `QUERY_KEYS`/`RESET_GUID`
  bodies are TLS on the wire, so the capture plan (usbmon + IOCTL trace) remains
  the belt-and-suspenders proof.

### Bottom line
GO **only with the third patch added** (`0x44012d 74→EB`) alongside the two named
ones, and with the existing `0x220034`+`0x22003c` 5000→4096 clamps still loaded
(those are unrelated VM page-cap fixes that must remain). With all three JZ→JMP
patches the emit is cloud-independent and the frames are genuine. As written
(two patches only), the plan can stall at RESET_GUID and never emit.
