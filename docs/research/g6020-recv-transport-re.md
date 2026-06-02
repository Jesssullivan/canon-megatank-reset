# G6020 RECV transport + functor-2/3 cipher re-confirm (Lane B)

**Date:** 2026-06-01 · **Binary:** `printerpotty.exe` (WICReset, 7.48 MB app),
`sha256 a199447db7d9237d95b11456db6e6d9898ab2eb2cae7918acaa1c700a564b3e8`.
Project: `.ghidra-work/project-full/wicreset-pp-full` (read-only).
Decompiles cited: `.ghidra-work/out/pp-forced-iocontrol.c` (IOCTL primitives),
`/tmp/pp-helpers.txt` (FUN_004e76c0 functor_implementation, FUN_004e8e40),
`/tmp/pp-cipher2.txt` (FUN_004e72b0 functor_initialization, FUN_0045f180,
FUN_0045ee10), `/tmp/pp-corechain.txt` (FUN_004e8410 functor_encryption_003,
FUN_004ea540 service_send_buffer, FUN_004ea9c0 service_read_buffer,
FUN_004eb430 set_session/get_keyword, FUN_004e89c0 execute_one_command).
Template data: `/tmp/appbin_out/devices.xml` (CANON-IPL spec).

---

## TL;DR

1. **RECV transport (Q1): the reply read is realized as a SINGLE combined
   `DeviceIoControl(0x22003c)` that both sends the (enciphered) prefix frame and
   reads the reply into a 5000-byte out-buffer — not a separate bulk-IN, not a
   USB control-IN built in the .exe.** `get_keyword`/`do_read_vendor`
   (`FUN_0052cab0`) feeds `lpInBuffer = param_2[0]` (the SEND-primed `0x82` frame,
   size `param_2[2]`) AND `lpOutBuffer = local_f8` (5000 B) to **one** IOCTL. The
   SEND primitive (`FUN_0052ce40`, `0x220038`) passes `lpOutBuffer = NULL, 0`. So
   the bulk-IN/control-IN pipe choice lives entirely inside the closed
   usbscan/usbprint minidriver: the app hands `0x22003c` one in-frame + one
   out-buffer and the minidriver does OUT-then-IN. The native lane's
   "bulk-IN 0x82 returns nothing, control-IN works" is therefore expected — the
   reply is *not* a free-standing bulk-IN; it is the IN half of the `0x22003c`
   round-trip, which the Windows minidriver maps to whatever pipe the `12fe`
   service interface exposes (empirically control-IN).

2. **Cipher (Q2): NOT byte-faithful. `scripts/canon_sr5_cipher.py` mis-models
   functor-2 and functor-3 in three structural ways, so its 20-byte
   `set_session = ed f4 75 21 …` is WRONG (wrong content AND wrong length).** The
   real functor output is **4 bytes** (a keystream transform of the *bound
   keyword*), not a 20-byte transform of the envelope; the prefix is carried in
   the clear by `execute_one_command`; and functor-3's `<special>` overwrite is
   omitted. See §2.

3. **VERDICT: cipher bug (multiple). Fix the cipher before any wire comparison.**
   The transport finding (combined `0x22003c`) is solid and independently useful
   to Lane A, but our enciphered bytes cannot be trusted until functor-2/3 are
   re-derived against the buffer wiring below.

---

## 1. RECV transport — do_read_vendor `FUN_0052cab0` (IOCTL 0x22003c)

Decompile (`pp-forced-iocontrol.c:1137-1264`). The handle at `this+0x24` is the
cached `CreateFileW(\\?\usb…, GENERIC_RW, SHARE_RW, OPEN_EXISTING,
OVERLAPPED|NO_BUFFERING)`. The descriptor `param_2` is the 3-word
`{*param_2 = buf_ptr, param_2[1] = alloc, param_2[2] = byte_count}`:

```c
lpInBuffer = (LPVOID)*param_2;            // the SEND-primed prefix frame
local_ec   = param_2[2];                  // its byte count (nIn)
...                                        // local_f8 = out-buffer, FUN_004d2510(0,local_e8,1,5000)
BVar4 = DeviceIoControl(*(HANDLE*)(param_1+0x24), 0x22003c,
                        lpInBuffer, local_ec,      // IN  : the prefix frame
                        local_f8,    5000,         // OUT : the reply (≤5000 B)
                        &local_fc, NULL);          // (single call)
// on success: param_2[2]=0; FUN_004d2510(0,local_f8,local_fc,1)  -> reply copied back
// error string: "USBPipe::do_read_vendor" / "DeviceIoControl:"
```

Compare do_send_vendor `FUN_0052ce40` (`pp-forced-iocontrol.c:1558-1660`):

```c
lpInBuffer   = (LPVOID)*param_2;
nInBufferSize= param_2[2];
BVar3 = DeviceIoControl(*(HANDLE*)(param_1+0x24), 0x220038,
                        lpInBuffer, nInBufferSize,
                        (LPVOID)0x0, 0,            // OUT : NULL,0 — no reply
                        &local_144, NULL);
// error string: "USBPipe::do_send_vendor"
```

**Shape of the get_keyword send/recv (Q "sendPrimedShape"):** it is **one
combined IOCTL**, not send-then-separate-read. `get_keyword` is dispatched as a
`get` action through `execute_one_command` (`FUN_004e89c0`,
`pp-corechain.txt:1715`). The action discriminant is read from the template
(`FUN_00522ac0("action")`); for `get` (action ≠ 7) it takes the
`local_ad == false → true` branch and calls **vtable+0x18** on the pipe object at
`this+0x18`:

```c
// execute_one_command, the GET branch (pp-corechain.txt:1866-1887)
cVar3 = (**(code**)(**(int**)(param_1+0x18) + 0x18))(&local_bc, &local_c8);
//                                          ^^^^ vtable+0x18 = do_read_vendor (0x22003c)
if (... local_c8 != 0) FUN_004d2510(0, local_c8, local_c0, 1);   // reply -> caller param_2
```

The `set` action (action == 7) instead calls **vtable+0x1c = do_send_vendor**
(`0x220038`) and returns no reply (`pp-corechain.txt:1830-1861`). So `do_read_vendor`
is handed `&local_bc` = the primed in-frame (the enciphered `0x82 …` prefix, copied
from `*param_2` at `pp-corechain.txt:1815-1817`) and `&local_c8` = the reply sink.
**No `bmRequestType/bRequest/wValue/wIndex` is ever assembled** anywhere in the
five IOCTL primitives — the .exe only ever builds the application frame and the
`{buf,alloc,count}` descriptor. The control-vs-bulk decision is the minidriver's.

**Answer to "is bulk-IN 0x82 the reply pipe?"** No — there is no app-level bulk-IN
read at all. The reply is the OUT half of the `0x22003c` IOCTL. A raw bulk-IN on
EP 0x82 issued by the native lane returns nothing because the service reply is not
delivered on a free bulk-IN; it is delivered as the read completion of the
`0x22003c` request, which the Windows minidriver fulfils over the `12fe` service
interface (empirically control-IN). **Lane A should model the reply as: write the
enciphered prefix, then read the completion on the SAME logical request — i.e. for
a libusb re-impl, do the control-IN (or the minidriver's read pipe), not a
speculative bulk-IN.** This matches `canon-servicemode-transport-research.md`.

vtable offsets confirmed against `/tmp/pp-vtablesend.txt:122` (`+0x18` read) and
the send sites at `:901/:928` (`+0x1c`). Pipe object lives at `this+0x18`.

---

## 2. Cipher re-verification — functor-2 (`FUN_004e76c0`) + functor-3 (`FUN_004e8410`)

### 2a. Buffer wiring (the load-bearing correction)

`service_send_buffer` (`FUN_004ea540`, `pp-corechain.txt:736`) selects the functor
from the template (`FUN_00522ac0("functor")`) and calls:

```c
// functor 2 (method 1/2):  pp-corechain.txt:847
FUN_004e76c0(&local_e8, &local_d8, param_2, param_3, 1);
//            ^command   ^OUTPUT(zeroed)              ^encrypt
// functor 3 (method 3):    pp-corechain.txt:879
FUN_004e8410(&local_e8, &local_d8, param_2, param_3);
```

- `local_e8` = the **command** (built from `param_4`, e.g. set_session `81 00 00 03`).
- `local_d8` = the **output**, zeroed (`*param_5==0`), length 0.

Inside functor-2 (`FUN_004e76c0`, `pp-helpers.txt:129`):

- `param_1` (the command) is duplicated to `local_10c`; its length is `local_104`.
- `param_2` (the output, empty) is duplicated to `local_ec`; because `*param_2==0`
  the copy at `pp-helpers.txt:233-236` is skipped, so `local_ec` starts empty.
- `FUN_004e72b0(&local_10c, &local_ec, …)` (`:244`) = **keyword binding**, which
  **fills `local_ec` with the 4-byte bound keyword** (`pp-cipher2.txt:247-256`)
  and sets `local_e4 = 4`.
- **Seed `local_d4`** = 32-bit big-endian fold of **`local_10c` = the command**
  (`pp-helpers.txt:258-266`) — NOT the keyword, NOT a keyword XOR.
- The XOR transform loop (`pp-helpers.txt:501-534`) runs **`local_e4 = 4`
  iterations over `local_ec` (the bound keyword)** → `local_100` (4 bytes), which
  is copied back to `param_2` (`:540-542`).

**Net: functor-2's output is 4 bytes — the bound keyword XOR'd with a keystream
that is *seeded by the command* but transforms the *keyword*.** The command bytes
themselves are never enciphered into the output; they only choose the array
indices and the per-position shift table.

functor-3 (`FUN_004e8410`, `pp-corechain.txt:1`) for set_session:

- Asserts frame ≥ 4 ("Command buffer is too small."); `bVar2 = frame[3]` (=0x03).
- Assembles `local_a8` = `00 12` (`local_c8=0x1200`, LE) ‖ `01` ‖ `bVar2` ‖ 16 LCG
  bytes (seed `0x12345678`, `s=s*0x343fd+0x269ec3`, emit `(s>>16)&0xff`) = 20 B
  (`:77-90`). LCG16 = `e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f`.
- **`<special>` overwrite (`:119-128`):** for each pair `(p,v)` in the template
  `special` table, `local_a8[p+4] = v` if `p < len`. Method-3 `special = 0x04 0x66`
  (devices.xml) ⇒ `local_a8[8] = 0x66` (overwrites the 5th LCG byte `0x96`→`0x66`).
- **`<indexes>` placement (`:129-138`):** empty for method-3, so skipped (the
  frame bytes beyond offset 4 would be scattered here; set_session has none).
- Copies the assembled 20-byte `local_a8` **into `param_3`** (`:139-142`,
  `FUN_004d2510(0, local_a8, local_a0=20, 1)` after `local_b4[2]=0`), then calls
  `FUN_004e76c0(local_cc=param_2(output), ppvVar4=param_3(now the 20-B envelope),
  …, 1)` (`:148`).

So functor-3 just substitutes a **20-byte envelope as functor-2's *seed message***
(param_1). functor-2 still transforms only the **4-byte bound keyword** (param_2
output is empty ⇒ `local_e4=4`). **functor-3's output is also 4 bytes**, seeded by
the special-modified 20-byte envelope.

### 2b. Where `canon_sr5_cipher.py` diverges (the bugs)

| # | Decompile (truth) | `canon_sr5_cipher.py` | Impact |
|---|---|---|---|
| **B1** | functor-2 transforms the **4-byte bound keyword**; seed = fold of the **command/envelope**; output = **4 bytes** | `functor2_transform` XORs the **whole message** (4-B frame, or 20-B assembled buffer) and returns its full length | **Wrong output length** (returns 20 B for set_session) and **wrong bytes** (transforms the envelope, not the keyword) |
| **B2** | functor-3 output = **4 bytes**; the 20-byte envelope is only the *seed source*; prefix is carried in clear by `execute_one_command` | `functor3_encrypt` returns `functor2(envelope‖frame[4:])` = **20 bytes** as the wire frame | The claimed 20-byte `set_session` is not the wire payload at all |
| **B3** | functor-3 applies the **`<special> 0x04 0x66`** overwrite (`local_a8[8]=0x66`) before seeding | `envelope3` omits `<special>` (byte[8] stays `0x96`) | Wrong seed *iff* the modified byte is in the low 4 bytes; for set_session it is byte[8] (shifted out of the 32-bit fold, so seed is coincidentally equal) — but the rule is still wrong and bites other commands |
| **B4** | shift is a **per-output-position table** built by the operator-VM over `command.shift`, then indexed per byte (`pp-helpers.txt:338-495`, used at `:522-526`) | `apply_shift_program` computes **one scalar** `shift_val` applied uniformly | Wrong keystream shift for any message > 1 transformed byte |
| **B5** | keystream byte = `(seed >> shift_table[pos]) ^ codes[permuted_pos]`, with `codes`/`index`/`shift` arrays chosen by `seed % count` and indexed through the permutation machinery | `ks[i] = (seed >> shamt) ^ codes[i % len]`, perm via `_bijection` rank-sort | Plausible only by luck; the real index path is the nested `FUN_00449110`/`FUN_004c1bf0` table walk, not a modulo |

The keyword-binding direction (`bound[i] = codes[idx[i]] ^ device_kw[idx[i]]`) is
the one piece that **is** faithful: `FUN_004e72b0` (`pp-cipher2.txt:223-249`) reads
`j = keyword.index[base+i]` then `out = keyword.codes[base2+j] ^ (*device_kw)[j]`,
which `bind_keyword` reproduces (default kw `4D B6 AB 00` → bound `00 ff 00 f8`).

### 2c. Expected vs computed set_session

- **Our `canon_sr5_cipher.py` set_session** = `ed f4 75 21 a3 c4 69 2c ba fb 46 12
  16 b8 73 c0 69 66 13 4e` (20 B). **Reproduced** by the script (self-consistent),
  but it is the wrong object: a 20-byte XOR of the envelope buffer.
- **Decompile-faithful set_session payload** = the **4-byte** functor-3 output =
  keystream-transform of the bound keyword `00 ff 00 f8`, seeded by the 20-byte
  special-modified envelope (seed low dword `0x83cf096f`; arrays
  index#3 / codes#6 / shift#2 by `seed % {5,7,3}`). The full 4 bytes require
  modeling the per-position shift TABLE + the table-walk index path (B4/B5) — not
  yet reduced to a number here because the scalar-shift model is wrong. The **wire
  set_session command** is then `prefix(81 00 00 03, clear) ‖ <4-byte enciphered
  keyword>`, assembled by `execute_one_command`, **not** a single 20-byte blob.

So **they do not match**: different length (4 vs 20), different content, different
assembly (prefix is not enciphered).

---

## 3. Verdict + fix direction

**The cipher is buggy (B1–B5), so the problem is NOT purely transport.** The
0-byte raw-bulk-IN read is independently explained (RECV is the IN half of a
combined `0x22003c` IOCTL; use the minidriver/control read, not a speculative
bulk-IN), but our enciphered `set_session`/`get_keyword` bytes are wrong and must
be re-derived before any wire match.

Fix plan for `scripts/canon_sr5_cipher.py`:

1. **Transform target = the 4-byte bound keyword** (not the message). Output is
   4 bytes. The command/envelope is the **seed source only**.
2. **Assembly = `prefix (clear) ‖ enciphered_keyword`** at the `execute_one_command`
   layer; functor output is the 4-byte trailer, not the whole frame.
3. **functor-3 envelope:** apply the `<special>` overwrite (`local_a8[p+4]=v`) and
   the `<indexes>` scatter for `frame[4:]` before using the 20-byte buffer as the
   functor-2 seed. (Output still 4 bytes.)
4. **Shift = per-position table** from the operator-VM over `command.shift`
   (seed = `local_d4`), indexed per transformed byte; not one scalar.
5. **Keystream/permutation:** port the actual `seed % count` array selection and
   the per-position `codes`/`index` table walk (`FUN_004e76c0:298-334, 501-534`),
   `ks_byte = (seed >> shift_table[pos]) ^ codes[perm_pos]`, with the
   send(`param_5=1`)/recv(`param_5=0`) index swap
   (`out[i]=in[perm[i]]^ks` vs `out[perm[i]]=in[i]^ks`).
6. Re-validate by enciphering `get_keyword (82 00 00 …)` and comparing the 4-byte
   trailer to a fresh wire/Frida capture at `FUN_004e8410`/`FUN_004e76c0`.

Confidence: **High** on the transport (direct decompile of both IOCTL primitives
+ the execute_one_command dispatch). **High** that the cipher is wrong on length
and assembly (B1/B2 are unambiguous in the buffer wiring); **Medium-High** on the
exact corrected keystream (B4/B5 require porting the table-walk, which the residual
work above specifies).
