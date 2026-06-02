# Canon MegaTank maintenance protocol — formal model

**Model:** `src/canon_megatank/protocol/model.py` · **Proofs:**
`tests/test_protocol_model.py` (Hypothesis) · **SSOT:**
`printers/canon-g6020/maintenance.yaml`.

> **Scope — read this first.** This is the early, two-tool-corroborated model of the
> **normal-mode** `usbscan` transport and frame grammar. The G6020 reset was since
> recovered and **hardware-validated over a different path**: the **service-mode**
> (`04a9:12fe`) vendor **control-transfer** transport and a keyed, enciphered session.
> That **supersedes the transport (§2) and the absorber-payload (§4) specifics here** —
> the plaintext `[00,03,flags,03,idx]` payload modelled below was **falsified** on
> hardware (it ACKs but does not clear 5B00). For the validated protocol see the
> [field guide](../research/canon-service-mode-field-guide.md) and the
> [reference runbook](../runbook/g6020-native-reset.md). This document is retained for
> its still-valid invariants (round-trip, determinism, idempotency, the safety gates,
> no SSOT drift) and as the methodology record. A rewrite to the validated control-
> transfer + functor-cipher protocol is tracked future work.

Each claim is marked **(K)** known/corroborated or **(P)** pending. The executable
model encodes the invariants; the property tests assert them.

## 1. Oracles

| Oracle | What it pins | Evidence |
|---|---|---|
| **Canon Service Tool** (v5103 static RE) | IOCTL primitive `FUN_004302c0`, the `[cmd][arg_hi][arg_lo][payload]` frame, group-7 absorber dialog payload | `docs/research/canon-service-mode-field-guide.md` |
| **WICReset** (`printerpotty.exe` static RE) | `USBPipe` IOCTL primitives (`0x220038`/`0x22003c`), `service.sendcmd`/`service.readcmd` template builders | `docs/research/canon-service-mode-field-guide.md` |

The two were reversed independently and **agree on the transport**. That
agreement is the basis for trusting the model before a single key is spent.

## 2. Transport binding (K)

```
Windows:  CreateFileW(\\.\UsbscanN) -> DeviceIoControl(handle, IOCTL, inBuf, ...)
Linux:    pyusb bulk on interface 4   (OUT 0x03 / IN 0x86)
```

| IOCTL | direction | Linux equivalent |
|---|---|---|
| `0x220038` **SEND** | host → printer (header + payload, out-buffer NULL) | bulk write `EP 0x03` |
| `0x22003c` **RECV** | printer → host (3-byte header out, response read back) | write header `EP 0x03`, read `EP 0x86` |

usbscan IOCTLs: `FILE_DEVICE = 0x22`, function codes `0x30/0x34/0x38/0x3c`
(`code << 2` → method/access). WICReset additionally touches `0x220030`/`0x220034`
read variants. Both tools cache the device handle (`USBPipe+0x24` in WICReset,
`this+0x10` in the Service Tool) and open with shared read/write + overlapped IO.

## 3. Wire grammar (K)

```
SEND frame   ::= cmd:u8  arg_hi:u8  arg_lo:u8  payload:bytes
RECV request ::= cmd:u8  arg_hi:u8  arg_lo:u8                 (no payload)

arg          ::= u16, BIG-ENDIAN     (arg_hi = arg >> 8, arg_lo = arg & 0xff)
buffer_len   ::= 3 + len(payload)    (SEND) | 3 (RECV)
```

Model functions: `encode_send(cmd, arg, payload)`, `encode_recv_header(cmd, arg)`,
`decode_frame(frame) -> (cmd, arg, payload)`.

**WICReset's higher layer.** `service.sendcmd`/`readcmd` build their buffer from a
per-model **template** with `$INDEX`/`$VALUE` tokens, emitting
`[header blob][2-byte len][value][index LE bytes][1-byte op][value]` before handing
it to the *same* SEND/RECV IOCTLs. So WICReset adds a template engine **on top of**
the identical transport — it does not contradict the Service Tool frame; the literal
bytes live in template data, not code (→ recovered by T4 capture, §6).

## 4. Absorber-reset operation (K shape / P bytes)

The 5B00 path is the Service Tool's **"Ink Absorber Counter → Set"** (operation
group 7). Recovered payload shape:

```
absorber payload ::= 0x00  0x03  flags:u8  0x03  idx:u8
flags            ∈ { 0x01 (main absorber), 0x81 (main + platen, checkbox bit) }
idx              ::= absorber selector (u8)            [P — concrete value from T4]
```

Full reset frame = `encode_send(cmd, arg, absorber_payload(flags, idx))`, modelled
as the pure **reset-derivation function** `derive_reset_frame(AbsorberResetSpec)`.

> **PENDING (P):** the concrete `cmd`/`arg`/`flags`/`idx` for the G6020 are filled by
> T4 ground-truth. The model parameterizes them and asserts only structure +
> determinism; it deliberately does **not** guess the literal bytes.

## 5. State machine

```
        ┌─────────────┐  open session   ┌────────┐  read (RECV)   ┌────────┐
        │ DISCONNECTED │ ───────────────▶│ OPENED │ ─────────────▶│  READ  │
        └─────────────┘                  └────────┘                └────────┘
               ▲                              │                         │
               │ close                        │ derive_reset_frame      │ (counter value)
               │                              ▼                         ▼
        ┌─────────────┐   verify (RECV)  ┌────────┐  reset (SEND)  ┌────────┐
        │   VERIFIED   │◀───────────────│ RESET  │◀───────────────│ DERIVE │
        └─────────────┘                  └────────┘                └────────┘
```

Device-state effect (modelled by `CounterState` + `apply_reset`):

* `apply_reset(s).value == 0` for **any** starting `s` → clears the 5B00 block.
* **Idempotent:** `apply_reset(apply_reset(s)) == apply_reset(s)`. The wire frame
  does not depend on the current counter value, so re-issuing it is safe.

## 6. Known vs pending — and how T4 closes it

| Claim | Status | Resolved by |
|---|---|---|
| Transport / IOCTLs / endpoints | **K** (two-tool) | — |
| Frame grammar `[cmd][arg_hi][arg_lo][payload]`, big-endian arg | **K** (two-tool) | — |
| Absorber payload *shape* `[00,03,flags,03,idx]` | **K** (Service Tool) | — |
| Literal `cmd/arg/flags/idx` for G6020 reset | **P** | T4 usbmon capture |
| Is the reset cloud-gated (key as per-byte input)? | **P** (likely *no*; key is an upstream gate) | T4 network trace + `action_is_permitted` |

**T4 validation contract:** capture WICReset performing the real reset, parse the
bulk-OUT stream with §3's grammar, recover the `AbsorberResetSpec`, and assert the
captured bytes **equal** `derive_reset_frame(spec)`. Agreement ⇒ promote
`maintenance.yaml::supported.absorber_reset` `pending-capture → verified-captured`.
Disagreement ⇒ the model is wrong; do not ship — refine §3–§4.

## 7. Invariants the property tests prove (offline, no key)

* **Round-trip:** `decode_frame(encode_send(c,a,p)) == (c,a,p)`.
* **Determinism:** encoding and `derive_reset_frame` are pure functions.
* **Byte order:** `arg` serializes big-endian; header is exactly 3 bytes.
* **Length:** SEND frame length `== 3 + len(payload)`.
* **Payload shape:** absorber payload is exactly `[00,03,flags,03,idx]`; illegal
  flags rejected.
* **Idempotency:** reset zeroes the counter from any state and is re-applicable.
* **Write-budget monotonicity:** `consumed` only grows, `remaining` only shrinks,
  `exhausted` latches at the cap.
* **UUID gate:** only the locked `test_unit` UUID permits a write.
* **No SSOT drift:** model transport constants `==` `maintenance.yaml`.

## 8. Relationship to the native tool

The native pyusb tool implements §3 directly on interface 4: a SEND is
`ep_out.write(encode_send(cmd, arg, payload))`; a RECV writes
`encode_recv_header(cmd, arg)` then `ep_in.read()`. The reset path is exactly
`derive_reset_frame(spec)` behind all safety gates (UUID isolation, write-budget,
mandatory EEPROM dump, ping-suite baseline, lockfile). No Wine, no key, no cloud.
