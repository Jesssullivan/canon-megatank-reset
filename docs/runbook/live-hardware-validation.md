# Live-hardware validation tiers (the native tool vs the real G6020)

The native tool is validated against the real printer in **safety tiers**, each a
strict superset of the last. Run on the capture host (mbp-13) with the
`canon_tool_dev` role applied. Every tier stops `ipp-usb` first (scoped sudo) and
restores it on exit, so the office CUPS queue is only down for the run.

## Tier 0 — claim-only, ZERO bytes ✅ (passed 2026-05-30)

`scripts/tier0-claim-probe.sh`. Binds the maintenance lane and verifies the
endpoints — **sends no maintenance command at all**. The safest first contact;
validates the USB stack (interface selection + endpoint binding) against real
hardware.

**Result (mbp-13, G6020 `04a9:1865`):**
```
expected: iface 4 OUT 0x3 IN 0x86
CLAIM_OK  vendor 0x4a9  product 0x1865  serial 01807C
  bulk_out 0x3   bulk_in 0x86
ENDPOINTS_VERIFIED — bound the maintenance lane, sent nothing
```
Serial `01807C` matches the locked `test_unit` UUID `…01807c`. This is the proof
that the **interface-pinning fix (PR #15)** works on the actual device: the live
descriptor exposes a bulk pair on interface 0 *before* interface 4, and the tool
correctly bound iface 4 / `0x03` / `0x86` (the old first-match code would have
grabbed iface 0). ipp-usb restored cleanly afterward.

## Tier 1 — single counter READ (BLOCKED on the read command)

Stop ipp-usb → issue ONE RECV of the waste counter → decode the reply.
Read-only: no EEPROM write, no reset, no key, no pads risk.

**Status: blocked.** The literal read `(cmd, arg)` for the G6020 counter is not
yet derivable by static RE:
- The Service Tool's read path is C++ **virtual-dispatched** — the IOCTL
  primitive `FUN_004302c0` has **0 direct callers**, and the WICReset-era
  `get_command`/`readcmd` string anchors do not exist in the Canon binary (they
  were the Epson path). See `.ghidra-work/out/v5103/read.txt`.
- Per the documented design the operation identity rides in the **payload**, not
  the cmd byte (generic RECV `cmd=0x86`), so the request body — not a simple
  `(cmd,arg)` — selects the counter.

We do **not** guess a command to send to the real printer. Tier 1 unblocks via
one of: (a) deeper RE of the read request body (resolve the EncCommService vtable
instance), or (b) a usbmon capture of the free WICReset "Read waste counters"
(no key) to observe the exact request bytes — the original T1 plan, now feasible
on the QEMU path since Wine can't surface USB.

## Tier 2 — the reset (HARD-GATED) 🔒

`just reset --execute`. Blocked by `maintenance.yaml::absorber_reset.status ==
derived-unvalidated` until a pads-installed physical-validation run promotes it to
`verified-captured`. Requires the new waste-ink pads physically installed first
(OctoInkjet's instruction — reset on a full absorber overflows). The reset frame
is fully derived (`8500000003010307`, idx 0x07 = "Main") and dry-run-verified.
