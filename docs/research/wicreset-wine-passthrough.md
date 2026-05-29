# WICReset under Wine — headless run works, USB passthrough does not (T1 finding)

**Date:** 2026-05-29 · **Host:** mbp-13 (Rocky 10, Budgie/Wayland) · key NOT spent.

## What we confirmed

- `PrinterPotty_WICReset.exe` (the `getwicreset` download) is an **Inno Setup
  installer**, not the app. Silent install works under Wine:
  `wine PrinterPotty_WICReset.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /NOICONS`
  → installs `…/drive_c/Program Files (x86)/Printer Potty WICReset/printerpotty.exe`
  (the real app) + `unins000.exe`.
- The **headless Xvfb + xdotool + scrot pipeline works end-to-end**: launched
  `printerpotty.exe` under `DISPLAY=:99`, listed its windows (`Printer Potty
  WICReset v.5.95 May 1 2024`), and captured a clean screenshot. So GUI automation
  is viable — *if* the app can see the printer.

## The blocker

WICReset reports **"Application could not find any printers connected to this PC"**
under Wine, even with ipp-usb stopped. It is **not** a Linux-side problem:

- The G6020 enumerates fine; interface 4 (the maintenance lane, class `ff`,
  `bulk OUT 0x03 / IN 0x86`) has **`driver=none`** — free for our own pyusb tool.
- `usblp` is not loaded; only ipp-usb (usbfs) claims the printer-class ifaces, and
  it was stopped during the run.
- The gap is **Wine's own USB enumeration inside the flatpak sandbox**: the wine
  log shows `wineusb:query_id Unhandled ID query type 0x5` (repeated) — Wine's USB
  layer partially sees devices but fails to present the Canon to the app. Flatpak's
  `--device=all` does not give `wineusb` what it needs (the `/dev/bus/usb`
  filesystem override is reserved/rejected by flatpak).

## Second signal: WICReset is cloud-connected ("Connect")

The wine log shows repeated `secur32:get_enabled_protocols handle TLS parameters`
and `GetCurrentPackageId` — **WIC Reset Connect phones home over TLS**. So even a
successful USB capture might involve cloud-brokered / opaque bytes; the reset is
plausibly gated on a server handshake (the single-use key is validated online).

## Implications for the tranche

Dynamic capture of WICReset over **flatpak-Wine USB is blocked**, and cloud-gating
makes a pure USB capture suspect anyway. The robust, reproducible path to the
protocol shifts to:

1. **T2 — static RE of `printerpotty.exe`** (Ghidra). Recovers the read/reset
   command construction + the USB-write path + the key/cloud logic. Needs **no**
   Wine USB passthrough and **no** printer. This becomes the primary oracle.
2. The **native pyusb tool (T5)** drives interface 4 directly (`driver=none`, fully
   accessible at the Linux level) — Wine's limitation does not affect our own tool.
3. Cross-ref with the Canon Service Tool Ghidra findings (already recovered).

### Options still open for a *dynamic* WICReset capture (if wanted)
- **Native/nix Wine** (not flatpak) with direct `/dev/bus/usb` → `wineusb` may
  enumerate the Canon. Untried (wine is a heavy nix build).
- **Network discovery**: WICReset finds printers over "USB **or network**". Put the
  G6020 on the LAN; WICReset Connect may find it over the network (no USB
  passthrough) — but then the capture surface is network (tcpdump), not usbmon, and
  likely cloud-brokered.

**Recommendation:** make **T2 static RE** the primary protocol-recovery path; keep
the Wine/network capture as an optional corroboration if static RE leaves gaps.
