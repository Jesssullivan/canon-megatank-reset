---
title: User guide — clearing the 5B00 "ink absorber full" error
description: Plain-language guide to clearing the Canon G-series MegaTank 5B00 lock on hardware you own, after installing a fresh waste-ink absorber kit.
---

# Clearing the 5B00 "ink absorber full" error

For owners of a Canon G-series MegaTank (G6020 and relatives) stopped with **support
code 5B00**. No reverse-engineering background assumed — for the protocol and the
engineering, see the [field guide](research/canon-service-mode-field-guide.md) and the
[validated runbook](runbook/g6020-native-reset.md).

!!! warning "Install a waste-ink pad kit first"
    5B00 means the waste-ink absorber counter has reached its limit. Resetting a
    *physically full* absorber overflows ink inside the printer. **Install a fresh
    absorber/maintenance kit before resetting**, and reset only printers you own.

## What 5B00 is

A counter in the printer's memory — not a broken part. Firmware refuses to print once
it crosses a threshold, and this generation's consumer firmware exposes no user reset.
This tool performs the service-mode reset over USB.

## What you need

- The printer, with a **fresh waste-ink absorber kit installed**.
- A **Linux** computer and a USB cable.
- Comfort running one terminal command.

A signed graphical macOS/Windows/Linux app is tracked as a community contribution in
[issue #31](https://github.com/Jesssullivan/canon-megatank-reset/issues/31); until it
lands, the steps below are the supported path.

## Steps

1. **Install the absorber kit** (see the warning above) — do not skip this.
2. **Enter service mode.** Power off. Hold **ON**, press **Stop/Resume five times**,
   then release **ON**. The screen turns to a plain colour field.
3. **Connect** the printer to the Linux computer by USB.
4. **Run the tool** (install per the
   [README](https://github.com/Jesssullivan/canon-megatank-reset)):
   ```sh
   canon-megatank reset-native            # dry run — prints what it will do, writes nothing
   canon-megatank reset-native --execute  # performs the reset
   ```
   It refuses to run against the wrong printer and snapshots the printer's memory first.
5. **Power-cycle with the power button.** Let the tool finish, then turn the printer
   **off with its power button** (not by unplugging) — you will hear the printhead
   park. Turn it back on.
6. **Done.** The printer returns to normal mode and prints.

## If it does not clear

- Confirm you used the **power button**, not the plug — the reset commits during a
  clean shutdown.
- Confirm the printer was in **service mode** (plain-colour screen) when you ran the tool.
- See the troubleshooting section of the [runbook](runbook/g6020-native-reset.md).

## Is this allowed?

Resetting your own printer's waste-ink counter, after installing fresh pads, is a
repair — not a circumvention of any content protection. See
[right to repair](https://github.com/Jesssullivan/canon-megatank-reset/blob/main/ETHICS/RIGHT-TO-REPAIR.md).
