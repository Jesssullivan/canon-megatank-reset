#!/usr/bin/env bash
# Tier-0 claim-only probe: bind the maintenance lane on the REAL G6020, confirm
# endpoints, send ZERO maintenance bytes, release. The safest possible
# first-contact test — validates the interface-pinning USB stack against real
# hardware without issuing any maintenance command. Run on the capture host
# (mbp-13) with the canon_tool_dev role applied (usbmon group + scoped sudo for
# the ipp-usb toggle). Restores ipp-usb on exit (office queue).
set -euo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo ~/git/canon-megatank-reset)"

echo "=== stop ipp-usb (scoped sudo) ==="
sudo -n systemctl stop ipp-usb && echo "ipp-usb stopped" || { echo "sudo stop failed"; exit 3; }
sleep 1
cleanup() { echo "=== restarting ipp-usb ==="; sudo -n systemctl start ipp-usb && echo "ipp-usb restarted"; }
trap cleanup EXIT

# Run from src on PYTHONPATH so canon_megatank imports without an install step.
PYTHONPATH="$PWD/src" nix develop --command bash -lc 'PYTHONPATH="$PWD/src" uv run --no-project --with pyusb python - <<PY
from canon_megatank.usb import open_g6020, MAINT_INTERFACE, MAINT_BULK_OUT, MAINT_BULK_IN
print("expected: iface", MAINT_INTERFACE, "OUT", hex(MAINT_BULK_OUT), "IN", hex(MAINT_BULK_IN))
with open_g6020() as dev:
    print("CLAIM_OK")
    print("  vendor   ", hex(dev.vendor_id))
    print("  product  ", hex(dev.product_id))
    print("  serial   ", dev.serial_number)
    print("  bulk_out ", hex(dev.bulk_out_endpoint))
    print("  bulk_in  ", hex(dev.bulk_in_endpoint))
    assert dev.bulk_out_endpoint == MAINT_BULK_OUT, "WRONG OUT endpoint!"
    assert dev.bulk_in_endpoint == MAINT_BULK_IN, "WRONG IN endpoint!"
    print("ENDPOINTS_VERIFIED — bound the maintenance lane, sent nothing")
PY'
