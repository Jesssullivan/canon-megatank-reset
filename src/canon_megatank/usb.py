"""Thin pyusb wrapper for Canon G-series USB access.

Safety-by-default:
- Vendor allowlist (only Canon, idVendor=0x04a9, opens succeed).
- Context-managed device claim so the kernel driver gets reattached on exit.
- Bulk endpoint discovery (no hardcoded EP addresses).
- Read transfer (`read_response`: write a 3-byte RECV header, read the reply).
- Write transfer (`send_command`: the 0x220038 SEND equivalent) is exposed but
  is a thin unconditional byte-pusher — ALL safety gating lives in
  `ops.reset_absorber`, which is the only thing that may call it.

This is the ONLY module in printstack-canon allowed to import `usb`. All
other code calls into `ClaimedDevice` (see below).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import cast

import usb.core
import usb.util

from .types import UsbAccessError

CANON_VENDOR_ID = 0x04A9


class ClaimedDevice:
    """A USB device the caller has claimed for exclusive maintenance access.
    Use as a context manager — exit detaches and reattaches the kernel
    driver."""

    def __init__(self, dev: usb.core.Device) -> None:
        if dev.idVendor != CANON_VENDOR_ID:
            raise UsbAccessError(
                f"refusing to open non-Canon device (vendor={dev.idVendor:#06x})"
            )
        self._dev = dev
        self._kernel_was_attached: bool = False
        self._interface_number: int | None = None
        self._bulk_in_ep: int | None = None
        self._bulk_out_ep: int | None = None

    def __enter__(self) -> ClaimedDevice:
        # Detach the kernel driver (ipp-usb or canon-cups) if it has the
        # device. We re-attach in __exit__.
        try:
            if self._dev.is_kernel_driver_active(0):
                self._kernel_was_attached = True
                self._dev.detach_kernel_driver(0)
        except (NotImplementedError, usb.core.USBError):
            # Some platforms don't implement is_kernel_driver_active or detach;
            # don't fail here.
            pass

        try:
            self._dev.set_configuration()
        except usb.core.USBError as exc:
            raise UsbAccessError(f"could not set USB configuration: {exc}") from exc

        cfg = self._dev.get_active_configuration()
        # Find the first interface with both bulk-IN and bulk-OUT endpoints.
        for intf in cfg:
            bulk_in = next(
                (
                    ep.bEndpointAddress
                    for ep in intf
                    if usb.util.endpoint_direction(ep.bEndpointAddress)
                    == usb.util.ENDPOINT_IN
                    and usb.util.endpoint_type(ep.bmAttributes)
                    == usb.util.ENDPOINT_TYPE_BULK
                ),
                None,
            )
            bulk_out = next(
                (
                    ep.bEndpointAddress
                    for ep in intf
                    if usb.util.endpoint_direction(ep.bEndpointAddress)
                    == usb.util.ENDPOINT_OUT
                    and usb.util.endpoint_type(ep.bmAttributes)
                    == usb.util.ENDPOINT_TYPE_BULK
                ),
                None,
            )
            if bulk_in is not None and bulk_out is not None:
                self._interface_number = intf.bInterfaceNumber
                self._bulk_in_ep = bulk_in
                self._bulk_out_ep = bulk_out
                try:
                    usb.util.claim_interface(self._dev, self._interface_number)
                except usb.core.USBError as exc:
                    raise UsbAccessError(
                        f"could not claim interface {self._interface_number}: {exc}"
                    ) from exc
                return self

        raise UsbAccessError(
            "no interface with bulk-IN + bulk-OUT endpoints found "
            "(is this really a Canon printer in normal mode?)"
        )

    def __exit__(self, *exc_info: object) -> None:
        try:
            if self._interface_number is not None:
                usb.util.release_interface(self._dev, self._interface_number)
            usb.util.dispose_resources(self._dev)
            if self._kernel_was_attached:
                with suppress(NotImplementedError, usb.core.USBError):
                    self._dev.attach_kernel_driver(0)
        except Exception:
            # Cleanup best-effort; don't mask the original exception.
            pass

    # ─── Read-only inspection helpers (safe to expose) ──────────────────────

    @property
    def vendor_id(self) -> int:
        return int(self._dev.idVendor)

    @property
    def product_id(self) -> int:
        return int(self._dev.idProduct)

    @property
    def serial_number(self) -> str | None:
        try:
            return cast("str | None", usb.util.get_string(self._dev, self._dev.iSerialNumber))
        except (usb.core.USBError, ValueError):
            return None

    @property
    def bulk_in_endpoint(self) -> int:
        if self._bulk_in_ep is None:
            raise UsbAccessError("not yet entered context")
        return self._bulk_in_ep

    @property
    def bulk_out_endpoint(self) -> int:
        if self._bulk_out_ep is None:
            raise UsbAccessError("not yet entered context")
        return self._bulk_out_ep

    # ─── Read-only transfer (the 0x22003c RECV equivalent) ──────────────────

    def read_response(
        self, request_header: bytes, *, timeout_ms: int = 5000, length: int = 64
    ) -> bytes:
        """Issue a RECV: write the 3-byte request header to the bulk-OUT
        endpoint, then read the reply from bulk-IN.

        This is the Linux equivalent of the Service Tool's ``0x22003c`` RECV
        IOCTL (write ``[cmd][arg_hi][arg_lo]``, read the response back). It is
        the ONLY transfer helper exposed — there is deliberately no
        payload-write/reset method here; the reset path lives behind the safety
        gates in ops.py / replay.py.

        ``request_header`` is the 3-byte header built by
        ``protocol.model.encode_recv_header``. Returns the raw reply bytes.
        """
        try:
            self._dev.write(self.bulk_out_endpoint, request_header, timeout=timeout_ms)
            reply = self._dev.read(self.bulk_in_endpoint, length, timeout=timeout_ms)
        except usb.core.USBError as exc:
            raise UsbAccessError(f"bulk RECV transfer failed: {exc}") from exc
        return bytes(reply)

    # ─── Write transfer (the 0x220038 SEND equivalent) — GATED ──────────────

    def send_command(self, frame: bytes, *, timeout_ms: int = 5000) -> int:
        """Issue a SEND: write a full command ``frame`` to the bulk-OUT endpoint
        (no reply read). This is the Linux equivalent of the ``0x220038`` SEND
        IOCTL — the write path.

        ⚠ This is the only method on ``ClaimedDevice`` that can mutate printer
        state. It is intentionally a thin, unconditional byte-pusher: ALL safety
        gating (UUID isolation, write budget, mandatory EEPROM dump,
        derived-vs-validated status, lockfile, dry-run) lives in
        ``ops.reset_absorber`` and MUST be passed before this is ever called.
        Do not call this directly from CLI/handler code.

        ``frame`` is the complete wire frame from
        ``protocol.model.encode_send`` / ``derive_reset_frame``. Returns the
        number of bytes written.
        """
        try:
            written = self._dev.write(self.bulk_out_endpoint, frame, timeout=timeout_ms)
        except usb.core.USBError as exc:
            raise UsbAccessError(f"bulk SEND transfer failed: {exc}") from exc
        return int(written)


@contextmanager
def open_g6020(product_id: int = 0x1865) -> Iterator[ClaimedDevice]:
    """Locate the Canon G6020 (or family-compatible product id) and yield
    a ClaimedDevice."""
    dev = usb.core.find(idVendor=CANON_VENDOR_ID, idProduct=product_id)
    if dev is None:
        raise UsbAccessError(
            f"no Canon device with productId={product_id:#06x} found on USB; "
            "check that the printer is powered on and the udev rule + "
            "printstack group membership are in place"
        )
    with ClaimedDevice(dev) as cd:
        yield cd


def find_all_canon() -> list[tuple[int, int, str | None]]:
    """Enumerate every Canon USB device on the bus. Read-only.
    Returns [(vid, pid, serial_number_or_None), ...]."""
    out: list[tuple[int, int, str | None]] = []
    for dev in usb.core.find(idVendor=CANON_VENDOR_ID, find_all=True) or []:
        try:
            sn = usb.util.get_string(dev, dev.iSerialNumber)
        except (usb.core.USBError, ValueError):
            sn = None
        out.append((int(dev.idVendor), int(dev.idProduct), sn))
    return out
