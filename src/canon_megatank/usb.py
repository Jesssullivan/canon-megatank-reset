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
from typing import Any, cast

import usb.core
import usb.util

from .types import UsbAccessError

CANON_VENDOR_ID = 0x04A9


class ClaimedDevice:
    """A USB device the caller has claimed for exclusive maintenance access.
    Use as a context manager — exit detaches and reattaches the kernel
    driver."""

    def __init__(
        self,
        dev: usb.core.Device,
        *,
        interface: int | None = None,
        bulk_out_ep: int | None = None,
        bulk_in_ep: int | None = None,
    ) -> None:
        if dev.idVendor != CANON_VENDOR_ID:
            raise UsbAccessError(
                f"refusing to open non-Canon device (vendor={dev.idVendor:#06x})"
            )
        self._dev = dev
        self._kernel_was_attached: bool = False
        self._interface_number: int | None = None
        self._bulk_in_ep: int | None = None
        self._bulk_out_ep: int | None = None
        # When pinned (the maintenance lane), bind EXACTLY this interface and
        # verify its endpoints — never auto-pick. The G6020 has bulk endpoints on
        # interface 0 BEFORE interface 4, so first-match would claim the wrong
        # lane. The SSOT pins iface 4 / OUT 0x03 / IN 0x86.
        self._want_interface = interface
        self._want_bulk_out = bulk_out_ep
        self._want_bulk_in = bulk_in_ep

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

        def _bulk_eps(intf: Any) -> tuple[int | None, int | None]:  # pyusb iface is untyped
            bin_ = next(
                (
                    ep.bEndpointAddress
                    for ep in intf
                    if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN
                    and usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
                ),
                None,
            )
            bout = next(
                (
                    ep.bEndpointAddress
                    for ep in intf
                    if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT
                    and usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
                ),
                None,
            )
            return bin_, bout

        # PINNED mode (the maintenance lane): bind EXACTLY the requested interface
        # and verify its endpoints match the SSOT. The G6020 exposes bulk
        # endpoints on interface 0 before interface 4, so first-match would claim
        # the wrong lane and send the reset to the wrong endpoint.
        if self._want_interface is not None:
            for intf in cfg:
                if intf.bInterfaceNumber != self._want_interface:
                    continue
                bulk_in, bulk_out = _bulk_eps(intf)
                if bulk_in is None or bulk_out is None:
                    raise UsbAccessError(
                        f"interface {self._want_interface} has no bulk in+out pair"
                    )
                if self._want_bulk_out is not None and bulk_out != self._want_bulk_out:
                    raise UsbAccessError(
                        f"interface {self._want_interface} bulk-OUT is "
                        f"{bulk_out:#04x}, expected {self._want_bulk_out:#04x} — "
                        "wrong interface/descriptor; refusing to bind."
                    )
                if self._want_bulk_in is not None and bulk_in != self._want_bulk_in:
                    raise UsbAccessError(
                        f"interface {self._want_interface} bulk-IN is "
                        f"{bulk_in:#04x}, expected {self._want_bulk_in:#04x} — "
                        "wrong interface/descriptor; refusing to bind."
                    )
                self._bind(intf.bInterfaceNumber, bulk_in, bulk_out)
                return self
            raise UsbAccessError(
                f"maintenance interface {self._want_interface} not found on device"
            )

        # AUTO mode (no pin): first interface with a bulk in+out pair. Used by
        # callers that don't care which lane (e.g. simple probes / tests).
        for intf in cfg:
            bulk_in, bulk_out = _bulk_eps(intf)
            if bulk_in is not None and bulk_out is not None:
                self._bind(intf.bInterfaceNumber, bulk_in, bulk_out)
                return self

        raise UsbAccessError(
            "no interface with bulk-IN + bulk-OUT endpoints found "
            "(is this really a Canon printer in normal mode?)"
        )

    def _bind(self, interface: int, bulk_in: int, bulk_out: int) -> None:
        """Record + claim the chosen interface and its endpoints."""
        self._interface_number = interface
        self._bulk_in_ep = bulk_in
        self._bulk_out_ep = bulk_out
        try:
            usb.util.claim_interface(self._dev, interface)
        except usb.core.USBError as exc:
            raise UsbAccessError(
                f"could not claim interface {interface}: {exc}"
            ) from exc

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

    # ─── EP0 control transfer (the WICReset service-mode transport) — GATED ───

    def control_transfer(  # noqa: PLR0913 — mirrors the USB setup packet (5 wire fields)
        self,
        bm_request_type: int,
        b_request: int,
        w_value: int,
        w_index: int,
        data_or_length: bytes | int,
        *,
        timeout_ms: int = 5000,
    ) -> bytes:
        """Issue a single USB control transfer on EP0 (the default endpoint).

        This is the Linux equivalent of WICReset's service-mode transport: the
        real working absorber-reset path is a vendor control-OUT on EP0
        (``bmRequestType=0x40 bRequest=0x85 wValue=0 wIndex=0
        data=[00 03 01 03 07]``), with class control-IN reads
        (``0xA1/0x00`` 1284-id, ``0xA1/0x01`` status) framing it. EP0 is always
        available once the configuration is set — no interface claim or bulk
        endpoint is needed (the reset is addressed to ``wIndex`` interface 0).

        ⚠ Like :meth:`send_command`, this is a thin, unconditional byte-pusher
        for the WRITE direction. A vendor control-OUT mutates printer state. ALL
        safety gating (UUID isolation, validated-status, EEPROM dump, write
        budget, lockfile, dry-run) lives in ``ops.replay_control_sequence`` and
        MUST pass before this is reached. Do not call directly from CLI/handler
        code for any OUT transfer.

        ``data_or_length`` is the OUT data bytes (host→device) when the direction
        bit of ``bm_request_type`` is clear, or the IN read length (an int) when
        it is set. Returns the bytes read on an IN transfer; on an OUT transfer
        returns ``b""`` (pyusb returns the count, which we discard here).
        """
        try:
            ret = self._dev.ctrl_transfer(
                bm_request_type,
                b_request,
                w_value,
                w_index,
                data_or_length,
                timeout=timeout_ms,
            )
        except usb.core.USBError as exc:
            raise UsbAccessError(
                f"control transfer failed "
                f"(bmRequestType={bm_request_type:#04x}, bRequest={b_request:#04x}, "
                f"wValue={w_value:#06x}, wIndex={w_index:#06x}): {exc}"
            ) from exc
        # IN transfers return an array of bytes; OUT transfers return an int count.
        if isinstance(ret, int):
            return b""
        return bytes(ret)


# The maintenance lane, pinned from maintenance.yaml::usb_interface_layout.
# Hardcoded as the safe default here (the G6020 has bulk endpoints on iface 0
# before iface 4, so auto-pick would grab the wrong lane); callers may override.
MAINT_INTERFACE = 4
MAINT_BULK_OUT = 0x03
MAINT_BULK_IN = 0x86


@contextmanager
def open_g6020(
    product_id: int = 0x1865,
    *,
    interface: int | None = MAINT_INTERFACE,
    bulk_out_ep: int | None = MAINT_BULK_OUT,
    bulk_in_ep: int | None = MAINT_BULK_IN,
) -> Iterator[ClaimedDevice]:
    """Locate the Canon G6020 (or family-compatible product id) and yield a
    ClaimedDevice bound to the maintenance lane (interface 4, OUT 0x03 / IN 0x86)
    by default. The endpoints are VERIFIED against the descriptor — a mismatch
    refuses rather than binding the wrong interface. Pass ``interface=None`` to
    auto-pick the first bulk in+out pair (probes/tests only)."""
    dev = usb.core.find(idVendor=CANON_VENDOR_ID, idProduct=product_id)
    if dev is None:
        raise UsbAccessError(
            f"no Canon device with productId={product_id:#06x} found on USB; "
            "check that the printer is powered on and the udev rule + "
            "printstack group membership are in place"
        )
    with ClaimedDevice(
        dev, interface=interface, bulk_out_ep=bulk_out_ep, bulk_in_ep=bulk_in_ep
    ) as cd:
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
