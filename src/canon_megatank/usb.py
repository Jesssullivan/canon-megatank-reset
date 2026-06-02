"""Thin pyusb wrapper for Canon G-series USB access.

Safety-by-default:
- Vendor allowlist (only Canon, idVendor=0x04a9, opens succeed).
- Context-managed device claim so the kernel driver gets reattached on exit.
- Bulk endpoint discovery (no hardcoded EP addresses).
- Read transfer (`read_response`: write the RECV header on bulk-OUT, then read
  the reply over a CONTROL-IN transfer — see the transport note below).
- Write transfer (`send_command`: the 0x220038 SEND equivalent) is exposed but
  is a thin unconditional byte-pusher — ALL safety gating lives in
  `ops.reset_absorber`, which is the only thing that may call it.

Transport note (the bulk-IN → control-IN RECV fix)
---------------------------------------------------
The WICReset RECV (``do_read_vendor`` ``FUN_0052cab0`` ⇒ ``DeviceIoControl``
``0x22003c``) is the IN half of ONE combined ``DeviceIoControl`` whose
``lpInBuffer`` is the primed enciphered prefix and ``lpOutBuffer`` is a 5000-byte
reply. Empirically on the 12fe G6020, the bulk-IN endpoint (EP 0x82/0x86) always
returns a zero-length packet (ZLP); the reply is actually delivered over a
CONTROL-IN transfer on EP0. The exact setup packet
(``bmRequestType``/``bRequest``/``wValue``/``wIndex``) is NOT present in the
``.exe``, so it is PARAMETERIZED here via :class:`RecvControlSetup` with a
best-guess default and a :func:`sweep_recv_control_setups` helper that yields the
ranked candidates a probe can try. The SEND half (writing the enciphered prefix
on bulk-OUT) is unchanged.

This is the ONLY module in canon-megatank allowed to import `usb`. All
other code calls into `ClaimedDevice` (see below).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from typing import Any, cast

import usb.core
import usb.util

from .types import UsbAccessError

CANON_VENDOR_ID = 0x04A9

# USB setup-packet direction bit (bit 7 of bmRequestType): set == device→host (IN).
_USB_DIR_IN = 0x80
# bmRequestType for a printer-CLASS, interface-recipient control-IN (0xA1). These
# are the only control-INs that ANSWERED on the live device (GET_DEVICE_ID,
# GET_PORT_STATUS); the vendor 0xC0/0xC1 channel STALLed.
_CLASS_IN_IFACE = 0xA1


@dataclass(frozen=True, slots=True)
class RecvControlSetup:
    """The USB control-IN setup packet used for the maintenance RECV read.

    The RECV half of the WICReset transport is a control-IN transfer on EP0
    (the bulk-IN endpoint only ever ZLPs on the live 12fe device). The exact
    setup packet is not recoverable from the ``.exe``, so it is parameterized:

    - ``bm_request_type`` MUST have the direction bit (0x80) set (device→host).
      A non-IN value is rejected — RECV is always a read.
    - ``b_request`` / ``w_value`` / ``w_index`` are the remaining setup fields.
    - ``length`` is the default read length (callers may still override via the
      ``length=`` kwarg on :meth:`ClaimedDevice.read_response` /
      :meth:`ClaimedDevice.send_and_receive`).

    The default is the printer-class GET_PORT_STATUS read (``0xA1/0x01``), which
    is the most likely RECV channel: on the live device only the standard
    printer-class control-INs answered — ``0xA1/0x00`` (GET_DEVICE_ID) and
    ``0xA1/0x01`` (GET_PORT_STATUS) — while every vendor control-IN
    (``0xC0``/``0xC1``) STALLed and bulk-IN ZLP'd. :data:`RECV_CONTROL_CANDIDATES`
    enumerates the ranked sweep set."""

    bm_request_type: int = _CLASS_IN_IFACE
    b_request: int = 0x01
    w_value: int = 0x0000
    w_index: int = 0x0000
    length: int = 64

    def __post_init__(self) -> None:
        if not self.bm_request_type & _USB_DIR_IN:
            raise UsbAccessError(
                f"RecvControlSetup.bm_request_type={self.bm_request_type:#04x} is "
                "not a control-IN (direction bit 0x80 must be set) — RECV is a read."
            )

    def with_length(self, length: int) -> RecvControlSetup:
        """Return a copy with ``length`` overridden (used when a caller passes an
        explicit read length but reuses the device's configured setup)."""
        return replace(self, length=length)

    def describe(self) -> str:
        return (
            f"bmRequestType={self.bm_request_type:#04x} bRequest={self.b_request:#04x} "
            f"wValue={self.w_value:#06x} wIndex={self.w_index:#06x} len={self.length}"
        )


# Default RECV control-IN setup: the class GET_PORT_STATUS read that answered on
# the live device. Used when no override is supplied to ClaimedDevice/open_g6020.
DEFAULT_RECV_CONTROL_SETUP = RecvControlSetup()

# Ranked sweep set for the probe. Ordered most-likely → least: the two
# printer-class control-INs that ANSWERED on the live 12fe device first
# (0xA1/0x01 GET_PORT_STATUS, 0xA1/0x00 GET_DEVICE_ID), then the vendor
# control-INs (0xC0/0xC1, bRequest 0x00..0x11) that STALLed but are the natural
# DeviceIoControl-style channel and may answer once a session is primed. The
# probe should try these in order and watch for a changed/new reply vs the
# generic 1284-id / status baseline.
RECV_CONTROL_CANDIDATES: tuple[RecvControlSetup, ...] = (
    RecvControlSetup(_CLASS_IN_IFACE, 0x01, 0x0000, 0x0000),  # GET_PORT_STATUS — answered
    RecvControlSetup(_CLASS_IN_IFACE, 0x00, 0x0000, 0x0000),  # GET_DEVICE_ID — answered
    *(
        RecvControlSetup(req_type, b_request, 0x0000, 0x0000)
        for req_type in (0xC0, 0xC1)
        for b_request in range(0x00, 0x12)
    ),
)


def sweep_recv_control_setups(*, include_vendor: bool = True) -> tuple[RecvControlSetup, ...]:
    """Return the ranked RECV control-IN candidates for a probe to sweep.

    The order is the empirical likelihood order (the class reads that answered
    on the live device first). Pass ``include_vendor=False`` to restrict to the
    two class reads (skip the vendor 0xC0/0xC1 scan that STALLed)."""
    if include_vendor:
        return RECV_CONTROL_CANDIDATES
    return tuple(c for c in RECV_CONTROL_CANDIDATES if c.bm_request_type == _CLASS_IN_IFACE)


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
        recv_control_setup: RecvControlSetup | None = None,
    ) -> None:
        if dev.idVendor != CANON_VENDOR_ID:
            raise UsbAccessError(f"refusing to open non-Canon device (vendor={dev.idVendor:#06x})")
        self._dev = dev
        self._kernel_was_attached: bool = False
        self._interface_number: int | None = None
        self._bulk_in_ep: int | None = None
        self._bulk_out_ep: int | None = None
        # The RECV control-IN setup packet (the bulk-IN → control-IN fix). The
        # SEND half still writes the enciphered prefix on bulk-OUT; the RECV half
        # reads over this control-IN transfer. Parameterized + swappable so the
        # probe can sweep candidates (RecvControlSetup rejects a non-IN type).
        self._recv_control_setup: RecvControlSetup = (
            recv_control_setup if recv_control_setup is not None else DEFAULT_RECV_CONTROL_SETUP
        )
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
            raise UsbAccessError(f"could not claim interface {interface}: {exc}") from exc

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

    @property
    def recv_control_setup(self) -> RecvControlSetup:
        """The control-IN setup packet currently used for the RECV read."""
        return self._recv_control_setup

    @recv_control_setup.setter
    def recv_control_setup(self, setup: RecvControlSetup) -> None:
        """Swap the RECV control-IN setup packet (the probe uses this to sweep
        candidates against an already-open device without re-claiming)."""
        self._recv_control_setup = setup

    # ─── RECV read over control-IN (the 0x22003c RECV / bulk-IN ZLP fix) ─────

    def _control_recv(self, length: int, timeout_ms: int) -> bytes:
        """Read the RECV reply over the configured control-IN transfer.

        The bulk-IN endpoint always ZLPs on the live device; the reply rides a
        control-IN transfer on EP0 instead. ``length`` is the read length the
        caller requested (the ``read_response`` / ``send_and_receive`` kwarg);
        only the setup's ``bmRequestType``/``bRequest``/``wValue``/``wIndex`` are
        taken from the configured :class:`RecvControlSetup`. Setup-field errors
        and STALLs surface as :class:`UsbAccessError`."""
        setup = self._recv_control_setup
        try:
            ret = self._dev.ctrl_transfer(
                setup.bm_request_type,
                setup.b_request,
                setup.w_value,
                setup.w_index,
                length,
                timeout=timeout_ms,
            )
        except usb.core.USBError as exc:
            raise UsbAccessError(
                f"control-IN RECV transfer failed ({setup.describe()}): {exc}"
            ) from exc
        # An IN transfer returns the array of bytes read; defensively coerce.
        if isinstance(ret, int):
            return b""
        return bytes(ret)

    # ─── Read-only transfer (the 0x22003c RECV equivalent) ──────────────────

    def read_response(
        self, request_header: bytes, *, timeout_ms: int = 5000, length: int = 64
    ) -> bytes:
        """Issue a RECV: write the request header to the bulk-OUT endpoint, then
        read the reply over a CONTROL-IN transfer (EP0), not bulk-IN.

        This is the Linux equivalent of the Service Tool's ``0x22003c`` RECV
        IOCTL (prime ``[cmd][arg_hi][arg_lo]``, read the response back). The
        bulk-IN endpoint (EP 0x82/0x86) only ever ZLPs on the live device, so
        the reply is read over the parameterized control-IN setup
        (:attr:`recv_control_setup`, default ``0xA1/0x01`` GET_PORT_STATUS)
        instead. It is the ONLY read-transfer helper exposed — there is
        deliberately no payload-write/reset method here; the reset path lives
        behind the safety gates in ops.py / replay.py.

        ``request_header`` is the 3-byte header built by
        ``protocol.model.encode_recv_header``; it is written (primed) on
        bulk-OUT exactly as before. Returns the raw reply bytes.
        """
        try:
            self._dev.write(self.bulk_out_endpoint, request_header, timeout=timeout_ms)
        except usb.core.USBError as exc:
            raise UsbAccessError(f"RECV prime (bulk-OUT) failed: {exc}") from exc
        return self._control_recv(length, timeout_ms)

    # ─── Send-primed RECV (the WICReset get_keyword equivalent) ─────────────

    def send_and_receive(self, frame: bytes, *, timeout_ms: int = 5000, length: int = 64) -> bytes:
        """Issue a SEND-primed RECV: write a full ``frame`` to the bulk-OUT
        endpoint, then read the reply over a CONTROL-IN transfer (EP0).

        This is the read-with-payload sibling of :meth:`read_response`. Where
        ``read_response`` writes a bare 3-byte ``[cmd][arg_hi][arg_lo]`` header,
        this writes an arbitrary (typically *enciphered*) frame and then reads
        the response — the shape WICReset's ``get_keyword`` uses: send the
        functor-enciphered ``0x82 …`` prefix on bulk-OUT (EP 0x03, the
        ``0x220038`` SEND equivalent), then read the keyword reply over the
        control-IN setup (the ``0x22003c`` RECV equivalent — the IN half of the
        one combined IOCTL, delivered over control, not bulk-IN which ZLPs).

        Unlike :meth:`send_command` this does NOT mutate printer state by itself
        — opening a session and reading the keyword are reads/handshakes. The
        actual state-changing ``set_command`` still goes through
        :meth:`send_command`, and the whole sequence stays behind the gate stack
        in ``ops.reset_absorber_wicreset``. ``frame`` is the enciphered bytes
        Lane A's encoder produced. Returns the raw reply bytes.
        """
        try:
            self._dev.write(self.bulk_out_endpoint, frame, timeout=timeout_ms)
        except usb.core.USBError as exc:
            raise UsbAccessError(f"send-primed RECV prime (bulk-OUT) failed: {exc}") from exc
        return self._control_recv(length, timeout_ms)

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
    recv_control_setup: RecvControlSetup | None = None,
) -> Iterator[ClaimedDevice]:
    """Locate the Canon G6020 (or family-compatible product id) and yield a
    ClaimedDevice bound to the maintenance lane (interface 4, OUT 0x03 / IN 0x86)
    by default. The endpoints are VERIFIED against the descriptor — a mismatch
    refuses rather than binding the wrong interface. Pass ``interface=None`` to
    auto-pick the first bulk in+out pair (probes/tests only).

    ``recv_control_setup`` overrides the RECV control-IN setup packet (default
    ``0xA1/0x01`` GET_PORT_STATUS). A probe sweeping candidates can either pass
    one here per open or mutate ``cd.recv_control_setup`` between reads."""
    dev = usb.core.find(idVendor=CANON_VENDOR_ID, idProduct=product_id)
    if dev is None:
        raise UsbAccessError(
            f"no Canon device with productId={product_id:#06x} found on USB; "
            "check that the printer is powered on and the udev rule + "
            "printstack group membership are in place"
        )
    with ClaimedDevice(
        dev,
        interface=interface,
        bulk_out_ep=bulk_out_ep,
        bulk_in_ep=bulk_in_ep,
        recv_control_setup=recv_control_setup,
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
