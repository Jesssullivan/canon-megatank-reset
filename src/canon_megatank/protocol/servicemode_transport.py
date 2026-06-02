"""Native libusb service-mode transport for the Canon G6020 (04a9:12fe).

This module replicates, on Linux/libusb, the EXACT USB control transfers that
Windows' ``usbprint.sys`` emits for its ``VENDOR_SET_COMMAND`` (IOCTL 0x220038),
``VENDOR_GET_COMMAND`` (0x22003c) and ``GET_1284_ID`` (0x220034) IOCTLs. It is the
Lane 2 (pure-native) replacement for the parameterized / guessed RECV control
setup in :mod:`canon_megatank.usb` — here the SET/GET setup packets are no longer
guessed: they are DERIVED byte-for-byte from a static decompile of
``usbprint.sys``.

It exposes a :class:`ServiceModeTransport` whose surface satisfies
``ops.WicSessionDevice`` (``send_and_receive`` + ``send_command``) and
``ops.ReadableDevice`` (``read_response``) so it can drive
``ops.reset_absorber_wicreset`` unchanged. It does NOT open hardware itself; it is
constructed around an injected control-transfer callable (``usb.ClaimedDevice``
satisfies it), which keeps it unit-shaped and hardware-free for tests.

================================================================================
EVIDENCE — usbprint.sys 10.0.26100.8328 (Win11 24H2)
  SHA256 3eb6b8172849290bac6ff548b53fbf78c37c6f68a22bdc604b12418d1b22a968
  (110592 bytes; PE32+ native x86-64). Decompiled statically; NO hardware touched.
================================================================================

IRP_MJ_DEVICE_CONTROL dispatcher @ 0x140004c8d:
    mov eax, [rdx+0x18]          ; eax = IoControlCode
    ...
    add eax, 0xffddffd0          ; eax -= 0x2200030  (normalize)
    cmp eax, 0x34 / ja default
    movzx eax, [B + eax + 0x1140c]      ; byte index table
    mov  ecx, [B + idx*4  + 0x113d0]    ; dword jump-offset table
    jmp  B+ecx                          ; (B = image base 0x140000000)
  Resolved jump table -> handlers:
    0x220030 GET_LPT_STATUS -> 0x1400050bb
    0x220034 GET_1284_ID    -> 0x140005056 (-> shared 0x140001ca0)
    0x220038 VENDOR_SET     -> 0x1400051d4
    0x22003c VENDOR_GET     -> 0x1400026e0

All three build a _URB_CONTROL_VENDOR_OR_CLASS_REQUEST (size 0x88) and submit it
to the USB bus driver via an IOCTL_INTERNAL_USB_SUBMIT_URB (0x220003) IRP. 64-bit
URB field offsets used (canonical Windows layout):
    +0x00  Hdr.Length (u16) / Hdr.Function (u16)
    +0x20  TransferFlags (u32)
    +0x24  TransferBufferLength (u32)
    +0x28  TransferBuffer (ptr)
    +0x30  TransferBufferMDL (ptr)
    +0x38  UrbLink (ptr)
    +0x80  RequestTypeReservedBits (u8)
    +0x81  Request   (u8)  == bRequest
    +0x82  Value     (u16) == wValue
    +0x84  Index     (u16) == wIndex

VENDOR_SET handler @ 0x1400051d4 (input buffer = rdi = Irp->SystemBuffer,
                                  InputBufferLength = ebx = [stack+0x10]):
    cmp ebx,3 / jb fail                 ; InputBufferLength >= 3 required
    ... ExAllocatePool2(0x88,'USBP') -> rdx ...
    movzx r8d,[rdi+1] ; movzx eax,[rdi+2] ; movzx r9d,[rdi]
    shl r8w,8 ; or r8w,ax               ; r8w = (inBuf[1]<<8)|inBuf[2]
    ; cx = (ifaceDesc[2]<<8)|ifaceDesc[3]   from [dev+0x550]/[+0x558]
    mov [rdx+0x82], r8w                 ; wValue = (inBuf[1]<<8)|inBuf[2]
    mov [rdx+0x84], cx                  ; wIndex = (bInterfaceNumber<<8)|bAltSetting
    mov dword [rdx], 0x180088           ; Function=0x0018 VENDOR_INTERFACE, Len=0x88
    mov [rdx+0x24], ebx                 ; TransferBufferLength = InputBufferLength
    mov [rdx+0x30], 0                   ; TransferBufferMDL = NULL
    mov [rdx+0x28], rdi                 ; TransferBuffer    = SystemBuffer (WHOLE inBuf)
    mov byte [rdx+0x80], 0              ; RequestTypeReservedBits = 0
    mov byte [rdx+0x81], r9b            ; Request (bRequest) = inBuf[0]
    mov dword [rdx+0x20], 0             ; TransferFlags = 0  -> OUT (host->device)
    mov [rdx+0x38], 0                   ; UrbLink = NULL

VENDOR_GET worker @ 0x1400026e0 (mirror of SET; differs only in direction/length):
    mov [r14+0x81], dl                  ; Request = inBuf[0]
    mov [r14+0x82], r8w                 ; wValue  = (inBuf[1]<<8)|inBuf[2]
    mov [r14+0x84], cx                  ; wIndex  = (bInterfaceNumber<<8)|bAltSetting
    mov dword [r14], 0x180088           ; Function 0x0018 VENDOR_INTERFACE
    mov [r14+0x24], edi                 ; TransferBufferLength = OutputBufferLength
    mov [r14+0x28], r15                 ; TransferBuffer = SystemBuffer (reused for OUT data)
    mov dword [r14+0x20], 3             ; TransferFlags = IN | SHORT_TRANSFER_OK -> IN

GET_1284_ID helper @ 0x140001ca0 (cross-check that this decode reading is correct):
    mov dword [rbx], 0x1b0088           ; Function=0x001b CLASS_INTERFACE, Len=0x88
    ; (Request @0x81 NOT written -> 0 = GET_DEVICE_ID ; Value @0x82 NOT written -> 0)
    mov [rbx+0x84], si  (si = ifaceDesc[2]<<8)  ; wIndex = bInterfaceNumber<<8
    mov dword [rbx+0x20], 3             ; TransferFlags = IN | SHORT_OK
  -> reproduces the CONFIRMED 0xA1 / bRequest=0x00 / wValue=0 / wIndex=iface mapping,
     proving the field-offset reading above is correct.

bmRequestType assembled by USBD from {Hdr.Function, TransferFlags}:
    type      : VENDOR_* (0x18) -> 0x40 (vendor) ; CLASS_* (0x1b) -> 0x20 (class)
    recipient : *_INTERFACE     -> 0x01 (interface)
    direction : TransferFlags & USBD_TRANSFER_DIRECTION_IN(0x1) -> 0x80 (IN)
  => GET_1284_ID  : 0x20|0x01|0x80 = 0xA1   (CONFIRMED)
  => VENDOR_GET   : 0x40|0x01|0x80 = 0xC1   (CONFIRMED)
  => VENDOR_SET   : 0x40|0x01|0x00 = 0x41   (DERIVED — vendor control-OUT, recipient=interface)

THE decisive SET detail (why a naive 0x41/0x81 try STALLed on the live device):
  usbprint does NOT strip inBuf[0..2] before the data stage. The OUT data stage is
  the WHOLE InputBuffer (TransferBuffer = SystemBuffer, length = InputBufferLength).
  inBuf[0] is used for bRequest AND remains the first byte of the OUT payload; the
  wValue bytes inBuf[1..2] likewise remain in the payload. Splitting the frame
  (stripping the prefix into the setup-only fields) yields a DIFFERENT data stage
  and the device stalls. Reproduce the frame VERBATIM as the OUT data.

Concrete resulting transfers (12fe service-mode, iface 0 / alt 0 => wIndex=0x0000):
  set_session  81 00 00 03 2d 2d ba 2b
    -> 0x41 / bReq=0x81 / wValue=0x0000 / wIndex=0x0000 / data = the WHOLE 8 bytes
  set_command  85 00 00 00 00 10 07 7c 40 40 8f ec
    -> 0x41 / bReq=0x85 / wValue=0x0000 / wIndex=0x0000 / data = the WHOLE 12 bytes
  set_command  85 00 00 00 00 0d 00 00 40 40 8f ec
    -> 0x41 / bReq=0x85 / wValue=0x0000 / wIndex=0x0000 / data = the WHOLE 12 bytes

NOTE ON wVALUE ENDIANNESS: the decompile is explicit that
``wValue = (inBuf[1] << 8) | inBuf[2]`` (inBuf[1] = HIGH byte). The two confirmed
ground-truth captures used arg bytes 00 00 and cannot disambiguate the order; all
three target SET frames also carry 00 00, so wValue = 0x0000 regardless. Should a
future frame carry non-zero arg bytes, this module follows the decompiled
``(hi=inBuf[1], lo=inBuf[2])`` order — see :func:`_wvalue_from_app_frame`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

# ─── Derived USB constants (see module docstring for the usbprint.sys evidence) ──

# bmRequestType pieces.
_DIR_IN = 0x80
_TYPE_VENDOR = 0x40
_TYPE_CLASS = 0x20
_RCPT_INTERFACE = 0x01

# Vendor, recipient=interface (URB_FUNCTION_VENDOR_INTERFACE, 0x0018).
BMREQTYPE_VENDOR_SET = _TYPE_VENDOR | _RCPT_INTERFACE              # 0x41 (OUT)
BMREQTYPE_VENDOR_GET = _TYPE_VENDOR | _RCPT_INTERFACE | _DIR_IN    # 0xC1 (IN)
# Class, recipient=interface (URB_FUNCTION_CLASS_INTERFACE, 0x001b): GET_DEVICE_ID.
BMREQTYPE_GET_1284_ID = _TYPE_CLASS | _RCPT_INTERFACE | _DIR_IN    # 0xA1 (IN)
GET_1284_ID_BREQUEST = 0x00  # GET_DEVICE_ID

# WICReset app-frame layout: [cmd][arg_hi][arg_lo][payload...]. usbprint maps:
#   bRequest = inBuf[0] ; wValue = (inBuf[1]<<8)|inBuf[2] ; data = WHOLE inBuf.
_APP_FRAME_MIN = 3  # usbprint's VENDOR handlers require InputBufferLength >= 3.

# Default read length for a send-primed RECV (matches ops' keyword_len default).
DEFAULT_RECV_LEN = 64


# A single EP0 control transfer, signature-compatible with
# ``usb.ClaimedDevice.control_transfer`` (and trivially fakeable in tests).
ControlTransferFn = Callable[..., bytes]


def _wvalue_from_app_frame(frame: bytes) -> int:
    """wValue per the usbprint decompile: ``(inBuf[1] << 8) | inBuf[2]``."""
    return ((frame[1] << 8) | frame[2]) & 0xFFFF


def _check_frame(frame: bytes) -> None:
    if len(frame) < _APP_FRAME_MIN:
        raise ValueError(
            f"service-mode app frame too short ({len(frame)} < {_APP_FRAME_MIN}); "
            "usbprint.sys VENDOR handlers require InputBufferLength >= 3 "
            "(cmd + 2 arg bytes)."
        )


@dataclass(frozen=True, slots=True)
class VendorSetup:
    """The resolved control-transfer setup for one app frame (audit/dry-run)."""

    bm_request_type: int
    b_request: int
    w_value: int
    w_index: int
    data_or_length: bytes | int

    @property
    def is_out(self) -> bool:
        return (self.bm_request_type & _DIR_IN) == 0

    def describe(self) -> str:
        tail = (
            f"data={self.data_or_length.hex()}"
            if isinstance(self.data_or_length, bytes)
            else f"wLength={self.data_or_length}"
        )
        return (
            f"bmRequestType=0x{self.bm_request_type:02x} bRequest=0x{self.b_request:02x} "
            f"wValue=0x{self.w_value:04x} wIndex=0x{self.w_index:04x} {tail}"
        )


def vendor_set_setup(frame: bytes, *, w_index: int = 0x0000) -> VendorSetup:
    """Resolve the VENDOR_SET (0x220038) control-OUT for a WICReset SET frame.

    ``data`` is the WHOLE app frame (usbprint does NOT strip the prefix). ``w_index``
    is ``(bInterfaceNumber << 8) | bAlternateSetting``; the 12fe service-mode device
    is iface 0 / alt 0, hence 0x0000."""
    _check_frame(frame)
    return VendorSetup(
        bm_request_type=BMREQTYPE_VENDOR_SET,
        b_request=frame[0],
        w_value=_wvalue_from_app_frame(frame),
        w_index=w_index,
        data_or_length=bytes(frame),
    )


def vendor_get_setup(
    frame: bytes, *, length: int = DEFAULT_RECV_LEN, w_index: int = 0x0000
) -> VendorSetup:
    """Resolve the VENDOR_GET (0x22003c) control-IN for a WICReset GET frame.

    The IN read length is ``length`` (OutputBufferLength in the IOCTL). The 3-byte
    ``[cmd][arg_hi][arg_lo]`` prefix supplies bRequest + wValue exactly as for SET."""
    _check_frame(frame)
    return VendorSetup(
        bm_request_type=BMREQTYPE_VENDOR_GET,
        b_request=frame[0],
        w_value=_wvalue_from_app_frame(frame),
        w_index=w_index,
        data_or_length=length,
    )


def get_1284_id_setup(*, length: int = 1024, w_index: int = 0x0000) -> VendorSetup:
    """Resolve the GET_1284_ID (0x220034) class control-IN (GET_DEVICE_ID)."""
    return VendorSetup(
        bm_request_type=BMREQTYPE_GET_1284_ID,
        b_request=GET_1284_ID_BREQUEST,
        w_value=0x0000,
        w_index=w_index,
        data_or_length=length,
    )


class ServiceModeTransport:
    """WicSessionDevice over the usbprint-derived EP0 vendor control transport.

    Satisfies ``ops.WicSessionDevice`` (``send_and_receive`` + ``send_command``)
    and ``ops.ReadableDevice`` (``read_response``). It owns NO USB handle: it wraps
    an injected ``control_transfer`` callable shaped like
    ``usb.ClaimedDevice.control_transfer(bmRequestType, bRequest, wValue, wIndex,
    data_or_length, *, timeout_ms=...)``. This keeps it hardware-free and
    unit-testable (drive it with a recording fake).

    Semantics (all derived from usbprint.sys — see module docstring):

    * ``send_command(frame)``      -> VENDOR_SET control-OUT (0x41), the WHOLE frame
                                      as the OUT data stage. Used for set_session /
                                      set_command writes. Returns bytes "written".
    * ``send_and_receive(frame)``  -> VENDOR_GET control-IN (0xC1) keyed by the
                                      frame's 3-byte prefix. Used for the
                                      send-primed RECVs (set_session ack / get_keyword
                                      / get_command verify). Returns the reply bytes.
    * ``read_response(header)``    -> VENDOR_GET control-IN for a bare 3-byte header
                                      (the 0x22003c RECV equivalent).

    ``w_index`` defaults to 0x0000 (iface 0 / alt 0 — the 12fe service-mode device).
    Pass ``w_index=(bInterfaceNumber<<8)|bAltSetting`` for any other layout.
    """

    def __init__(
        self,
        control_transfer: ControlTransferFn,
        *,
        w_index: int = 0x0000,
    ) -> None:
        self._ctrl = control_transfer
        self._w_index = w_index & 0xFFFF

    # ─── set_session / set_command — VENDOR_SET control-OUT (0x41) ──────────────
    def send_command(self, frame: bytes, *, timeout_ms: int = 5000) -> int:
        """SEND a WICReset frame as a usbprint VENDOR_SET control-OUT.

        ⚠ This is the state-mutating write (the 0x220038 equivalent). It is a thin,
        unconditional byte-pusher; ALL safety gating lives in
        ``ops.reset_absorber_wicreset`` and MUST pass before this is reached."""
        s = vendor_set_setup(frame, w_index=self._w_index)
        self._ctrl(
            s.bm_request_type, s.b_request, s.w_value, s.w_index,
            s.data_or_length, timeout_ms=timeout_ms,
        )
        return len(frame)

    # ─── set_session (OUT) / get_keyword / get_command (IN) ─────────────────────
    def send_and_receive(
        self, frame: bytes, *, timeout_ms: int = 5000, length: int = DEFAULT_RECV_LEN
    ) -> bytes:
        """SEND-primed RECV step. Routes by frame SHAPE to the validated direction
        (see docs/research/canon-service-mode-field-guide.md), because the WICReset
        session mixes an OUT open with two IN reads under this one op-level call:

        * A bare 3-byte READ HEADER (``82 00 00`` get_keyword / ``86 00 00``
          get_command) is a VENDOR_GET control-IN (``0xC1``): the 3-byte prefix
          supplies bRequest+wValue and the device returns the reply
          (the 0x22003c equivalent). This is the path that reads the live keyword.

        * A WRITE-SHAPED frame (> 3 bytes, i.e. it carries an operand/payload — the
          enciphered ``set_session`` 23-byte ``81 00 00 ...`` frame) is a VENDOR_SET
          control-OUT (``0x41/0x81``), driven exactly like :meth:`send_command`:
          usbprint puts the WHOLE buffer in the OUT data stage. set_session is an
          OUT with no IN data stage, and the op discards its reply, so this returns
          ``b""``. Routing it as an IN (``0xC1/0x81``) STALLed on the live device —
          the validated native open is the OUT.

        ``length`` is the IN read length for the VENDOR_GET path (ignored for the
        OUT path)."""
        if len(frame) > _APP_FRAME_MIN:  # write-shaped (carries operand) -> VENDOR_SET OUT
            self.send_command(frame, timeout_ms=timeout_ms)
            return b""
        s = vendor_get_setup(frame, length=length, w_index=self._w_index)
        return self._ctrl(
            s.bm_request_type, s.b_request, s.w_value, s.w_index,
            s.data_or_length, timeout_ms=timeout_ms,
        )

    # ─── bare RECV header (the 0x22003c RECV equivalent) ────────────────────────
    def read_response(
        self, request_header: bytes, *, timeout_ms: int = 5000, length: int = DEFAULT_RECV_LEN
    ) -> bytes:
        """RECV a reply for a bare 3-byte ``[cmd][arg_hi][arg_lo]`` header via the
        VENDOR_GET control-IN (the read-only 0x22003c path)."""
        return self.send_and_receive(request_header, timeout_ms=timeout_ms, length=length)

    # ─── 1284 device-ID (GET_1284_ID, 0x220034) — read-only probe ───────────────
    def read_1284_id(self, *, length: int = 1024, timeout_ms: int = 5000) -> bytes:
        """Read the IEEE-1284 device-ID string (class GET_DEVICE_ID, 0xA1/0x00).

        Returns the raw reply; the first 2 bytes are a big-endian length prefix
        (``MFG:Canon;...;MDL:...`` follows), exactly as usbprint's GET_1284_ID."""
        s = get_1284_id_setup(length=length, w_index=self._w_index)
        return self._ctrl(
            s.bm_request_type, s.b_request, s.w_value, s.w_index,
            s.data_or_length, timeout_ms=timeout_ms,
        )
