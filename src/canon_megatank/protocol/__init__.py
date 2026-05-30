"""Formal, offline, CI-checkable model of the Canon MegaTank maintenance protocol.

Re-exports the public surface of :mod:`canon_megatank.protocol.model`.
"""

from __future__ import annotations

from canon_megatank.protocol.model import (
    ABSORBER_FLAGS,
    BULK_IN_EP,
    BULK_OUT_EP,
    HEADER_LEN,
    IOCTL_RECV,
    IOCTL_SEND,
    MAINT_INTERFACE,
    AbsorberResetSpec,
    CounterState,
    ProtocolError,
    absorber_reset_payload,
    apply_reset,
    decode_frame,
    derive_reset_frame,
    encode_recv_header,
    encode_send,
    uuid_permits_write,
)

__all__ = [
    "ABSORBER_FLAGS",
    "BULK_IN_EP",
    "BULK_OUT_EP",
    "HEADER_LEN",
    "IOCTL_RECV",
    "IOCTL_SEND",
    "MAINT_INTERFACE",
    "AbsorberResetSpec",
    "CounterState",
    "ProtocolError",
    "absorber_reset_payload",
    "apply_reset",
    "decode_frame",
    "derive_reset_frame",
    "encode_recv_header",
    "encode_send",
    "uuid_permits_write",
]
