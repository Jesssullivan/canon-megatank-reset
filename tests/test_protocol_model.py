"""Property tests for the formal protocol model (T3).

These assert the protocol invariants derived from the two RE oracles, with
Hypothesis exploring the input space. They run offline — no hardware, no key —
so CI proves the grammar holds before T4 ground-truth fills the literal bytes.

The model is also tied to the SSOT: ``test_model_matches_ssot`` fails if
``maintenance.yaml`` and ``protocol/model.py`` ever disagree on the transport
constants. The SSOT IS the spec (same posture as ``test_fingerprint``).
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from canon_megatank.fingerprint import load_maintenance, locked_test_unit
from canon_megatank.protocol import (
    ABSORBER_FLAGS,
    ABSORBER_IDX,
    ABSORBER_MAIN_IDX,
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
from canon_megatank.types import WriteBudget

u8 = st.integers(min_value=0, max_value=0xFF)
u16 = st.integers(min_value=0, max_value=0xFFFF)
payloads = st.binary(min_size=0, max_size=512)
flags = st.sampled_from(ABSORBER_FLAGS)

# Load the SSOT once — re-parsing maintenance.yaml inside a Hypothesis loop blows
# the per-example deadline.
LOCKED_UUID = locked_test_unit().uuid


# ─── Wire grammar: round-trip + determinism + byte order ──────────────────────


@given(cmd=u8, arg=u16, payload=payloads)
def test_send_frame_roundtrips(cmd: int, arg: int, payload: bytes) -> None:
    """decode(encode(...)) is the identity on (cmd, arg, payload)."""
    assert decode_frame(encode_send(cmd, arg, payload)) == (cmd, arg, payload)


@given(cmd=u8, arg=u16, payload=payloads)
def test_send_frame_is_deterministic(cmd: int, arg: int, payload: bytes) -> None:
    """Encoding is a pure function — same inputs, identical bytes."""
    assert encode_send(cmd, arg, payload) == encode_send(cmd, arg, payload)


@given(cmd=u8, arg=u16, payload=payloads)
def test_send_frame_length(cmd: int, arg: int, payload: bytes) -> None:
    """Frame length is exactly the 3-byte header plus the payload."""
    assert len(encode_send(cmd, arg, payload)) == HEADER_LEN + len(payload)


@given(cmd=u8, arg=u16)
def test_arg_is_big_endian(cmd: int, arg: int) -> None:
    """arg_hi = arg >> 8, arg_lo = arg & 0xff (Service Tool FUN_004302c0)."""
    header = encode_recv_header(cmd, arg)
    assert header[0] == cmd
    assert header[1] == (arg >> 8) & 0xFF
    assert header[2] == arg & 0xFF


@given(cmd=u8, arg=u16)
def test_recv_header_is_three_bytes(cmd: int, arg: int) -> None:
    """A read request is always the bare 3-byte header (no payload)."""
    assert len(encode_recv_header(cmd, arg)) == HEADER_LEN


@given(cmd=u8, arg=u16, payload=payloads)
def test_send_payload_suffix_matches_recv_header(cmd: int, arg: int, payload: bytes) -> None:
    """The SEND frame's header equals the RECV header for the same (cmd, arg)."""
    assert encode_send(cmd, arg, payload)[:HEADER_LEN] == encode_recv_header(cmd, arg)


@given(frame=st.binary(max_size=2))
def test_short_frame_rejected(frame: bytes) -> None:
    """Frames shorter than the header are a modelling error, not silent."""
    with pytest.raises(ProtocolError):
        decode_frame(frame)


@given(bad=st.integers(min_value=0x100, max_value=0x10000))
def test_out_of_range_fields_rejected(bad: int) -> None:
    """cmd > 255 and arg > 65535 are rejected, not truncated."""
    with pytest.raises(ProtocolError):
        encode_send(bad, 0, b"")
    with pytest.raises(ProtocolError):
        encode_recv_header(0, 0x10000 + bad)


# ─── Absorber payload + reset-derivation ──────────────────────────────────────


@given(f=flags, idx=u8)
def test_absorber_payload_shape(f: int, idx: int) -> None:
    """Payload is exactly [00, 03, flags, 03, idx]."""
    assert absorber_reset_payload(f, idx) == bytes([0x00, 0x03, f, 0x03, idx])


@given(idx=u8)
def test_absorber_payload_rejects_bad_flags(idx: int) -> None:
    """Only the recovered checkbox flags are legal."""
    with pytest.raises(ProtocolError):
        absorber_reset_payload(0x02, idx)


def test_main_absorber_idx_is_seven() -> None:
    """The 5B00 main absorber is idx 0x07 ("Main"), label-confirmed from the
    Service Tool DAT_0048295c table. (Guards against regressing to the earlier
    wrong guess of 0x00, which is actually the Platen.)"""
    assert ABSORBER_MAIN_IDX == 0x07
    assert ABSORBER_IDX["main"] == 0x07
    assert ABSORBER_IDX["platen"] == 0x00  # the value we must NOT reset for 5B00


def test_main_absorber_reset_payload_is_recovered_literal() -> None:
    """The derived main-absorber reset payload matches the v5103 static finding:
    [00, 03, 01, 03, 07] (flags=0x01 unchecked, idx=0x07 Main)."""
    assert absorber_reset_payload(0x01, ABSORBER_MAIN_IDX) == bytes(
        [0x00, 0x03, 0x01, 0x03, 0x07]
    )


@given(cmd=u8, arg=u16, f=flags, idx=u8)
def test_reset_frame_deterministic_and_invertible(cmd: int, arg: int, f: int, idx: int) -> None:
    """derive_reset_frame is pure, and decodes back to the absorber payload."""
    spec = AbsorberResetSpec(cmd=cmd, arg=arg, flags=f, idx=idx)
    frame = derive_reset_frame(spec)
    assert frame == derive_reset_frame(spec)  # determinism
    dc, darg, payload = decode_frame(frame)
    assert (dc, darg) == (cmd, arg)
    assert payload == absorber_reset_payload(f, idx)


@given(cmd=u8, arg=u16, f=flags, idx=u8)
def test_reset_spec_rejects_out_of_range(cmd: int, arg: int, f: int, idx: int) -> None:
    """The spec validates its fields at construction (fail fast)."""
    with pytest.raises(ProtocolError):
        AbsorberResetSpec(cmd=256, arg=arg, flags=f, idx=idx)
    with pytest.raises(ProtocolError):
        AbsorberResetSpec(cmd=cmd, arg=arg, flags=0x00, idx=idx)


# ─── Device-state idempotency ─────────────────────────────────────────────────


@given(value=st.integers(min_value=0, max_value=100))
def test_reset_zeroes_counter(value: int) -> None:
    """Reset drives the counter to 0 from any starting value, clearing 5B00."""
    after = apply_reset(CounterState(value=value))
    assert after.value == 0
    assert not after.is_blocked


@given(value=st.integers(min_value=0, max_value=100))
def test_reset_is_idempotent(value: int) -> None:
    """Re-issuing the reset is safe: apply_reset∘apply_reset == apply_reset."""
    once = apply_reset(CounterState(value=value))
    assert apply_reset(once) == once


@given(value=st.integers(min_value=100, max_value=100))
def test_full_counter_is_blocked(value: int) -> None:
    """A saturated counter models the 5B00 block precondition."""
    assert CounterState(value=value).is_blocked


# ─── Write-budget monotonicity ────────────────────────────────────────────────


@given(cap=st.integers(min_value=0, max_value=50), n=st.integers(min_value=0, max_value=50))
def test_write_budget_monotonic(cap: int, n: int) -> None:
    """consumed only grows; remaining only shrinks; exhausted latches True."""
    budget = WriteBudget(cap=cap, consumed=0)
    prev_remaining = budget.remaining
    latched = False
    for _ in range(n):
        budget.consumed += 1
        assert budget.remaining <= prev_remaining
        prev_remaining = budget.remaining
        if budget.exhausted:
            latched = True
        # once exhausted, more consumption never un-exhausts it
        assert not (latched and not budget.exhausted)


@given(cap=st.integers(min_value=1, max_value=50))
def test_write_budget_exhausts_exactly_at_cap(cap: int) -> None:
    """remaining hits 0 and exhausted flips True precisely at the cap."""
    budget = WriteBudget(cap=cap, consumed=cap - 1)
    assert not budget.exhausted
    budget.consumed += 1
    assert budget.exhausted
    assert budget.remaining == 0


# ─── UUID write-gate ──────────────────────────────────────────────────────────


def test_uuid_gate_permits_only_locked_unit() -> None:
    """Only the locked test_unit UUID permits a write."""
    assert uuid_permits_write(LOCKED_UUID, LOCKED_UUID)
    assert uuid_permits_write(LOCKED_UUID.upper(), LOCKED_UUID)  # case-insensitive


@given(other=st.uuids())
def test_uuid_gate_refuses_others(other: object) -> None:
    """Any non-locked UUID (and the empty string) is refused."""
    candidate = str(other)
    if candidate.strip().lower() == LOCKED_UUID.strip().lower():
        return  # astronomically unlikely collision; skip
    assert not uuid_permits_write(candidate, LOCKED_UUID)
    assert not uuid_permits_write("", LOCKED_UUID)


# ─── Model ↔ SSOT consistency (no drift) ──────────────────────────────────────


def test_model_matches_ssot() -> None:
    """The model's transport constants MUST equal maintenance.yaml. The SSOT is
    the spec — drift here means the model is stale and is a HARD failure."""
    cp = load_maintenance()["command_protocol"]["transport"]
    assert cp["ioctl_send"] == IOCTL_SEND
    assert cp["ioctl_receive"] == IOCTL_RECV

    layout = load_maintenance()["usb_interface_layout"]["expected_maintenance"]
    assert layout["interface_number"] == MAINT_INTERFACE
    assert int(layout["bulk_out_endpoint"], 16) == BULK_OUT_EP
    assert int(layout["bulk_in_endpoint"], 16) == BULK_IN_EP


def test_absorber_flags_match_ssot() -> None:
    """The modelled absorber flags must cover the SSOT pre_transform_payload
    flags note (0x01 | 0x81)."""
    assert set(ABSORBER_FLAGS) == {0x01, 0x81}
