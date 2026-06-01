"""Tests for the WICReset-derived enciphered session→keyword→clear sequence.

``ops.reset_absorber_wicreset`` drives the ORDERED WICReset bulk session
(set_session → get_keyword → set_command(10 07 7C) → set_command(0D 00 00) →
verify), every frame functor-3 enciphered by a Lane A encoder. As with the two
sibling reset paths, the point is the SAFETY GATES + the ORDER, so these assert:

  (a) the literal frames come from the SSOT derived_template (no hardcoding);
  (b) dry-run enciphers + previews but drives NOTHING and consults NO gate;
  (c) execute=True is blocked at each gate IN ORDER (UUID, status, EEPROM,
      budget) and never touches the device when a gate refuses;
  (d) the happy path drives EXACTLY the ordered sequence, seeds the encoder with
      the keyword read at step 2, and uses send_and_receive for the read steps /
      send_command for the writes.

A fake device records every transfer (and its order/kind) so we can prove what
was driven; a fake encoder records the plaintext frames it was asked to encipher
and the keyword it was seeded with.
"""

from __future__ import annotations

import pytest

import canon_megatank.protocol.wicreset as wic
from canon_megatank.ops import (
    WicResetFrames,
    load_wicreset_frames,
    reset_absorber_wicreset,
)
from canon_megatank.types import (
    CanonToolError,
    EepromDumpFailedError,
    PrinterFingerprint,
    ResetNotValidatedError,
    UnknownPrinterError,
    WriteBudgetExhaustedError,
)

FP = PrinterFingerprint(
    uuid="00000000-0000-1000-8000-00186501807c",
    firmware_version="1.070",
    device_id_raw="",
    cmd_set=(),
)

# The recovered CANON-IPL template prefixes + functions.waste rows (devices.xml
# lines 43504/43506/43507/43508 and 43807), as the SSOT derived_template carries
# them. The test loader mirrors the SSOT shape so we never depend on the real file.
DERIVED_TEMPLATE = {
    "commands": {
        # devices.xml on-wire headers (the '0x0000000' arg word collapses to one
        # wire byte): set_session=81 00 00 03, get_keyword/get_command=82/86 00 00,
        # set_command=85 00 00 (the 3-byte SEND header). Re-synced 2026-06-01 to
        # match the shipped SSOT + the validated native frame 85 00 00 || 10 07 7c.
        "set_session": "0x81 0x00 0x00 0x03",
        "get_version": "0x8A 0x00 0x00",
        "get_keyword": "0x82 0x00 0x00",
        "get_command": "0x86 0x00 0x00",
        "set_command": "0x85 0x00 0x00",
    },
    "functions_waste": {
        "common": {"commands": ["0x10 0x07 0x7C", "0x0D 0x00 0x00"]},
        "platen": {"commands": ["0x10 0x07 0x7C", "0x0D 0x01 0x00"]},
    },
}


def _doc(status: str) -> dict:
    return {
        "supported": {
            "absorber_reset": {
                "status": status,
                "derived_template": DERIVED_TEMPLATE,
            }
        }
    }


def _validated_doc(_pid: str) -> dict:
    return _doc("verified-captured")


def _unvalidated_doc(_pid: str) -> dict:
    return _doc("derived-unvalidated")


def _ok_verify(fp: PrinterFingerprint, printer_id: str) -> None:
    return None


class FakeEncoder:
    """Records the plaintext frames it enciphers + the keyword it was seeded
    with. ``encipher`` returns a recognizable wire form: b'ENC:' + plaintext so
    tests can assert which frame produced which wire bytes WITHOUT a real cipher.
    After ``seed_keyword`` the prefix flips to b'ENCK:' so we can prove the
    set_command frames were enciphered with the keyword already seeded."""

    def __init__(self) -> None:
        self.enciphered: list[bytes] = []
        self.seeded: bytes | None = None

    def encipher(self, plaintext_app_frame: bytes) -> bytes:
        self.enciphered.append(bytes(plaintext_app_frame))
        prefix = b"ENCK:" if self.seeded is not None else b"ENC:"
        return prefix + bytes(plaintext_app_frame)

    def seed_keyword(self, device_keyword: bytes) -> None:
        self.seeded = bytes(device_keyword)


class FakeSessionDevice:
    """Records every transfer as (kind, frame). Serves a canned keyword reply on
    send_and_receive (the RECV steps)."""

    def __init__(self, keyword_reply: bytes = b"\xde\xad\xbe\xef") -> None:
        self.calls: list[tuple[str, bytes]] = []
        self._reply = keyword_reply

    def send_and_receive(self, frame: bytes, *, timeout_ms: int = 5000, length: int = 64) -> bytes:
        self.calls.append(("recv", bytes(frame)))
        return self._reply

    def send_command(self, frame: bytes, *, timeout_ms: int = 5000) -> int:
        self.calls.append(("send", bytes(frame)))
        return len(frame)


# ─── SSOT sourcing: the literal frames come from derived_template ─────────────


def test_load_frames_sources_literals_from_ssot() -> None:
    frames = load_wicreset_frames(region="common", load_doc=_validated_doc)
    assert frames.set_session == bytes([0x81, 0x00, 0x00, 0x03])
    assert frames.get_keyword == bytes([0x82, 0x00, 0x00])
    assert frames.get_command == bytes([0x86, 0x00, 0x00])
    # set_command = 3-byte header 85 00 00 + selector 10 07 7C (frame[3]=0x10)
    assert frames.set_command_select == bytes([0x85, 0x00, 0x00, 0x10, 0x07, 0x7C])
    # set_command = header + the 'common' operand 0D 00 00 (the 5B00 clear)
    assert frames.set_command_reset == bytes([0x85, 0x00, 0x00, 0x0D, 0x00, 0x00])


def test_load_frames_common_is_the_g6000_clear_operand() -> None:
    """The G6000 family clears ONLY 'common' = operand 0D 00 00 (devices.xml:43807)."""
    frames = load_wicreset_frames(region="common", load_doc=_validated_doc)
    assert frames.set_command_reset[-3:] == bytes([0x0D, 0x00, 0x00])


def test_load_frames_rejects_unknown_region() -> None:
    with pytest.raises(CanonToolError):
        load_wicreset_frames(region="away", load_doc=_validated_doc)  # not in this template


def test_load_frames_refuses_without_template() -> None:
    def _no_template(_pid: str) -> dict:
        return {"supported": {"absorber_reset": {"status": "verified-captured"}}}

    with pytest.raises(ResetNotValidatedError):
        load_wicreset_frames(load_doc=_no_template)


def test_load_frames_against_real_ssot() -> None:
    """The shipped maintenance.yaml derived_template parses + yields the
    recovered literals (no hardcoding in the module — the real SSOT drives it)."""
    frames = load_wicreset_frames(region="common")  # default loader → real file
    assert isinstance(frames, WicResetFrames)
    assert frames.set_session == bytes([0x81, 0x00, 0x00, 0x03])
    assert frames.set_command_reset[-3:] == bytes([0x0D, 0x00, 0x00])


# ─── Dry-run enciphers + previews but drives nothing, consults no gate ────────


def test_dry_run_enciphers_all_frames_drives_nothing() -> None:
    dev = FakeSessionDevice()
    enc = FakeEncoder()
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=False,  # gate would fail — but dry-run never checks it
        encoder=enc,
        load_doc=_unvalidated_doc,  # status would fail — dry-run never checks it
    )
    assert plan.executed is False
    assert dev.calls == []  # NOTHING driven
    assert "DRY-RUN" in plan.outcome.response_summary
    # all 5 frames (incl. verify readback) were enciphered for the preview
    assert len(plan.steps) == 5
    assert [s.kind for s in plan.steps] == [
        "set_session",
        "get_keyword",
        "set_command",
        "set_command",
        "get_command",
    ]
    # dry-run never seeds a keyword (no live read happened)
    assert enc.seeded is None


def test_dry_run_without_verify_readback_has_four_steps() -> None:
    dev = FakeSessionDevice()
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=FakeEncoder(),
        verify_readback=False,
        load_doc=_validated_doc,
    )
    assert plan.executed is False
    assert [s.kind for s in plan.steps] == [
        "set_session",
        "get_keyword",
        "set_command",
        "set_command",
    ]


# ─── execute=True blocked at each gate, IN ORDER ──────────────────────────────


def test_execute_blocked_by_uuid_gate_first() -> None:
    dev = FakeSessionDevice()

    def _bad_verify(fp: PrinterFingerprint, pid: str) -> None:
        raise UnknownPrinterError("wrong unit")

    with pytest.raises(UnknownPrinterError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            encoder=FakeEncoder(),
            execute=True,
            verify=_bad_verify,
            load_doc=_validated_doc,
        )
    assert dev.calls == []  # nothing driven


def test_execute_blocked_by_unverified_status() -> None:
    """derived-unvalidated → HARD STOP: the sequence is derived, not validated."""
    dev = FakeSessionDevice()
    with pytest.raises(ResetNotValidatedError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            encoder=FakeEncoder(),
            execute=True,
            verify=_ok_verify,
            load_doc=_unvalidated_doc,
        )
    assert dev.calls == []


def test_execute_blocked_without_eeprom_dump() -> None:
    dev = FakeSessionDevice()
    with pytest.raises(EepromDumpFailedError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=False,
            encoder=FakeEncoder(),
            execute=True,
            verify=_ok_verify,
            load_doc=_validated_doc,
        )
    assert dev.calls == []


def test_execute_charges_budget_and_can_be_blocked() -> None:
    dev = FakeSessionDevice()

    def _charge_exhausted() -> None:
        raise WriteBudgetExhaustedError("cap reached")

    with pytest.raises(WriteBudgetExhaustedError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            encoder=FakeEncoder(),
            execute=True,
            verify=_ok_verify,
            load_doc=_validated_doc,
            charge=_charge_exhausted,
        )
    assert dev.calls == []  # budget charged BEFORE any transfer


# ─── Happy path: all gates pass → ordered enciphered sequence ─────────────────


def test_execute_drives_ordered_enciphered_sequence() -> None:
    dev = FakeSessionDevice(keyword_reply=b"\xde\xad\xbe\xef")
    enc = FakeEncoder()
    charged: list[bool] = []

    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=enc,
        execute=True,
        verify=_ok_verify,
        load_doc=_validated_doc,
        charge=lambda: charged.append(True),
    )

    assert plan.executed is True
    assert charged == [True]
    # keyword from step-2 RECV was fed back into the encoder
    assert plan.device_keyword == b"\xde\xad\xbe\xef"
    assert enc.seeded == b"\xde\xad\xbe\xef"

    # EXACT order + transport kind: set_session(recv), get_keyword(recv),
    # set_command(send), set_command(send), get_command(recv).
    kinds = [kind for kind, _ in dev.calls]
    assert kinds == ["recv", "recv", "send", "send", "recv"]

    # The frames are the ENCIPHERED wire bytes, in order, and the two writes were
    # enciphered AFTER the keyword was seeded (prefix flips ENC: -> ENCK:).
    _, ss = dev.calls[0]
    _, gk = dev.calls[1]
    _, sel = dev.calls[2]
    _, rst = dev.calls[3]
    assert ss == b"ENC:" + bytes([0x81, 0x00, 0x00, 0x03])
    assert gk == b"ENC:" + bytes([0x82, 0x00, 0x00])
    # selector + reset operand carried in set_command (3-byte header 85 00 00 +
    # operand), enciphered post-keyword
    assert sel == b"ENCK:" + bytes([0x85, 0x00, 0x00, 0x10, 0x07, 0x7C])
    assert rst == b"ENCK:" + bytes([0x85, 0x00, 0x00, 0x0D, 0x00, 0x00])

    # the recorded plan steps mirror the same order
    assert [s.kind for s in plan.steps] == [
        "set_session",
        "get_keyword",
        "set_command",
        "set_command",
        "get_command",
    ]


def test_set_command_reset_carries_common_operand() -> None:
    """The state-changing write is the 'common' clear (0D 00 00) — the 5B00."""
    dev = FakeSessionDevice()
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=FakeEncoder(),
        execute=True,
        verify=_ok_verify,
        load_doc=_validated_doc,
    )
    reset_step = plan.steps[3]
    assert reset_step.kind == "set_command"
    assert reset_step.plaintext[-3:] == bytes([0x0D, 0x00, 0x00])


def test_execute_without_verify_readback_omits_final_recv() -> None:
    dev = FakeSessionDevice()
    reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=FakeEncoder(),
        execute=True,
        verify_readback=False,
        verify=_ok_verify,
        load_doc=_validated_doc,
    )
    kinds = [kind for kind, _ in dev.calls]
    assert kinds == ["recv", "recv", "send", "send"]  # no trailing verify recv


# ─── accept_derived override (the one-run live-validation seam) ───────────────


def test_accept_derived_overrides_status_gate_only() -> None:
    """accept_derived bypasses ONLY the status gate; the derived clear runs and
    is recorded loudly. UUID/EEPROM/budget all still applied (proven elsewhere)."""
    dev = FakeSessionDevice(keyword_reply=b"\xde\xad\xbe\xef")
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=FakeEncoder(),
        execute=True,
        accept_derived=True,
        verify=_ok_verify,
        load_doc=_unvalidated_doc,  # status would normally HARD STOP
    )
    assert plan.executed is True
    assert [kind for kind, _ in dev.calls] == ["recv", "recv", "send", "send", "recv"]
    assert "OVERRIDE" in plan.outcome.response_summary


def test_accept_derived_still_enforces_eeprom_gate() -> None:
    """The override touches ONLY the status gate — EEPROM baseline still required."""
    dev = FakeSessionDevice()
    with pytest.raises(EepromDumpFailedError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=False,
            encoder=FakeEncoder(),
            execute=True,
            accept_derived=True,
            verify=_ok_verify,
            load_doc=_unvalidated_doc,
        )
    assert dev.calls == []


def test_accept_derived_still_enforces_uuid_gate() -> None:
    dev = FakeSessionDevice()

    def _bad_verify(fp: PrinterFingerprint, pid: str) -> None:
        raise UnknownPrinterError("wrong unit")

    with pytest.raises(UnknownPrinterError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            encoder=FakeEncoder(),
            execute=True,
            accept_derived=True,
            verify=_bad_verify,
            load_doc=_unvalidated_doc,
        )
    assert dev.calls == []


def test_verified_status_does_not_flag_override() -> None:
    """A genuinely verified-captured unit runs WITHOUT the override banner even
    when accept_derived is passed (override_used is false when status is good)."""
    dev = FakeSessionDevice()
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=FakeEncoder(),
        execute=True,
        accept_derived=True,
        verify=_ok_verify,
        load_doc=_validated_doc,
    )
    assert plan.executed is True
    assert "OVERRIDE" not in plan.outcome.response_summary


# ─── Live-keyword guard (Lane C R1): reject a zero/short get_keyword reply ─────


def test_zero_length_keyword_refuses_before_any_write() -> None:
    """A zero-byte get_keyword reply (session never opened) HARD STOPS before
    either set_command — the write is never sent (Lane C risk R1)."""
    dev = FakeSessionDevice(keyword_reply=b"")  # session never opened
    with pytest.raises(ResetNotValidatedError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            encoder=FakeEncoder(),
            execute=True,
            verify=_ok_verify,
            load_doc=_validated_doc,
        )
    # set_session + get_keyword RECV happened; NO set_command write was sent.
    assert [kind for kind, _ in dev.calls] == ["recv", "recv"]


def test_short_keyword_refuses_before_any_write() -> None:
    dev = FakeSessionDevice(keyword_reply=b"\x00\x01")  # 2 bytes < 4
    with pytest.raises(ResetNotValidatedError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            encoder=FakeEncoder(),
            execute=True,
            verify=_ok_verify,
            load_doc=_validated_doc,
        )
    assert [kind for kind, _ in dev.calls] == ["recv", "recv"]


def test_four_byte_keyword_is_accepted() -> None:
    """Exactly keyword_min_len (4) bytes is a valid live keyword → writes proceed."""
    dev = FakeSessionDevice(keyword_reply=b"\x11\x22\x33\x44")
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=FakeEncoder(),
        execute=True,
        verify=_ok_verify,
        load_doc=_validated_doc,
    )
    assert plan.executed is True
    assert plan.device_keyword == b"\x11\x22\x33\x44"
    assert [kind for kind, _ in dev.calls] == ["recv", "recv", "send", "send", "recv"]


def test_keyword_pad_to_pads_short_live_keyword_before_seeding() -> None:
    """The validated native VENDOR_GET read returns a 3-byte live keyword; with
    keyword_min_len=3 + keyword_pad_to=4 the op accepts it and 0x00-pads to the
    4-byte SEED width before seeding the encoder (and reports the padded keyword)."""
    dev = FakeSessionDevice(keyword_reply=b"\xe4\x7c\x5a")  # 3-byte live keyword
    enc = FakeEncoder()
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=enc,
        execute=True,
        verify=_ok_verify,
        load_doc=_validated_doc,
        keyword_min_len=3,
        keyword_pad_to=4,
    )
    assert plan.executed is True
    assert enc.seeded == b"\xe4\x7c\x5a\x00"  # padded to the 4-byte SEED width
    assert plan.device_keyword == b"\xe4\x7c\x5a\x00"
    assert [kind for kind, _ in dev.calls] == ["recv", "recv", "send", "send", "recv"]


def test_keyword_pad_to_still_rejects_below_min_len() -> None:
    """keyword_pad_to does NOT relax the live-keyword guard: a reply shorter than
    keyword_min_len still HARD STOPS before any write (session never opened)."""
    dev = FakeSessionDevice(keyword_reply=b"\x00\x01")  # 2 bytes < min_len 3
    with pytest.raises(ResetNotValidatedError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            encoder=FakeEncoder(),
            execute=True,
            verify=_ok_verify,
            load_doc=_validated_doc,
            keyword_min_len=3,
            keyword_pad_to=4,
        )
    assert [kind for kind, _ in dev.calls] == ["recv", "recv"]


def test_commit_instruction_in_executed_summary() -> None:
    """A real (executed) clear surfaces the MANDATORY clean-power-button commit
    step in the outcome — the writes + empty 0x86 do not persist by themselves."""
    dev = FakeSessionDevice(keyword_reply=b"\x11\x22\x33\x44")
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        encoder=FakeEncoder(),
        execute=True,
        verify=_ok_verify,
        load_doc=_validated_doc,
    )
    assert "POWER-BUTTON" in plan.outcome.response_summary
    assert "UNPLUG does NOT commit" in plan.outcome.response_summary


def test_missing_encoder_lazily_builds_lane_a_module() -> None:
    """With no injected encoder, ops lazily imports Lane A's
    canon_megatank.protocol.wicreset.build_encoder. Now that the module has
    landed the dry-run resolves it and enciphers the preview WITHOUT touching the
    device (the lazy-import seam works end to end). The clean-refusal contract for
    a *missing* module is exercised separately in test_missing_module_refuses."""
    dev = FakeSessionDevice()
    plan = reset_absorber_wicreset(
        dev,
        runtime_fingerprint=FP,
        eeprom_dump_done=True,
        load_doc=_validated_doc,
    )
    assert plan.executed is False
    assert dev.calls == []  # dry-run drives nothing
    assert len(plan.steps) == 5
    # Only the two set_command writes carry a secret operand → they are enciphered
    # to the 23-byte 85 00 00 || payload(20) form (wire != plaintext). set_session
    # (81 00 00 03), get_keyword (82 00 00) and get_command (86 00 00) are sent
    # VERBATIM (wire == plaintext): the device length-validates 0x81 to its 4
    # plaintext bytes and STALLs an enciphered frame, and the read primes ride the
    # request header (hardware-validated 2026-06-01). All wires are non-empty.
    by_kind = {s.kind: s for s in plan.steps}
    assert all(s.wire for s in plan.steps)
    set_cmd_steps = [s for s in plan.steps if s.kind == "set_command"]
    assert all(len(s.wire) == 23 and s.wire != s.plaintext for s in set_cmd_steps)  # noqa: PLR2004
    assert by_kind["set_session"].wire == by_kind["set_session"].plaintext  # plain
    assert by_kind["get_keyword"].wire == by_kind["get_keyword"].plaintext
    assert by_kind["get_command"].wire == by_kind["get_command"].plaintext


def test_missing_module_refuses_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    """If Lane A's factory is NOT usable (module absent, or build_encoder raises),
    ops refuses with a ResetNotValidatedError rather than crashing on the raw
    exception. We simulate the unusable factory by making build_encoder raise."""

    def _boom(*_args: object, **_kwargs: object) -> object:
        raise ImportError("simulated: Lane A factory unavailable")

    monkeypatch.setattr(wic, "build_encoder", _boom)
    dev = FakeSessionDevice()
    with pytest.raises(ResetNotValidatedError):
        reset_absorber_wicreset(
            dev,
            runtime_fingerprint=FP,
            eeprom_dump_done=True,
            load_doc=_validated_doc,
        )
    assert dev.calls == []
