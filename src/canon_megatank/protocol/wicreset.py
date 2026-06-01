"""WICReset functor-3 encoder for the Canon G6000-family (G6020) reset.

This is the package-resident encoder that ``ops.reset_absorber_wicreset``
lazily imports (``build_encoder(printer_id=...)``) or accepts injected as a
``WicResetEncoder``. It enciphers the plaintext WICReset session frames
(``[cmd][arg…][payload]``) into the on-wire bytes with the recovered
CANON-SR5 / CANON-IPL functor-3 transform (the G6000 method-3 path).

GROUND TRUTH (ADR-0007)
-----------------------
The obfuscation TABLES (keyword selector, command.index / command.codes /
command.shift, functor-3 envelope) are *derived data* recovered from the
decrypted WICReset model DB. They live in the SSOT
``printers/canon-g6020/maintenance.yaml`` under
``supported.absorber_reset.derived_template`` and this module reads them from
there via :func:`fingerprint.load_maintenance` — so the package does NOT depend
on the ephemeral ``/tmp/appbin_out/devices.xml`` and never vendors any Canon
binary. The cipher MATH below is ported verbatim from the validated reference
``scripts/canon_sr5_cipher.py`` (20 passing tests).

The algorithm (RECOVERED, see docs/research/wicreset-g6020-reset-derived.md):

  functor 3 -> functor_encryption_003 (FUN_004e8410): prepend a 20-byte
               deterministic envelope ``[00 12 01 frame[3]]`` + 16 fixed
               MSVC-rand() bytes (seed 0x12345678), then run functor 2 over the
               assembled buffer.
  functor 2 -> functor_implementation (FUN_004e76c0): a message-seeded XOR
               keystream + index permutation over command.index / command.codes,
               with a per-position shift from a tiny operator-VM over
               command.shift, seeded big-endian by folding the message bytes and
               mixing the bound session keyword.
  keyword   -> functor_initialization (FUN_004e72b0): the per-session encoder
               XORs the live device keyword into keyword.codes via keyword.index;
               with the template-default keyword (4D B6 AB 00) this reduces to
               the canonical session keyword.

This is pure derivation: no WICReset key is spent and no device is touched.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..types import CanonToolError

# ─── functor-3 envelope (functor_encryption_003, FUN_004e8410) — RECOVERED ──────
LCG_MUL = 0x343FD  # MSVC rand() multiplier (214013)
LCG_ADD = 0x269EC3  # MSVC rand() increment  (2531011)
LCG_SEED0 = 0x12345678  # hard-coded seed -> the 16 envelope bytes are CONSTANT

KEYWORD_LEN = 4  # the keyword is always a 4-byte word
ENVELOPE_LEN = 20  # functor-3 preamble: 4 header bytes + 16 fixed LCG bytes

# functor selector values (devices.xml <functor> field)
FUNCTOR_IDENTITY = 1
FUNCTOR_IMPLEMENTATION = 2
FUNCTOR_ENCRYPTION_003 = 3

# The recovered 16 fixed envelope bytes (MSVC rand, seed 0x12345678).
ENVELOPE_FIXED_16 = bytes.fromhex("e93f0da196953104492d9e6183cf096f")

# Template-default device keyword (the <resolution> keyword.value).
TEMPLATE_DEFAULT_KEYWORD = bytes([0x4D, 0xB6, 0xAB, 0x00])

# Where the recovered tables live in the SSOT.
_DERIVED_TEMPLATE_PATH = ("supported", "absorber_reset", "derived_template")


def lcg16(seed: int = LCG_SEED0, n: int = 16) -> bytes:
    """The 16 fixed envelope bytes: ESI = ESI*0x343fd + 0x269ec3; emit (ESI>>16)&0xff."""
    out: list[int] = []
    s = seed
    for _ in range(n):
        s = (s * LCG_MUL + LCG_ADD) & 0xFFFFFFFF
        out.append((s >> 16) & 0xFF)
    return bytes(out)


# ─── operator-VM (command.shift program) — RECOVERED data-flow ──────────────────
@dataclass(frozen=True)
class ShiftStep:
    sign: str  # one of = + - * / % & | ^
    data: int


def apply_shift_program(seed: int, steps: tuple[ShiftStep, ...]) -> int:
    """Evaluate one command.shift array as the operator-VM over the seed.

    Mirrors functor_implementation's inner loop: acc starts at the message seed
    and each step folds: '=' set, '+' add, '-' sub, '*' mul, '/' div, '%' mod,
    '&' and, '|' or, '^' xor (32-bit)."""
    acc = seed & 0xFFFFFFFF
    for step in steps:
        d = step.data & 0xFFFFFFFF
        if step.sign == "=":
            acc = d
        elif step.sign == "+":
            acc = (acc + d) & 0xFFFFFFFF
        elif step.sign == "-":
            acc = (acc - d) & 0xFFFFFFFF
        elif step.sign == "*":
            acc = (acc * d) & 0xFFFFFFFF
        elif step.sign == "/":
            acc = (acc // d) if d else 0
        elif step.sign == "%":
            acc = (acc % d) if d else 0
        elif step.sign == "&":
            acc = acc & d
        elif step.sign == "|":
            acc = acc | d
        elif step.sign == "^":
            acc = acc ^ d
        else:
            raise CanonToolError(f"unknown operator sign {step.sign!r}")
    return acc & 0xFFFFFFFF


# ─── the parsed functor-3 method (the recovered CANON-IPL tables) ───────────────
@dataclass(frozen=True)
class SR5Method:
    handler: int
    functor: int
    keyword_codes: tuple[int, ...]  # 4 bytes, e.g. 4D 49 53 00
    keyword_index: tuple[int, ...]  # 4 bytes, e.g. 03 01 00 02
    keyword_value: tuple[int, ...]  # default device keyword (4D B6 AB 00)
    command_index: tuple[tuple[int, ...], ...]  # 5 perm arrays, 20 bytes each
    command_codes: tuple[tuple[int, ...], ...]  # 7 keystream arrays, 20 bytes each
    command_shift: tuple[tuple[ShiftStep, ...], ...]  # operator-VM arrays


# ─── keyword binding (functor_initialization, FUN_004e72b0) — RECOVERED ─────────
def bind_keyword(method: SR5Method, device_keyword: bytes) -> bytes:
    """Per-session 4-byte encoder keyword.

        for i in 0..4:
            j        = keyword.index[i]
            bound[i] = keyword.codes[j] ^ device_keyword[j]

    With the template-default keyword (4D B6 AB 00) this reduces to the canonical
    session keyword; a live device keyword changes every bound byte and therefore
    the entire keystream (device binding)."""
    if len(device_keyword) != KEYWORD_LEN:
        raise CanonToolError("device keyword must be 4 bytes")
    out = bytearray(KEYWORD_LEN)
    for i in range(KEYWORD_LEN):
        j = method.keyword_index[i]
        out[i] = (method.keyword_codes[j] ^ device_keyword[j]) & 0xFF
    return bytes(out)


# ─── functor 2 (functor_implementation, FUN_004e76c0) — RECOVERED algorithm ─────
def _message_seed(message: bytes, bound_keyword: bytes) -> int:
    """local_d4: big-endian fold of the message, mixed with the session keyword."""
    seed = 0
    for b in message:
        seed = (seed * 0x100 + b) & 0xFFFFFFFF
    kw = 0
    for b in bound_keyword:
        kw = (kw * 0x100 + b) & 0xFFFFFFFF
    return (seed ^ kw) & 0xFFFFFFFF


def _bijection(base_perm: tuple[int, ...], length: int) -> list[int]:
    """A true permutation of range(length) derived from the 20-element base."""
    width = len(base_perm)
    order = sorted(range(length), key=lambda p: (base_perm[p % width], p))
    perm = [0] * length
    for rank, pos in enumerate(order):
        perm[pos] = rank
    return perm


def _derive(method: SR5Method, seed: int) -> tuple[tuple[int, ...], tuple[int, ...], int]:
    """Select the index/codes arrays and per-message shift for ``seed``."""
    index_arr = method.command_index[seed % len(method.command_index)]
    codes_arr = method.command_codes[seed % len(method.command_codes)]
    shift_arr = method.command_shift[seed % len(method.command_shift)]
    shift_val = apply_shift_program(seed, shift_arr)
    return index_arr, codes_arr, shift_val


def functor2_transform(
    method: SR5Method,
    message: bytes,
    bound_keyword: bytes,
    *,
    decrypt: bool,
    seed_source: bytes | None = None,
) -> bytes:
    """Symmetric XOR keystream + index permutation.

      encrypt:  cipher[perm[i]] = msg[i] ^ ks[i]      (seed = plaintext)
      decrypt:  msg[i]          = cipher[perm[i]] ^ ks[i]  (seed = plaintext)

    ks[i] = (seed >> (shift & 0x1f)) ^ codes[i % len(codes)]."""
    seed = _message_seed(seed_source if seed_source is not None else message, bound_keyword)
    index_arr, codes_arr, shift_val = _derive(method, seed)
    perm = _bijection(index_arr, len(message))
    shamt = shift_val & 0x1F

    ks = bytes(
        ((seed >> shamt) ^ codes_arr[i % len(codes_arr)]) & 0xFF for i in range(len(message))
    )
    out = bytearray(len(message))
    if decrypt:
        for i in range(len(message)):
            out[i] = (message[perm[i]] ^ ks[i]) & 0xFF
    else:
        for i in range(len(message)):
            out[perm[i]] = (message[i] ^ ks[i]) & 0xFF
    return bytes(out)


# ─── functor 3 (functor_encryption_003, FUN_004e8410) — RECOVERED ───────────────
def envelope3(app_frame: bytes) -> bytes:
    """The deterministic 20-byte preamble functor 3 prepends:
    ``[00 12 01 frame[3]]`` + 16 fixed LCG bytes. Errors below 4 bytes."""
    if len(app_frame) < KEYWORD_LEN:
        raise CanonToolError("Command buffer is too small.")
    return bytes([0x00, 0x12, 0x01, app_frame[3]]) + lcg16()


def functor3_encrypt(method: SR5Method, app_frame: bytes, bound_keyword: bytes) -> bytes:
    """envelope + functor 2 over (envelope || frame[4:])."""
    assembled = envelope3(app_frame) + app_frame[4:]
    return functor2_transform(method, assembled, bound_keyword, decrypt=False)


def functor3_decrypt(
    method: SR5Method, wire: bytes, bound_keyword: bytes, *, assembled_plaintext: bytes
) -> bytes:
    """Inverse of functor3_encrypt's functor-2 stage (returns the assembled buffer)."""
    return functor2_transform(
        method, wire, bound_keyword, decrypt=True, seed_source=assembled_plaintext
    )


# ─── SSOT loading: build SR5Method from derived_template (never devices.xml) ────
def _hexbytes(spec: str) -> tuple[int, ...]:
    """Parse a ``'0x4D 0x49 0x53 0x00'`` token string into a byte tuple."""
    out: list[int] = []
    for tok in spec.split():
        try:
            out.append(int(tok, 16) & 0xFF)
        except ValueError as exc:
            raise CanonToolError(f"malformed template byte {tok!r} in {spec!r}") from exc
    return tuple(out)


def load_method_from_ssot(
    *,
    printer_id: str = "canon-g6020",
    load_doc: Callable[[str], dict[str, Any]] | None = None,
) -> SR5Method:
    """Build the functor-3 :class:`SR5Method` from the SSOT ``derived_template``.

    Sources the keyword selector + command tables from
    ``maintenance.yaml::supported.absorber_reset.derived_template`` (the recovered
    CANON-IPL functor-3 tables) — NOT from the ephemeral devices.xml. Raises
    ``CanonToolError`` if the template or a required table is absent."""
    if load_doc is None:
        from ..fingerprint import load_maintenance  # noqa: PLC0415

        load_doc = load_maintenance
    tmpl: Any = load_doc(printer_id)
    for key in _DERIVED_TEMPLATE_PATH:
        tmpl = (tmpl or {}).get(key, {})
    if not tmpl:
        raise CanonToolError(
            "no derived_template in the SSOT — the functor-3 cipher tables have "
            "not been recovered for this printer."
        )

    for required in ("keyword", "command_index", "command_codes", "command_shift"):
        if required not in tmpl:
            raise CanonToolError(
                f"derived_template is missing {required!r} — incomplete cipher "
                "tables; cannot build the functor-3 encoder. The SSOT should carry "
                "the full recovered tables (fall back to parsing devices.xml only "
                "if the SSOT gap cannot be closed)."
            )

    kw = tmpl["keyword"]
    functor = tmpl.get("functor", FUNCTOR_ENCRYPTION_003)
    if isinstance(functor, str):
        functor = int(functor, 16)
    handler = tmpl.get("method", FUNCTOR_ENCRYPTION_003)

    command_index = tuple(_hexbytes(a) for a in tmpl["command_index"])
    command_codes = tuple(_hexbytes(a) for a in tmpl["command_codes"])
    command_shift: list[tuple[ShiftStep, ...]] = []
    for arr in tmpl["command_shift"]:
        command_shift.append(
            tuple(ShiftStep(sign=str(step["sign"]), data=int(step["data"])) for step in arr)
        )

    return SR5Method(
        handler=int(handler),
        functor=int(functor),
        keyword_codes=_hexbytes(kw["codes"]),
        keyword_index=_hexbytes(kw["index"]),
        keyword_value=_hexbytes(kw["resolution_value"]),
        command_index=command_index,
        command_codes=command_codes,
        command_shift=tuple(command_shift),
    )


# ─── the encoder (satisfies ops.WicResetEncoder) ────────────────────────────────
class WicResetEncoder:
    """Functor-3 encoder for the G6000-family WICReset clear sequence.

    Satisfies ``ops.WicResetEncoder``: :meth:`encipher` applies the functor-3
    transform (LCG envelope + XOR keystream + permutation) to a plaintext
    ``[cmd][arg…][payload]`` app frame; :meth:`seed_keyword` stores the live
    device keyword (read over ``get_keyword``) so that SUBSEQUENT
    :meth:`encipher` calls bind it (functor_initialization).

    Before :meth:`seed_keyword` is called, the encoder uses the template-default
    keyword (4D B6 AB 00) — the key-free derivation. After it is called, every
    enciphered byte is keyed to the live session (device binding). The current
    keyword is tracked on the instance (``self._keyword``)."""

    def __init__(self, method: SR5Method, *, default_keyword: bytes | None = None) -> None:
        self._method = method
        default = default_keyword if default_keyword is not None else bytes(method.keyword_value)
        if not default:
            default = TEMPLATE_DEFAULT_KEYWORD
        if len(default) != KEYWORD_LEN:
            raise CanonToolError("default keyword must be 4 bytes")
        self._keyword: bytes = bytes(default)

    @property
    def keyword(self) -> bytes:
        """The 4-byte device keyword currently bound (default until seeded)."""
        return self._keyword

    def seed_keyword(self, device_keyword: bytes) -> None:
        """Store the live 4-byte device keyword for subsequent encipher() calls.

        The live ``get_keyword`` RECV reply may be longer than 4 bytes; only the
        leading 4 bytes form the keyword word (functor_initialization indexes
        keyword.index ∈ {0..3}). A reply shorter than 4 bytes is refused — the
        op's live-keyword guard already blocks that case, but we re-check so a
        bad seed can never silently key the cipher wrong."""
        if len(device_keyword) < KEYWORD_LEN:
            raise CanonToolError(
                f"device keyword must be at least {KEYWORD_LEN} bytes, got {len(device_keyword)}"
            )
        self._keyword = bytes(device_keyword[:KEYWORD_LEN])

    def encipher(self, plaintext_app_frame: bytes) -> bytes:
        """Functor-3 encipher a plaintext ``[cmd][arg…][payload]`` app frame.

        Returns the on-wire bytes (20-byte envelope folded over frame[0:4] then
        frame[4:], run through functor 2 keyed by the bound session keyword)."""
        bound = bind_keyword(self._method, self._keyword)
        if self._method.functor == FUNCTOR_IDENTITY:
            return bytes(plaintext_app_frame)
        if self._method.functor == FUNCTOR_IMPLEMENTATION:
            return functor2_transform(
                self._method, bytes(plaintext_app_frame), bound, decrypt=False
            )
        if self._method.functor == FUNCTOR_ENCRYPTION_003:
            return functor3_encrypt(self._method, bytes(plaintext_app_frame), bound)
        raise CanonToolError(f"unknown functor {self._method.functor}")


def build_encoder(
    printer_id: str = "canon-g6020",
    *,
    load_doc: Callable[[str], dict[str, Any]] | None = None,
) -> WicResetEncoder:
    """Build the functor-3 :class:`WicResetEncoder` for ``printer_id``.

    Loads the recovered cipher tables from the SSOT ``derived_template`` (via
    :func:`fingerprint.load_maintenance`) and returns an encoder primed with the
    template-default keyword. This is the factory ``ops.reset_absorber_wicreset``
    lazily imports when no ``encoder=`` is injected."""
    method = load_method_from_ssot(printer_id=printer_id, load_doc=load_doc)
    return WicResetEncoder(method)
