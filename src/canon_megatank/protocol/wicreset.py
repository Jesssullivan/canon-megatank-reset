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

The algorithm (RECOVERED, see docs/research/g6020-cipher-fix.md):

  functor 3 -> functor_encryption_003 (FUN_004e8410): build a 20-byte
               deterministic envelope ``[00 12 01 frame[3]]`` + 16 fixed
               MSVC-rand() bytes (seed 0x12345678), apply the function-block
               ``<special>`` overwrite (envelope[4+off]:=val) and the
               ``<indexes>`` payload scatter, then use that envelope as the
               functor-2 SEED ONLY and emit the 4-byte enciphered keyword.
  functor 2 -> functor_implementation (FUN_004e76c0): transforms ONLY the
               4-byte BOUND keyword (functor_initialization writes it; the
               output loop is bounded by len==4). Seeded big-endian by folding
               the COMMAND/ENVELOPE buffer ONLY (the keyword enters via bind,
               not the seed). The per-byte SHIFT is a TABLE built by the
               operator-VM over the selected command.shift <array>'s <value>
               sub-programs, indexed per output position. Array selection =
               seed % {5 index, 7 codes, 3 shift}; the index path is the nested
               table-walk with the send/recv swap.
  keyword   -> functor_initialization (FUN_004e72b0): the per-session encoder
               XORs the live device keyword into keyword.codes via keyword.index;
               with the template-default keyword (4D B6 AB 00) this reduces to
               the canonical session keyword.

The on-wire frame is ``prefix(CLEAR) || 4-byte enciphered keyword`` — NOT a
20-byte blob; the envelope is the functor-2 SEED, not the transform subject.

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
    """Evaluate ONE command.shift <value> sub-program as the operator-VM.

    Mirrors functor_implementation's inner shift-table loop: acc starts at the
    message seed and each <action> step folds: '=' set, '+' add, '-' sub, '*'
    mul, '/' div, '%' mod, '&' and, '|' or, '^' xor (32-bit). A command.shift
    <array> holds several <value> sub-programs (see :func:`build_shift_table`)."""
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


# A command.shift <array> is N <value> sub-programs, each a tuple of steps.
ShiftArray = tuple[tuple[ShiftStep, ...], ...]


def build_shift_table(seed: int, shift_array: ShiftArray) -> tuple[int, ...]:
    """Build the per-position SHIFT TABLE for one command.shift <array>.

    FUN_004e76c0:340-495 evaluates each <value> sub-program of the selected
    <array> from the message seed, appending each result to the shift-table
    container. Returns one shift value per <value>."""
    return tuple(apply_shift_program(seed, value) for value in shift_array)


@dataclass(frozen=True)
class FunctionBlock:
    """One functor-3 <function> entry, keyed by <code> (= command id frame[3]).

    ``special`` is a flat list of (offset, value) pairs the envelope builder
    writes as envelope[4+offset]:=value (FUN_004e8410:120-128); ``indexes``
    scatters the frame[4:] payload into envelope[4+indexes[i]] (lines 129-138)."""

    code: int
    special: tuple[int, ...]
    indexes: tuple[int, ...]


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
    command_shift: tuple[ShiftArray, ...]  # 3 <array>s, each N <value> sub-programs
    functions: dict[int, FunctionBlock]  # functor-3 <function> blocks keyed by <code>


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
def seed_fold(buffer: bytes) -> int:
    """local_d4: big-endian fold of the COMMAND/ENVELOPE buffer ONLY.

    FUN_004e76c0:258-266 -- local_d4 = local_d4*0x100 + byte. The keyword does
    NOT enter the seed (it is bound separately and is the transform subject).
    Over a >4-byte buffer only the trailing 4 bytes survive (256^4 == 0)."""
    seed = 0
    for b in buffer:
        seed = (seed * 0x100 + b) & 0xFFFFFFFF
    return seed


def _derive(
    method: SR5Method, seed: int
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    """Select the index/codes arrays and build the shift TABLE for ``seed``.

    Array selection = seed % {len index (5), len codes (7), len shift (3)}."""
    index_arr = method.command_index[seed % len(method.command_index)]
    codes_arr = method.command_codes[seed % len(method.command_codes)]
    shift_arr = method.command_shift[seed % len(method.command_shift)]
    shift_table = build_shift_table(seed, shift_arr)
    return index_arr, codes_arr, shift_table


def functor2_transform(
    method: SR5Method,
    keyword: bytes,
    *,
    seed_source: bytes,
    send: bool = True,
) -> bytes:
    """functor_implementation (FUN_004e76c0): transform the 4-byte keyword.

    Operates on the 4-byte BOUND keyword, seeded by the big-endian fold of the
    COMMAND/ENVELOPE buffer (``seed_source``). The output loop walks the
    index/codes/shift tables per output position:

        j      = index_arr[i] % len ; code = codes_arr[j % 20]
        shift  = shift_table[j % len(table)]
        ksbyte = (seed >> (shift & 0x1f)) ^ code
        send (param_5=1):  out[i] = keyword[j] ^ ksbyte
        recv (param_5=0):  out[j] = keyword[i] ^ ksbyte"""
    seed = seed_fold(seed_source)
    index_arr, codes_arr, shift_table = _derive(method, seed)
    n = len(keyword)
    out = bytearray(n)
    for i in range(n):
        j = index_arr[i % len(index_arr)] % n
        code = codes_arr[j % len(codes_arr)]
        shift = shift_table[j % len(shift_table)]
        ksbyte = ((seed >> (shift & 0x1F)) ^ code) & 0xFF
        if send:
            out[i] = (keyword[j] ^ ksbyte) & 0xFF
        else:
            out[j] = (keyword[i] ^ ksbyte) & 0xFF
    return bytes(out)


# ─── functor 3 (functor_encryption_003, FUN_004e8410) — RECOVERED ───────────────
def envelope3(method: SR5Method, app_frame: bytes) -> bytes:
    """The deterministic 20-byte functor-3 envelope (the functor-2 SEED).

    ``[00 12 01 frame[3]]`` + 16 fixed LCG bytes, then the function-block
    ``<special>`` overwrite (envelope[4+off]:=val) and the ``<indexes>`` payload
    scatter for the block keyed by frame[3]. Errors below 4 bytes."""
    if len(app_frame) < KEYWORD_LEN:
        raise CanonToolError("Command buffer is too small.")
    cmd_id = app_frame[3]
    env = bytearray([0x00, 0x12, 0x01, cmd_id]) + bytearray(lcg16())
    block = method.functions.get(cmd_id)
    if block is not None:
        sp = block.special
        for k in range(0, len(sp) - 1, 2):
            off = sp[k]
            if 4 + off < len(env):
                env[4 + off] = sp[k + 1] & 0xFF
        payload = app_frame[4:]
        for i, off in enumerate(block.indexes):
            if i < len(payload) and 4 + off < len(env):
                env[4 + off] = payload[i]
    return bytes(env)


def functor3_encrypt(method: SR5Method, app_frame: bytes, bound_keyword: bytes) -> bytes:
    """Emit the 4-byte enciphered keyword (functor-2 over the bound keyword,
    seeded by the 20-byte envelope ONLY)."""
    envelope = envelope3(method, app_frame)
    return functor2_transform(method, bound_keyword, seed_source=envelope, send=True)


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


def _parse_shift_value(value: Any) -> tuple[ShiftStep, ...]:
    """Parse one command.shift <value> sub-program (an ordered list of <action>
    {sign,data} steps) into a tuple of :class:`ShiftStep`.

    Mirrors the devices.xml nesting: a <value> is a multi-action operator-VM
    program. The SSOT stores it as a list of ``{sign, data}`` mappings; a bare
    ``{sign, data}`` mapping (the legacy single-action form) is accepted as a
    one-step program. The list order is preserved verbatim (load-bearing)."""
    if isinstance(value, dict):  # legacy single-action <value>: {sign, data}
        steps: list[Any] = [value]
    else:
        steps = list(value)
    out: list[ShiftStep] = []
    for step in steps:
        try:
            out.append(ShiftStep(sign=str(step["sign"]), data=int(step["data"])))
        except (KeyError, TypeError, ValueError) as exc:
            raise CanonToolError(
                f"malformed command.shift <action> step {step!r}: expected "
                "{sign, data}"
            ) from exc
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
    # ONE TRUE shift semantics (FUN_004e76c0:340-495): each command.shift <array>
    # holds an ORDERED list of <value> sub-programs; each <value> is its own
    # multi-action operator-VM program (a list of {sign,data} <action> steps).
    # build_shift_table evaluates each <value> from the seed (acc reset per
    # <value>) and emits ONE shift-table entry per <value>. The SSOT stores this
    # as list[array][value][action]; we parse that nesting verbatim so the table
    # is identical to the devices.xml mirror AND order is interpreter-pinned.
    command_shift: list[ShiftArray] = []
    for arr in tmpl["command_shift"]:
        command_shift.append(tuple(_parse_shift_value(value) for value in arr))

    functions: dict[int, FunctionBlock] = {}
    for code_key, blk in (tmpl.get("functor3_functions") or {}).items():
        code = code_key if isinstance(code_key, int) else int(str(code_key), 16)
        special = _hexbytes(blk["special"]) if blk.get("special") else ()
        idx_field = blk.get("indexes") or []
        indexes = tuple(int(str(x), 16) & 0xFF for x in idx_field)
        functions[code] = FunctionBlock(code=code, special=special, indexes=indexes)

    return SR5Method(
        handler=int(handler),
        functor=int(functor),
        keyword_codes=_hexbytes(kw["codes"]),
        keyword_index=_hexbytes(kw["index"]),
        keyword_value=_hexbytes(kw["resolution_value"]),
        command_index=command_index,
        command_codes=command_codes,
        command_shift=tuple(command_shift),
        functions=functions,
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
        """Encipher a plaintext ``[cmd][arg…][payload]`` app frame.

        Returns the full on-wire frame: ``prefix(CLEAR) || 4-byte enciphered
        keyword``. The clear prefix is the plaintext app frame itself; the
        cipher (functor 2 over the bound keyword, seeded by the functor-3
        envelope) appends the 4 enciphered keyword bytes. This is the
        execute_one_command framing — NOT a 20-byte blob."""
        frame = bytes(plaintext_app_frame)
        bound = bind_keyword(self._method, self._keyword)
        if self._method.functor == FUNCTOR_IDENTITY:
            return frame
        if self._method.functor == FUNCTOR_IMPLEMENTATION:
            enc_kw = functor2_transform(self._method, bound, seed_source=frame, send=True)
            return frame + enc_kw
        if self._method.functor == FUNCTOR_ENCRYPTION_003:
            return frame + functor3_encrypt(self._method, frame, bound)
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
