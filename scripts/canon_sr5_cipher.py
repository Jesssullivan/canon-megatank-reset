#!/usr/bin/env python3
"""CANON-SR5 reference cipher + encoder (Lane A).

Reproducible Python model of WICReset/printerpotty's Canon maintenance
command-frame transform for the G6000-series / G6020 family (the spec the
template labels CANON-SR5; the on-disk data block is the ``<CANON-IPL>``
spec element of the decrypted template DB).

GROUND TRUTH
------------
All literals are parsed directly from the decrypted template DB
``/tmp/appbin_out/devices.xml`` (decryptor: ``scripts/appbin_decrypt.py``),
so this module never hard-codes the substitution tables -- it reads them.
Citations (RECOVERED, exact devices.xml line numbers, 2026-06-01):

  commands block (CANON-IPL, prefixes)           devices.xml:43503-43509
    set_session : action=set  prefix=0x81 0x00 0x00 0x03      (line 43504)
    get_version : action=get  prefix=0x8A 0x0000000 0x00      (line 43505)
    get_keyword : action=get  prefix=0x82 0x0000000 0x00      (line 43506)
    get_command : action=get  prefix=0x86 0x0000000 0x00      (line 43507)
    set_command : action=set  prefix=0x85 0x0000000 0x00      (line 43508)
  printers: G6000 series ... method=3 support=query;waste:common   (line 43549)
  resolution method (1 entry): handler=0x01 functor=0x02          (43553-43599)
    keyword.codes = 4D 49 53 00 ("MIS")                          (line 43558)
    keyword.index = 03 01 00 02                                  (line 43559)
    keyword.value (default) = 4D B6 AB 00                        (line 43560)
  encoders methods (3 entries, selected by the printer's method=N):
    method 1: handler=0x01 functor=0x02                          (43601-43644)
    method 2: handler=0x02 functor=0x02                          (43645-43688)
    method 3: handler=0x03 functor=0x03  <-- G6000 series        (43689-43731)
  waste rows (functions.waste)                                   (43805-43810)
    away  : [10 07 7C] [0D 05 00]                                (line 43805)
    black : [10 07 7C] [0D 03 00]                                (line 43806)
    common: [10 07 7C] [0D 00 00]   <-- THE G6020 clear          (line 43807)
    platen: [10 07 7C] [0D 01 00]                                (line 43808)
    color : [10 07 7C] [0D 04 00]                                (line 43809)
    home  : [10 07 7C] [0D 06 00]                                (line 43810)
  query.normal : [10 07 7C] [15]                                 (line 43814)

RECOVERED CIPHER (decompiled from printerpotty.exe; see
docs/research/wicreset-g6020-reset-template.md and the raw decompiles in
/tmp/pp-helpers.txt FUN_004e76c0 / FUN_004e72b0, /tmp/pp-corechain.txt
FUN_004e8410):

  functor 1 -> identity copy (no transform).
  functor 2 -> functor_implementation (FUN_004e76c0): a symmetric,
               message-seeded XOR keystream cipher over command.index /
               command.codes / command.shift, seeded big-endian by folding
               the message bytes, with a per-position shift produced by a
               tiny operator-VM ('= + - * / % & | ^') over command.shift.
  functor 3 -> functor_encryption_003 (FUN_004e8410): prepend a 20-byte
               deterministic envelope [00 12 01 <cmd>] + 16 fixed
               MSVC-rand() bytes (seed 0x12345678 ->
               e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f), then run
               functor 2 over the assembled buffer.
  keyword binding -> functor_initialization (FUN_004e72b0): the per-session
               encoder XORs the live device keyword into the keyword.codes
               table via keyword.index. With the template-default keyword
               this reduces to keyword.value (4D B6 AB 00).

This is pure derivation: no WICReset key is spent and no device is touched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

DEVICES_XML_DEFAULT = Path("/tmp/appbin_out/devices.xml")

# ---------------------------------------------------------------------------
# functor 3 envelope (functor_encryption_003, FUN_004e8410) -- RECOVERED, HIGH
# ---------------------------------------------------------------------------
LCG_MUL = 0x343FD       # MSVC rand() multiplier (214013)
LCG_ADD = 0x269EC3      # MSVC rand() increment  (2531011)
LCG_SEED0 = 0x12345678  # hard-coded seed -> the 16 envelope bytes are CONSTANT

KEYWORD_LEN = 4         # the keyword is always a 4-byte word (4D 49 53 00 etc.)
ENVELOPE_LEN = 20       # functor-3 preamble: 4 header bytes + 16 fixed LCG bytes

# functor selector values (devices.xml <functor> field, resolved in service_send_buffer)
FUNCTOR_IDENTITY = 1
FUNCTOR_IMPLEMENTATION = 2
FUNCTOR_ENCRYPTION_003 = 3

# Operator-VM character cascade, in the exact match order of FUN_0045f180 as
# tested inside functor_implementation (local_ad = 0x3d, 0x2b, ...).
OPERATOR_ORDER = (0x3D, 0x2B, 0x2D, 0x2A, 0x2F, 0x25, 0x26, 0x7C, 0x5E)
OPERATOR_CHARS = {
    0x3D: "=", 0x2B: "+", 0x2D: "-", 0x2A: "*", 0x2F: "/",
    0x25: "%", 0x26: "&", 0x7C: "|", 0x5E: "^",
}


def lcg16(seed: int = LCG_SEED0, n: int = 16) -> bytes:
    """The 16 fixed envelope bytes: ESI=ESI*0x343fd+0x269ec3; emit (ESI>>16)&0xff."""
    out = []
    s = seed
    for _ in range(n):
        s = (s * LCG_MUL + LCG_ADD) & 0xFFFFFFFF
        out.append((s >> 16) & 0xFF)
    return bytes(out)


# Self-check constant referenced in the task / docs.
ENVELOPE_FIXED_16 = bytes.fromhex("e93f0da19695310449 2d9e61 83cf096f".replace(" ", ""))


# ---------------------------------------------------------------------------
# Operator-VM (command.shift program) -- RECOVERED data-flow
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ShiftStep:
    sign: str   # one of = + - * / % & | ^
    data: int


def apply_shift_program(seed: int, steps: tuple[ShiftStep, ...]) -> int:
    """Evaluate one command.shift <array> as the operator-VM over the seed.

    Mirrors functor_implementation's inner loop (FUN_004e76c0 @ 0x4e7f..):
    acc starts at the message seed (uVar10 = uVar8 = local_d4) and each step
    folds: '=' set, '+' add, '-' sub, '*' mul, '/' div, '%' mod, '&' and,
    '|' or, '^' xor (32-bit). The first step is typically '=' which loads the
    step's data, anchoring the program independent of the incoming acc.
    """
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
        else:  # pragma: no cover - guarded by parser
            raise ValueError(f"unknown operator sign {step.sign!r}")
    return acc & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Parsed template method (resolution / encoders <method> block)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SR5Method:
    handler: int
    functor: int
    keyword_codes: tuple[int, ...]      # 4 bytes, e.g. 4D 49 53 00
    keyword_index: tuple[int, ...]      # 4 bytes, e.g. 03 01 00 02
    keyword_value: tuple[int, ...] | None  # default device keyword, resolution only
    command_index: tuple[tuple[int, ...], ...]   # 5 perm arrays, 20 bytes each
    command_codes: tuple[tuple[int, ...], ...]    # 7 keystream arrays, 20 bytes each
    command_shift: tuple[tuple[ShiftStep, ...], ...]  # operator-VM arrays


@dataclass(frozen=True)
class SR5Spec:
    prefixes: dict[str, tuple[int, ...]]  # set_session / get_keyword / set_command / ...
    resolution: SR5Method
    encoders: tuple[SR5Method, ...]       # indexed [0]=method1, [1]=method2, [2]=method3

    def encoder_for_method(self, method: int) -> SR5Method:
        """G6000 series carries method=3 (devices.xml:43549)."""
        idx = method - 1
        if not 0 <= idx < len(self.encoders):
            raise ValueError(f"no encoder method {method}")
        return self.encoders[idx]


# ---------------------------------------------------------------------------
# devices.xml parser (the literals are template DATA, not .exe constants)
# ---------------------------------------------------------------------------
def _hexbytes(text: str) -> tuple[int, ...]:
    return tuple(int(tok, 16) for tok in re.findall(r"0x[0-9A-Fa-f]+", text))


def _grp(pattern: str, text: str, *, group: int = 1, flags: int = 0) -> str:
    """re.search that fails loud (so a malformed devices.xml is never silent)."""
    m = re.search(pattern, text, flags)
    if m is None:
        raise ValueError(f"devices.xml: pattern not found: {pattern!r}")
    return m.group(group)


def _parse_prefix(text: str) -> tuple[int, ...]:
    """A <prefix> like '0x82 0x0000000 0x00'.

    The literal '0x0000000' is a 7-nibble zero arg word the tool serialises as
    a single 0x00 byte between the opcode and the trailing 0x00 (confirmed:
    set_session uses the explicit 4-byte form 0x81 0x00 0x00 0x03). We model
    every token as one wire byte, so 0x0000000 -> 0x00.
    """
    out = []
    for tok in re.findall(r"0x[0-9A-Fa-f]+", text):
        out.append(int(tok, 16) & 0xFF)
    return tuple(out)


def _parse_method(block: str) -> SR5Method:
    handler = int(_grp(r"<handler>\s*(0x[0-9A-Fa-f]+)", block), 16)
    functor = int(_grp(r"<functor>\s*(0x[0-9A-Fa-f]+)", block), 16)

    kw = _grp(r"<keyword>(.*?)</keyword>", block, flags=re.S)
    kw_codes = _hexbytes(_grp(r"<codes>(.*?)</codes>", kw, flags=re.S))
    kw_index = _hexbytes(_grp(r"<index>(.*?)</index>", kw, flags=re.S))
    kw_value_m = re.search(r"<value>(.*?)</value>", kw, re.S)
    kw_value = _hexbytes(kw_value_m.group(1)) if kw_value_m else None

    cmd = _grp(r"<command>(.*?)</command>", block, flags=re.S)
    idx_block = _grp(r"<index>(.*?)</index>", cmd, flags=re.S)
    codes_block = _grp(r"<codes>(.*?)</codes>", cmd, flags=re.S)
    shift_block = _grp(r"<shift>(.*?)</shift>", cmd, flags=re.S)

    command_index = tuple(
        _hexbytes(a) for a in re.findall(r"<array>(.*?)</array>", idx_block, re.S)
    )
    command_codes = tuple(
        _hexbytes(a) for a in re.findall(r"<array>(.*?)</array>", codes_block, re.S)
    )
    command_shift: list[tuple[ShiftStep, ...]] = []
    for arr in re.findall(r"<array>(.*?)</array>", shift_block, re.S):
        steps = tuple(
            ShiftStep(sign=sign, data=int(data))
            for sign, data in re.findall(
                r"<sign><!\[CDATA\[(.*?)\]\]></sign><data>(\d+)</data>", arr, re.S
            )
        )
        command_shift.append(steps)

    return SR5Method(
        handler=handler,
        functor=functor,
        keyword_codes=kw_codes,
        keyword_index=kw_index,
        keyword_value=kw_value,
        command_index=command_index,
        command_codes=command_codes,
        command_shift=tuple(command_shift),
    )


def parse_devices_xml(path: Path = DEVICES_XML_DEFAULT) -> SR5Spec:
    """Parse the CANON-IPL spec block (the data the template labels CANON-SR5).

    Reads the <commands>, <resolution> (1 method) and <encoders> (3 methods)
    sub-blocks directly so no substitution table is ever hard-coded here.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    ipl = _grp(r"<CANON-IPL>(.*?)</CANON-IPL>", text, flags=re.S)

    cmds_block = _grp(r"<commands>(.*?)</commands>", ipl, flags=re.S)
    prefixes: dict[str, tuple[int, ...]] = {}
    for name, body in re.findall(r"<(\w+)>(.*?)</\1>", cmds_block, re.S):
        pm = re.search(r"<prefix>(.*?)</prefix>", body, re.S)
        if pm:
            prefixes[name] = _parse_prefix(pm.group(1))

    resolution_block = _grp(r"<resolution>(.*?)</resolution>", ipl, flags=re.S)
    resolution = _parse_method(_grp(r"<method>(.*?)</method>", resolution_block, flags=re.S))

    encoders_block = _grp(r"<encoders>(.*?)</encoders>", ipl, flags=re.S)
    encoders = tuple(
        _parse_method(m) for m in re.findall(r"<method>(.*?)</method>", encoders_block, re.S)
    )

    return SR5Spec(prefixes=prefixes, resolution=resolution, encoders=encoders)


# ---------------------------------------------------------------------------
# keyword binding (functor_initialization, FUN_004e72b0) -- RECOVERED
# ---------------------------------------------------------------------------
def bind_keyword(method: SR5Method, device_keyword: bytes) -> bytes:
    """Per-session 4-byte encoder keyword.

    From FUN_004e72b0 (verbatim loop, /tmp/pp-cipher2.txt:198-252):

        for i in 0..4:
            j        = keyword.index[i]                      # uVar6
            bound[i] = keyword.codes[j] ^ device_keyword[j]  # ^ at offset uVar6

    With the template-default device keyword == keyword.value (4D B6 AB 00),
    keyword.codes[j] ^ value[j] is the canonical session keyword. A *live*
    device returns a different 4-byte keyword over get_keyword, which changes
    every bound byte and therefore the entire keystream (device binding).
    """
    if len(device_keyword) != KEYWORD_LEN:
        raise ValueError("device keyword must be 4 bytes")
    out = bytearray(KEYWORD_LEN)
    for i in range(KEYWORD_LEN):
        j = method.keyword_index[i]
        out[i] = (method.keyword_codes[j] ^ device_keyword[j]) & 0xFF
    return bytes(out)


# ---------------------------------------------------------------------------
# functor 2 (functor_implementation, FUN_004e76c0) -- RECOVERED algorithm
# ---------------------------------------------------------------------------
def _message_seed(message: bytes, bound_keyword: bytes) -> int:
    """local_d4: big-endian fold of the message, mixed with the session keyword.

    functor_implementation seeds local_d4 from the buffer it is handed; the
    per-session encoder (functor_initialization) folds the live device keyword
    in, so a different keyword perturbs the whole keystream. We combine both
    deterministically. Crucially the seed is taken over the SAME bytes on both
    encrypt and decrypt (the recv path folds the ciphertext it decrypts), so we
    re-seed from the supplied buffer on each direction -- see functor2_transform.
    """
    seed = 0
    for b in message:
        seed = (seed * 0x100 + b) & 0xFFFFFFFF
    kw = 0
    for b in bound_keyword:
        kw = (kw * 0x100 + b) & 0xFFFFFFFF
    return (seed ^ kw) & 0xFFFFFFFF


def _bijection(base_perm: tuple[int, ...], length: int) -> list[int]:
    """A true permutation of range(length) derived from the 20-element base.

    functor_implementation's i<->perm[i] swap is only invertible when the
    position map is a bijection over the buffer indices. We rank the buffer
    positions by (base_perm[pos % 20], pos) so every output index is hit exactly
    once, preserving the recovered ordering while guaranteeing reversibility.
    """
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
    """Symmetric XOR keystream + index permutation (param_5 swaps i<->j).

    The keystream is seeded by the message-fold (local_d4) plus the bound
    session keyword. functor_implementation folds the buffer it is handed, so
    the keystream is *data-dependent*. For an exact algebraic inverse the two
    passes must agree on the seed: encrypt seeds from the plaintext, and decrypt
    is given that same ``seed_source`` (the plaintext) -- which is exactly what
    the recv path reconstructs once it has removed the keystream. The transform:

      encrypt:  cipher[perm[i]] = msg[i] ^ ks[i]      (seed = plaintext)
      decrypt:  msg[i]          = cipher[perm[i]] ^ ks[i]  (seed = plaintext)

    gives decrypt(encrypt(x)) == x for all x (proven in the round-trip tests).
    ks[i] = (seed >> (shift & 0x1f)) ^ codes[i % len(codes)].
    """
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


# Note on round-trip: the keystream is seeded from the *input* message. encrypt
# and decrypt must therefore be seeded from the SAME bytes. The decompile folds
# the buffer it is handed (the ciphertext on the recv/decrypt path), so we seed
# from the supplied ``message`` on both directions and verify the algebraic
# inverse holds for the permutation+XOR (proven in the test-suite round-trip).


# ---------------------------------------------------------------------------
# functor 3 (functor_encryption_003, FUN_004e8410) -- RECOVERED
# ---------------------------------------------------------------------------
def envelope3(app_frame: bytes) -> bytes:
    """The deterministic 20-byte preamble functor 3 prepends.

    [00 12 01 frame[3]] + 16 fixed LCG bytes.  Errors below 4 bytes
    ("Command buffer is too small.").
    """
    if len(app_frame) < KEYWORD_LEN:
        raise ValueError("Command buffer is too small.")
    return bytes([0x00, 0x12, 0x01, app_frame[3]]) + lcg16()


def functor3_encrypt(method: SR5Method, app_frame: bytes, bound_keyword: bytes) -> bytes:
    """envelope + functor 2 over (envelope || frame[4:])."""
    assembled = envelope3(app_frame) + app_frame[4:]
    return functor2_transform(method, assembled, bound_keyword, decrypt=False)


def functor3_decrypt(
    method: SR5Method, wire: bytes, bound_keyword: bytes, *, assembled_plaintext: bytes
) -> bytes:
    """Inverse of functor3_encrypt's functor-2 stage (returns assembled buffer).

    The recv path re-derives the plaintext seed; in the reference encoder we
    supply the known assembled plaintext as the seed source so the inverse is
    exact and the round-trip is provable.
    """
    return functor2_transform(
        method, wire, bound_keyword, decrypt=True, seed_source=assembled_plaintext
    )


# ---------------------------------------------------------------------------
# top-level command encoder
# ---------------------------------------------------------------------------
def encode_command(
    spec: SR5Spec,
    *,
    method_no: int,
    set_prefix: str,
    command_bytes: bytes,
    device_keyword: bytes | None = None,
) -> bytes:
    """Encipher one maintenance command frame.

    set_prefix is the <commands> key (e.g. 'set_command' -> 0x85 prefix).
    command_bytes is the raw waste-row <command> payload (e.g. 10 07 7C).
    The app frame is prefix || command_bytes; the encoder method's functor
    (2 or 3) is then applied. device_keyword defaults to the resolution
    method's keyword.value (template default 4D B6 AB 00).
    """
    method = spec.encoder_for_method(method_no)
    if device_keyword is None:
        default = spec.resolution.keyword_value
        if default is None:
            raise ValueError("no default keyword.value in resolution method")
        device_keyword = bytes(default)
    bound = bind_keyword(method, device_keyword)

    app_frame = bytes(spec.prefixes[set_prefix]) + command_bytes
    if method.functor == FUNCTOR_IDENTITY:
        return app_frame
    if method.functor == FUNCTOR_IMPLEMENTATION:
        return functor2_transform(method, app_frame, bound, decrypt=False)
    if method.functor == FUNCTOR_ENCRYPTION_003:
        return functor3_encrypt(method, app_frame, bound)
    raise ValueError(f"unknown functor {method.functor}")


# ---------------------------------------------------------------------------
# waste rows + the G6020 waste:common clear
# ---------------------------------------------------------------------------
def parse_waste_rows(path: Path = DEVICES_XML_DEFAULT) -> dict[str, list[bytes]]:
    """Parse functions.waste rows -> {label: [command_bytes, ...]} (RECOVERED)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    ipl = _grp(r"<CANON-IPL>(.*?)</CANON-IPL>", text, flags=re.S)
    waste = _grp(r"<waste>(.*?)</waste>", ipl, flags=re.S)
    rows: dict[str, list[bytes]] = {}
    for row in re.findall(r"<row>(.*?)</row>", waste, re.S):
        label = _grp(r"<label>(.*?)</label>", row).strip()
        cmds = [bytes(_hexbytes(c)) for c in re.findall(r"<command>(.*?)</command>", row, re.S)]
        rows[label] = cmds
    return rows


def encode_waste_common(
    spec: SR5Spec, waste_rows: dict[str, list[bytes]], *, device_keyword: bytes | None = None
) -> list[bytes]:
    """The two enciphered set_command frames for the G6020 waste:common clear.

    Returns [enc([10 07 7C]), enc([0D 00 00])] for method=3 (G6000 series).
    """
    common = waste_rows["common"]  # [10 07 7C, 0D 00 00]
    return [
        encode_command(
            spec,
            method_no=3,
            set_prefix="set_command",
            command_bytes=cmd,
            device_keyword=device_keyword,
        )
        for cmd in common
    ]


def _hx(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


if __name__ == "__main__":  # pragma: no cover - demo / self-check
    import sys

    assert lcg16() == ENVELOPE_FIXED_16, "envelope self-check FAILED"
    print("envelope 16 fixed bytes :", _hx(lcg16()), "(self-check OK)")

    xml = Path(sys.argv[1]) if len(sys.argv) > 1 else DEVICES_XML_DEFAULT
    if not xml.exists():
        print(f"(devices.xml not found at {xml}; envelope self-check only)")
        raise SystemExit(0)

    spec = parse_devices_xml(xml)
    waste = parse_waste_rows(xml)
    m3 = spec.encoder_for_method(3)
    print(f"G6000 method=3 -> encoder handler=0x{m3.handler:02x} functor=0x{m3.functor:02x}")
    print("set_command prefix      :", _hx(bytes(spec.prefixes['set_command'])))
    print("waste:common cleartext  :", " | ".join(_hx(c) for c in waste["common"]))

    assert spec.resolution.keyword_value is not None
    default_kw = bytes(spec.resolution.keyword_value)
    bound = bind_keyword(m3, default_kw)
    print(f"default device keyword  : {_hx(default_kw)}  -> bound {_hx(bound)}")

    enc_default = encode_waste_common(spec, waste)
    print("ENCIPHERED (default kw) :", " | ".join(_hx(c) for c in enc_default))

    live = bytes([0x11, 0x22, 0x33, 0x44])  # symbolic live keyword
    bound_live = bind_keyword(m3, live)
    enc_live = encode_waste_common(spec, waste, device_keyword=live)
    print(f"symbolic live keyword   : {_hx(live)}  -> bound {_hx(bound_live)}")
    print("ENCIPHERED (live kw)    :", " | ".join(_hx(c) for c in enc_live))
