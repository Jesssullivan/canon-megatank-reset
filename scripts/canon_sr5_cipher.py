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
  functor 2 -> functor_implementation (FUN_004e76c0): transforms the SUBJECT
               buffer, seeded big-endian by folding the SEED buffer. For
               functor-3 the SUBJECT is the 20-byte envelope and the SEED is the
               4-byte bound keyword (the RECOVERED, hardware-validated buffer-
               role swap), so the output is 20 bytes. The per-byte SHIFT is a
               TABLE built by the operator-VM over the selected command.shift
               <array> (its 4 <value> sub-programs, pp-helpers.txt:338-495),
               indexed per output position (pp-helpers.txt:522-526) -- NOT one
               scalar. Array selection = seed % {5 index, 7 codes, 3 shift}. The
               index PATH is the nested table-walk FUN_00449110/FUN_004c1bf0 with
               the send (param_5=1: out[i]=in[perm[i]]^ks) / recv (param_5=0:
               out[perm[i]]=in[i]^ks) swap.
  functor 3 -> functor_encryption_003 (FUN_004e8410): build a 20-byte
               deterministic envelope [00 12 01 <cmd>] + 16 fixed MSVC-rand()
               bytes (seed 0x12345678 ->
               e9 3f 0d a1 96 95 31 04 49 2d 9e 61 83 cf 09 6f), apply the
               function-block <special> overwrite (e.g. code 0x00 ->
               <special>0x04 0x66</special> => envelope[4+0x04]=envelope[8]:=0x66
               over 0x96, FUN_004e8410:120-128) and the <indexes> payload
               scatter (FUN_004e8410:129-138), then run functor-2 with this
               envelope as the SUBJECT and the bound keyword as the SEED,
               emitting a 20-byte payload. The wire frame is assembled as
               85 00 00 || payload(20) = 23 bytes -- NOT app_frame || 4 bytes.
  keyword binding -> functor_initialization (FUN_004e72b0): the per-session
               encoder XORs the live device keyword into the keyword.codes
               table via keyword.index. With the template-default keyword
               this reduces to keyword.value (4D B6 AB 00).

NOTE on the seed fold: local_d4 = local_d4*0x100 + byte over the SEED buffer
(FUN_004e76c0:258-266), mod 2^32. For functor-3 the SEED is the 4-byte bound
keyword, so the whole keyword folds into the seed; the 20-byte envelope is the
SUBJECT and every envelope byte (including the <special> overwrite and the
<indexes> payload scatter) reaches the output. The wire payload is therefore
fully command-dependent (the operand rides the envelope via frame[3] + the
<indexes> scatter). This is the literal transform, reproduced here exactly and
validated byte-exact against WICReset's real captured frame.

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
    """Evaluate ONE command.shift <value> sub-program as the operator-VM.

    Mirrors functor_implementation's inner shift-table loop
    (FUN_004e76c0:348-476, inner loop = local_114 <action> steps): acc
    (uVar10 = uVar8) starts at the message seed local_d4 and each <action> step
    folds: '=' set, '+' add, '-' sub, '*' mul, '/' div, '%' mod, '&' and, '|'
    or, '^' xor (32-bit). A command.shift <array> holds N <value> sub-programs
    (4 for method-3); the OUTER loop (FUN_004e76c0:340-495, local_128 of them)
    evaluates each independently from the seed -- acc reset to local_d4 at :342
    -- producing exactly one shift-table entry per <value>, appended at :492
    (see :func:`build_shift_table`). The first step is typically '=' which loads
    the step's data, anchoring the program independent of acc.
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


# A command.shift <array> is FOUR <value> sub-programs, each a tuple of steps.
ShiftArray = tuple[tuple[ShiftStep, ...], ...]


def build_shift_table(seed: int, shift_array: ShiftArray) -> tuple[int, ...]:
    """Build the per-position SHIFT TABLE for one command.shift <array>.

    ONE TRUE semantics (FUN_004e76c0:340-495): the OUTER loop iterates the
    <array>'s <value> sub-programs (local_128 of them), the INNER loop
    (:348-476, local_114 of them) folds each <value>'s <action> steps. The
    accumulator is reset to the message seed (uVar10 = local_d4, line 342) at
    the START of each <value>, and the accumulated result is appended to the
    shift-table container (local_cc, lines 484-492). Returns exactly one shift
    value per <value> -- NOT one per <action>. Document/array order is
    preserved verbatim (load-bearing; the keystream indexes this table by
    position). Returns one shift value per <value>.
    """
    return tuple(apply_shift_program(seed, value) for value in shift_array)


# ---------------------------------------------------------------------------
# functor-3 function block (<function> <code>/<special>/<indexes>) -- RECOVERED
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FunctionBlock:
    """One <function> entry: keyed by <code> (= the command id = frame[3]).

    <special> is a flat list of (offset, value) pairs the functor-3 envelope
    builder writes as envelope[4+offset] := value (FUN_004e8410:120-128).
    <indexes> scatters the frame[4:] payload bytes into envelope[4+indexes[i]]
    (FUN_004e8410:129-138).
    """

    code: int
    special: tuple[int, ...]
    indexes: tuple[int, ...]


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
    command_shift: tuple[ShiftArray, ...]  # 3 <array>s, each 4 <value> sub-programs
    functions: dict[int, FunctionBlock]    # <function> blocks keyed by <code>


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
    # Each command.shift <array> holds FOUR <value> sub-programs; each <value>
    # is its own operator-VM program (a tuple of <action> steps). Parse that
    # nesting (NOT a flat step list) so build_shift_table can produce one
    # shift-table entry per <value> (FUN_004e76c0:340-495).
    command_shift: list[ShiftArray] = []
    for arr in re.findall(r"<array>(.*?)</array>", shift_block, re.S):
        values: list[tuple[ShiftStep, ...]] = []
        for val in re.findall(r"<value>(.*?)</value>", arr, re.S):
            steps = tuple(
                ShiftStep(sign=sign, data=int(data))
                for sign, data in re.findall(
                    r"<sign><!\[CDATA\[(.*?)\]\]></sign><data>(\d+)</data>", val, re.S
                )
            )
            values.append(steps)
        command_shift.append(tuple(values))

    return SR5Method(
        handler=handler,
        functor=functor,
        keyword_codes=kw_codes,
        keyword_index=kw_index,
        keyword_value=kw_value,
        command_index=command_index,
        command_codes=command_codes,
        command_shift=tuple(command_shift),
        functions=_parse_functions(block),
    )


def _parse_functions(block: str) -> dict[int, FunctionBlock]:
    """Parse the <function> blocks (keyed by <code>) inside a <method> block.

    Each <function> carries <code>, <special> (offset/value pairs) and
    <indexes> (payload scatter offsets). Absent in resolution-only methods.
    """
    funcs: dict[int, FunctionBlock] = {}
    for fb in re.findall(r"<function>(.*?)</function>", block, re.S):
        code_m = re.search(r"<code>(.*?)</code>", fb, re.S)
        if code_m is None:
            continue
        code = _hexbytes(code_m.group(1))[0]
        sp_m = re.search(r"<special>(.*?)</special>", fb, re.S)
        ix_m = re.search(r"<indexes>(.*?)</indexes>", fb, re.S)
        funcs[code] = FunctionBlock(
            code=code,
            special=_hexbytes(sp_m.group(1)) if sp_m else (),
            indexes=_hexbytes(ix_m.group(1)) if ix_m else (),
        )
    return funcs


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
def seed_fold(buffer: bytes) -> int:
    """local_d4: big-endian fold of the COMMAND/ENVELOPE buffer ONLY.

    FUN_004e76c0:258-266 -- local_d4 = local_d4*0x100 + byte over local_104
    bytes (param_1, the command/envelope seed source). The keyword does NOT
    enter the seed; it is bound separately (functor_initialization) and is the
    *subject* of the transform, not the seed. Note: over a >4-byte buffer only
    the trailing 4 bytes survive (256^4 == 0 mod 2^32).
    """
    seed = 0
    for b in buffer:
        seed = (seed * 0x100 + b) & 0xFFFFFFFF
    return seed


def _derive(
    method: SR5Method, seed: int
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    """Select the index/codes arrays and build the SHIFT TABLE for ``seed``.

    Array selection = seed % {len index (5), len codes (7), len shift (3)}
    (FUN_004e76c0:286-292). The shift TABLE is built from the selected
    command.shift <array> by evaluating each of its <value> sub-programs.
    """
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

    Operates on the 4-byte BOUND keyword (``keyword``), seeded by the
    big-endian fold of the COMMAND/ENVELOPE buffer (``seed_source``). The output
    loop (FUN_004e76c0:501-534) is bounded by local_e4 = len(keyword) and walks
    the index/codes/shift tables per output position:

        for i in 0..len:
            j      = index_arr[i] % len            # FUN_004c1bf0 index walk
            code   = codes_arr[j % 20]             # second nested walk
            shift  = shift_table[j % len(table)]   # local_d0 shift-table walk
            ksbyte = (seed >> (shift & 0x1f)) ^ code
            send (param_5=1):  out[i] = keyword[j] ^ ksbyte
            recv (param_5=0):  out[j] = keyword[i] ^ ksbyte

    The 20-element index array is reduced modulo the 4-byte buffer length (the
    binary's bounded keyword buffer); the i<->j map is NOT a bijection for the
    keyword and the transform is an obfuscating scramble, not an involution
    (faithful to the binary, whose keyword transform is one-way over 4 bytes).
    """
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


# ---------------------------------------------------------------------------
# functor 3 (functor_encryption_003, FUN_004e8410) -- RECOVERED
# ---------------------------------------------------------------------------
def envelope3(method: SR5Method, app_frame: bytes) -> bytes:
    """The deterministic 20-byte functor-3 envelope (the functor-2 SEED).

    FUN_004e8410:57-138 -- [00 12 01 frame[3]] + 16 fixed LCG bytes, then:
      * <special> overwrite: for each (offset, value) pair of the function
        block keyed by frame[3], envelope[4 + offset] := value (lines 120-128).
        E.g. code 0x00 -> <special>0x04 0x66</special> => envelope[8] := 0x66
        (over the 0x96 LCG byte).
      * <indexes> scatter: envelope[4 + indexes[i]] := frame[4:][i] for each
        payload byte (lines 129-138).
    Errors below 4 bytes ("Command buffer is too small.").
    """
    if len(app_frame) < KEYWORD_LEN:
        raise ValueError("Command buffer is too small.")
    cmd_id = app_frame[3]
    env = bytearray([0x00, 0x12, 0x01, cmd_id]) + bytearray(lcg16())
    block = method.functions.get(cmd_id)
    if block is not None:
        # <special>: flat (offset, value) pairs -> env[4 + offset] = value
        sp = block.special
        for k in range(0, len(sp) - 1, 2):
            off = sp[k]
            if 4 + off < len(env):
                env[4 + off] = sp[k + 1] & 0xFF
        # <indexes>: scatter the frame[4:] payload into env[4 + indexes[i]]
        payload = app_frame[4:]
        for i, off in enumerate(block.indexes):
            if i < len(payload) and 4 + off < len(env):
                env[4 + off] = payload[i]
    return bytes(env)


def functor3_encrypt(method: SR5Method, app_frame: bytes, bound_keyword: bytes) -> bytes:
    """Emit the 20-byte enciphered functor-3 payload.

    RECOVERED buffer roles (hardware-validated 2026-06-01, native libusb 5B00
    clear): functor-2 runs with the SUBJECT = the 20-byte functor-3 ENVELOPE and
    the SEED = the 4-byte BOUND keyword (the swapped roles). Returns 20 bytes --
    the wire frame (``85 00 00 || these 20 bytes`` = 23 bytes) is assembled by
    :func:`encode_command`."""
    envelope = envelope3(method, app_frame)
    return functor2_transform(method, envelope, seed_source=bound_keyword, send=True)


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
    header = app_frame[:3]  # the set_command header (85 00 00); operand rides the envelope
    if method.functor == FUNCTOR_IDENTITY:
        return app_frame
    if method.functor == FUNCTOR_IMPLEMENTATION:
        # functor 2 direct (swapped roles): SUBJECT = the app frame, SEED = the
        # bound keyword; emit header || enciphered payload.
        payload = functor2_transform(method, app_frame, seed_source=bound, send=True)
        return header + payload
    if method.functor == FUNCTOR_ENCRYPTION_003:
        # functor 3: SUBJECT = the 20-byte envelope, SEED = the bound keyword;
        # emit the 23-byte wire frame 85 00 00 || payload(20).
        return header + functor3_encrypt(method, app_frame, bound)
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
