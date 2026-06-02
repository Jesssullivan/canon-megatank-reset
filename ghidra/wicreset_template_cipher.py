#!/usr/bin/env python3
# wicreset_template_cipher.py — reproducible Python model of WICReset's Canon
# command-frame transform, recovered statically from printerpotty.exe:
#
#   PrinterCanonSTD::functor_encryption_003  (FUN_004e8410)  — the ENVELOPE
#   PrinterCanonSTD::functor_implementation  (FUN_004e76c0)  — the CIPHER
#   PrinterCanonSTD::functor_initialization  (FUN_004e72b0)  — the KEYSTREAM seed
#
# This is NOT a runnable encryptor on its own: the cipher's substitution tables
# (command.index / command.codes / command.shift) and the device keyword are
# RUNTIME template/device data, not static .exe constants. What IS fully
# recovered and reproduced here is the deterministic ENVELOPE that
# functor_encryption_003 prepends, plus the exact data-flow of the cipher so a
# captured frame can be matched/decoded once the tables are known.
#
# Use: import the helpers, or run for the envelope demo.

# ---- envelope header (functor_encryption_003) -----------------------------
# Disassembly @ 0x4e84e5..0x4e85a6 (verbatim):
#   bVar2 = plaintext[3]                      # 4th byte of app frame [cmd][arg][...]
#   append uint16 0x1200  -> bytes 00 12      # FUN_004d2510(...,0x1200,2,1)
#   append uint8  0x01                        # FUN_004d2510(...,1)
#   append uint8  bVar2                       # the plaintext offset-3 byte
#   16x: seed = seed*0x343fd + 0x269ec3 ; append (seed>>16)&0xff   (seed0=0x12345678)
#   then a tail buffer = plaintext[4:]        # FUN_004d2960(buf, len-4, 4)
#   then index/special remap + functor_implementation over the assembled buffer.

LCG_MUL = 0x343FD          # MSVC rand() multiplier (214013)
LCG_ADD = 0x269EC3         # MSVC rand() increment  (2531011)
LCG_SEED0 = 0x12345678     # fixed seed -> header is DETERMINISTIC


def lcg_header_bytes(n=16, seed=LCG_SEED0):
    out = []
    for _ in range(n):
        seed = (seed * LCG_MUL + LCG_ADD) & 0xFFFFFFFF
        out.append((seed >> 16) & 0xFF)
    return bytes(out)


def encryption_003_header(plaintext_app_frame):
    """The deterministic 20-byte preamble functor_encryption_003 prepends.

    plaintext_app_frame = the app-level [cmd][arg_hi][arg_lo][payload...] frame
    (>= 4 bytes; the function errors 'Command buffer is too small.' below 4).
    Returns the literal header bytes (constant except for the single cmd byte).
    """
    assert len(plaintext_app_frame) >= 4, "Command buffer is too small."
    cmd_byte = plaintext_app_frame[3]            # MOV BL,[EAX+3]
    return bytes([0x00, 0x12, 0x01, cmd_byte]) + lcg_header_bytes()


# ---- cipher data-flow (functor_implementation, FUN_004e76c0) --------------
# For documentation/decoding; tables are runtime template data.
#
#   seed   = fold message bytes big-endian: s = (s<<8 | b) over the message
#   ix     = command.index[...]    (per-model array, dotted-path key)
#   codes  = command.codes[...]
#   shift  = command.shift[...]    + per-step operator program over {=,+,-,*,/,%,&,|,^}
#   keystream[i] derived from (seed % len(table)) indexing + the shift program
#   out[i] = in[i] ^ keystream[i]            # symmetric: encode==decode
#
# functor_initialization (FUN_004e72b0) seeds the per-session encoder from
# keyword.index/keyword.codes XOR the DEVICE keyword (commands.get_keyword),
# so the live keystream is device-/session-bound and cannot be precomputed
# from the .exe alone.

OPERATORS = {  # FUN_0045f180 cascade, chars in match order
    0x3D: "=", 0x2B: "+", 0x2D: "-", 0x2A: "*", 0x2F: "/",
    0x25: "%", 0x26: "&", 0x7C: "|", 0x5E: "^",
}


if __name__ == "__main__":
    # demo: header for a v5103-style absorber app frame 85 00 00 00 03 01 03 07
    frame = bytes([0x85, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0x07])
    hdr = encryption_003_header(frame)
    print("plaintext app frame :", frame.hex(" "))
    print("envelope header (20B):", hdr.hex(" "))
    print("  (= 00 12 01 [%02x] + 16 fixed LCG bytes)" % frame[3])
