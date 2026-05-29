#!/usr/bin/env python3
# canon-tool R3 TIN-1697 — parse Win32 RT_DIALOG templates → (dialogId, controlId, caption).
#
# MFC dispatches a button click via the message map keyed on the control ID,
# so to find the absorber-reset "Set" handler we first need that button's ID.
# Reads raw dialog resource files (wrestool -x --raw --type=5 --name=<id>) named
# <id>.bin in the given dir; prints every control's id + caption.
#
# usage: parse_dialogs.py <dir-of-dialog-bins>

import sys, struct, glob, os

def rd_sz_or_ord(buf, off):
    # sz_Or_Ord: 0x0000 => empty; 0xFFFF => ordinal (next u16); else UTF-16 NUL-terminated
    if off + 2 > len(buf):
        return "", off + 2
    first = struct.unpack_from("<H", buf, off)[0]
    if first == 0x0000:
        return "", off + 2
    if first == 0xFFFF:
        ordv = struct.unpack_from("<H", buf, off + 2)[0]
        return "#%d" % ordv, off + 4
    # UTF-16LE string until NUL
    end = off
    while end + 2 <= len(buf):
        ch = struct.unpack_from("<H", buf, end)[0]
        if ch == 0:
            break
        end += 2
    s = buf[off:end].decode("utf-16-le", "ignore")
    return s, end + 2

def align4(off):
    return (off + 3) & ~3

def parse_dialog(buf, dlg_id):
    out = []
    if len(buf) < 4:
        return out
    sig, ver = struct.unpack_from("<HH", buf, 0)
    ex = (sig == 0xFFFF and ver == 0x0001)  # DLGTEMPLATEEX has dlgVer=1, signature=0xFFFF (at off 0/2)
    # Actually DLGTEMPLATEEX: WORD dlgVer; WORD signature(0xFFFF). So check signature at off 2.
    sig2 = struct.unpack_from("<H", buf, 2)[0]
    ex = (sig2 == 0xFFFF)
    if ex:
        # DLGTEMPLATEEX header
        off = 0
        off += 2 + 2 + 4 + 4 + 4  # dlgVer,signature,helpID,exStyle,style
        cdit = struct.unpack_from("<H", buf, off)[0]; off += 2
        off += 2 + 2 + 2 + 2      # x,y,cx,cy
        _, off = rd_sz_or_ord(buf, off)  # menu
        _, off = rd_sz_or_ord(buf, off)  # windowClass
        _, off = rd_sz_or_ord(buf, off)  # title
        # if DS_SETFONT/SHELLFONT: pointsize(u16), weight(u16), italic(u8), charset(u8), typeface(sz)
        # detect via style bit DS_SETFONT=0x40; read style from header (off 8 after dlgVer/sig/helpID? )
        style = struct.unpack_from("<I", buf, 8)[0]  # exStyle at +4..7? approximate; many fonts present
        # We just try: assume font present (these dialogs all set MS UI Gothic)
        try:
            off += 2 + 2 + 1 + 1
            _, off = rd_sz_or_ord(buf, off)  # typeface
        except Exception:
            pass
        for _ in range(cdit):
            off = align4(off)
            if off + 4*5 + 2 > len(buf):
                break
            off += 4 + 4 + 4   # helpID, exStyle, style
            off += 2*4         # x,y,cx,cy
            cid = struct.unpack_from("<i", buf, off)[0]; off += 4  # id (DWORD in EX)
            cls, off = rd_sz_or_ord(buf, off)
            cap, off = rd_sz_or_ord(buf, off)
            extra = struct.unpack_from("<H", buf, off)[0]; off += 2
            off += extra
            if cap:
                out.append((dlg_id, cid, cls, cap))
    else:
        # classic DLGTEMPLATE
        off = 0
        style, exstyle = struct.unpack_from("<II", buf, 0); off += 8
        cdit = struct.unpack_from("<H", buf, off)[0]; off += 2
        off += 2*4  # x,y,cx,cy
        _, off = rd_sz_or_ord(buf, off)  # menu
        _, off = rd_sz_or_ord(buf, off)  # class
        _, off = rd_sz_or_ord(buf, off)  # title
        if style & 0x40:  # DS_SETFONT
            off += 2     # pointsize
            _, off = rd_sz_or_ord(buf, off)  # typeface
        for _ in range(cdit):
            off = align4(off)
            if off + 18 > len(buf):
                break
            off += 4 + 4     # style, exstyle
            off += 2*4       # x,y,cx,cy
            cid = struct.unpack_from("<H", buf, off)[0]; off += 2  # id (WORD in classic)
            cls, off = rd_sz_or_ord(buf, off)
            cap, off = rd_sz_or_ord(buf, off)
            extra = struct.unpack_from("<H", buf, off)[0]; off += 2
            off += extra
            if cap:
                out.append((dlg_id, cid, cls, cap))
    return out

def main():
    d = sys.argv[1]
    rows = []
    for path in sorted(glob.glob(os.path.join(d, "*.bin"))):
        dlg_id = os.path.splitext(os.path.basename(path))[0]
        with open(path, "rb") as fh:
            buf = fh.read()
        try:
            rows += parse_dialog(buf, dlg_id)
        except Exception as e:
            print("# parse error %s: %s" % (dlg_id, e))
    for dlg_id, cid, cls, cap in rows:
        print("dlg=%s  id=%d (0x%x)  cls=%-10s  %r" % (dlg_id, cid, cid & 0xffffffff, cls, cap))

if __name__ == "__main__":
    main()
