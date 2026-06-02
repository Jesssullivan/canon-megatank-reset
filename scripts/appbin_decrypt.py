#!/usr/bin/env python3
"""Decrypt WICReset printerpotty.exe APP.BIN container.
Cipher recovered statically: archive::des = OpenSSL DES_ede3_cbc (3DES-EDE3, CBC).
Key = 24 zero bytes, IV = 8 zero bytes (construction sites set empty wxStrings).
Pipeline: strip last 4 bytes (footer) -> 3DES-EDE3-CBC decrypt -> strip PKCS-style
trailing pad (last byte * N) -> zlib inflate -> property tree (devices.xml etc).
"""
import sys, struct, zlib, hashlib

# ---- pure-python DES (FIPS 46-3), then EDE3-CBC ----
# Use a compact DES implementation.
_IP=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
_FP=[40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
_E=[32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
_P=[16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
_PC1=[57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
_PC2=[14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
_SHIFT=[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
_S=[
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]
def _permute(block,table,n_in):
    v=0
    for i,pos in enumerate(table):
        v=(v<<1)|((block>>(n_in-pos))&1)
    return v
def _keys(key8):
    k=int.from_bytes(key8,'big')
    k=_permute(k,_PC1,64)
    C=k>>28; D=k&0xfffffff; ks=[]
    for s in _SHIFT:
        C=((C<<s)|(C>>(28-s)))&0xfffffff
        D=((D<<s)|(D>>(28-s)))&0xfffffff
        ks.append(_permute((C<<28)|D,_PC2,56))
    return ks
def _crypt_block(block8,ks):
    b=int.from_bytes(block8,'big')
    b=_permute(b,_IP,64)
    L=b>>32; R=b&0xffffffff
    for k in ks:
        er=_permute(R,_E,32)^k
        out=0
        for i in range(8):
            six=(er>>(42-6*i))&0x3f
            row=((six&0x20)>>4)|(six&1); col=(six>>1)&0xf
            out=(out<<4)|_S[i][row*16+col]
        f=_permute(out,_P,32)
        L,R=R,L^f
    pre=(R<<32)|L
    return _permute(pre,_FP,64).to_bytes(8,'big')
def des_ecb(block8,key8,decrypt):
    ks=_keys(key8)
    if decrypt: ks=ks[::-1]
    return _crypt_block(block8,ks)
def ede3_cbc_decrypt(data,k1,k2,k3,iv):
    out=bytearray(); prev=iv
    for i in range(0,len(data),8):
        ct=data[i:i+8]
        x=des_ecb(ct,k1,True); x=des_ecb(x,k2,False); x=des_ecb(x,k3,True)
        out+=bytes(a^b for a,b in zip(x,prev)); prev=ct
    return bytes(out)

def main():
    exe=open(sys.argv[1] if len(sys.argv)>1 else "/tmp/printerpotty.exe","rb").read()
    off=0x638ee8; ln=571596
    blob=exe[off:off+ln]
    print("blob len", len(blob), "sha256", hashlib.sha256(blob).hexdigest()[:16])
    # FUN_004d2a10: strip last 4 bytes (footer)
    body=blob[:-4]
    print("after footer strip:", len(body), "mult8?", len(body)%8)
    key=b"\x00"*24; iv=b"\x00"*8
    pt=ede3_cbc_decrypt(body, key[0:8],key[8:16],key[16:24], iv)
    print("decrypted head:", pt[:16].hex())
    print("(see decrypt_layer / extract_appbin for the full two-layer pipeline)")


# ---- the archive::des container pipeline (recovered from FUN_00457030/004151a0) ----
KEY = b"\x00" * 24   # archive::des wxString key field: empty -> 3 x 8 zero bytes
IV  = b"\x00" * 8    # archive::des wxString iv  field: empty -> 8 zero bytes

def decrypt_layer(blob):
    """One archive::des layer: strip 4-byte footer (FUN_004d2a10),
    3DES-EDE3-CBC decrypt (FUN_00457030), strip PKCS#5 pad (FUN_00457250).
    Returns the inner plaintext (a ZIP for both observed layers)."""
    body = blob[:-4]                       # FUN_004d2a10 trims the last 4 bytes
    assert len(body) % 8 == 0, "ciphertext not a multiple of the 8-byte DES block"
    pt = ede3_cbc_decrypt(body, KEY[0:8], KEY[8:16], KEY[16:24], IV)
    pad = pt[-1]
    if 0 < pad <= 8 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]                     # PKCS#5/CMS padding
    return pt

def extract_appbin(exe_path, out_dir="/tmp/appbin_out"):
    import os, io, zipfile
    exe = open(exe_path, "rb").read()
    off, ln = 0x638ee8, 571596             # APP.BIN PE resource (DATA/APP.BIN)
    layer1 = decrypt_layer(exe[off:off+ln])
    z1 = zipfile.ZipFile(io.BytesIO(layer1))
    os.makedirs(out_dir, exist_ok=True)
    z1.extractall(out_dir)
    print("layer-1 ZIP: %d entries -> %s" % (len(z1.namelist()), out_dir))
    srs_path = os.path.join(out_dir, "devices.srs")
    if os.path.exists(srs_path):
        layer2 = decrypt_layer(open(srs_path, "rb").read())
        z2 = zipfile.ZipFile(io.BytesIO(layer2))
        z2.extractall(out_dir)             # yields devices.xml (the plaintext DB)
        xmlp = os.path.join(out_dir, "devices.xml")
        print("layer-2 ZIP: %d entries; devices.xml=%d bytes" %
              (len(z2.namelist()), os.path.getsize(xmlp)))
    return out_dir


if __name__ == "__main__":
    exe = sys.argv[1] if len(sys.argv) > 1 else "/tmp/printerpotty.exe"
    extract_appbin(exe)
