#!/usr/bin/env python3
# wicreset_probe.py — read-only census of printerpotty.exe (WICReset, PE32).
#
# Verifies the saved analysis (function count) then anchors on the IMPORTS that
# decide the local-vs-cloud verdict and the USB hook target:
#   - network: WinINet / WinHTTP / WS2_32 (socket) / curl-internal
#   - crypto:  bcrypt / CRYPT32 (key/TLS)
#   - USB I/O: DeviceIoControl / CreateFileW / SetupDi*
# For each imported API it lists the caller functions (the static call sites),
# so the dynamic lane knows exactly which functions issue each event.
#
# Read-only: open the EXISTING analyzed program by name (never re-import).
import os
import pyghidra
pyghidra.start()
from pyghidra import open_program  # noqa: E402

PROJ = os.environ["CMR_PROJ"]
NAME = os.environ.get("CMR_PROJ_NAME", "wicreset-pp-full")
PROG = os.environ.get("CMR_PROG_NAME", "printerpotty.exe")
OUT = os.environ.get("CMR_OUT", "/tmp/pp-probe.txt")

# APIs whose call sites we want to enumerate.
USB_APIS = ["DeviceIoControl", "CreateFileW", "CreateFileA",
            "SetupDiGetClassDevsW", "SetupDiGetClassDevsA",
            "SetupDiEnumDeviceInterfaces", "WinUsb_ControlTransfer",
            "WinUsb_WritePipe", "WinUsb_ReadPipe", "WinUsb_Initialize"]
NET_APIS = ["InternetOpenW", "InternetOpenA", "InternetConnectW", "InternetConnectA",
            "HttpOpenRequestW", "HttpOpenRequestA", "HttpSendRequestW", "HttpSendRequestA",
            "InternetReadFile", "InternetOpenUrlW", "InternetOpenUrlA",
            "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
            "WinHttpReceiveResponse", "WinHttpReadData",
            "connect", "send", "recv", "WSAStartup", "getaddrinfo", "gethostbyname",
            "socket", "closesocket"]
CRYPTO_APIS = ["BCryptOpenAlgorithmProvider", "BCryptHashData", "BCryptEncrypt",
               "BCryptDecrypt", "BCryptGenerateSymmetricKey",
               "CryptStringToBinaryW", "CryptStringToBinaryA",
               "CryptBinaryToStringW", "CryptProtectData", "CryptUnprotectData",
               "CryptAcquireContextW", "CryptHashData", "CryptDecrypt"]


def callers_of(p, fm, st, refmgr, api):
    """Return set of (funcname, entry) calling `api`, two-hop through thunks."""
    out = {}
    for sym in st.getSymbols(api):
        seed = sym.getAddress()
        for r in refmgr.getReferencesTo(seed):
            fa = r.getFromAddress()
            fn = fm.getFunctionContaining(fa)
            if fn is not None:
                out[fn.getEntryPoint().toString()] = fn.getName()
            else:
                # thunk hop
                for r2 in refmgr.getReferencesTo(fa):
                    fn2 = fm.getFunctionContaining(r2.getFromAddress())
                    if fn2 is not None:
                        out[fn2.getEntryPoint().toString()] = fn2.getName()
    return out


def list_imported(st, names):
    """Which of `names` actually exist as symbols (i.e. imported)."""
    present = []
    for n in names:
        syms = list(st.getSymbols(n))
        if syms:
            present.append((n, [s.getAddress().toString() for s in syms]))
    return present


print("CMR_START probe")
with open_program(None, project_location=PROJ, project_name=NAME,
                  program_name=PROG, analyze=False) as flat:
    p = flat.getCurrentProgram()
    fm = p.getFunctionManager()
    st = p.getSymbolTable()
    refmgr = p.getReferenceManager()
    nfunc = fm.getFunctionCount()
    with open(OUT, "w") as fh:
        def w(s=""):
            fh.write(s + "\n")
            print(s)
        w("# WICReset printerpotty.exe probe")
        w("# functions in saved analysis: %d" % nfunc)
        w("# image base: %s" % p.getImageBase())
        w()
        for label, apis in (("USB / DEVICE I/O", USB_APIS),
                            ("NETWORK / CLOUD", NET_APIS),
                            ("CRYPTO / KEY", CRYPTO_APIS)):
            w("===== %s =====" % label)
            present = list_imported(st, apis)
            if not present:
                w("  (none imported)")
            for n, addrs in present:
                callers = callers_of(p, fm, st, refmgr, n)
                w("  %-30s imported@%s  -> %d caller fn(s)" % (n, addrs[0], len(callers)))
                for ea, nm in sorted(callers.items()):
                    w("        %s  %s" % (ea, nm))
            w()
print("CMR_DONE wrote %s" % OUT)
