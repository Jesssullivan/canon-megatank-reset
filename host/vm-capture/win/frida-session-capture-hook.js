/*
 * frida-session-capture-hook.js — Lane A combined hook for the WICReset G6020
 * ENCRYPTED-SESSION capture (NO KEY).
 *
 * MERGES the two proven hooks into one:
 *   (1) frida-1284clamp-hook.js  — clamp nOutBufferSize 5000->4096 for ioctl
 *       0x220034 (IOCTL_USBPRINT_GET_1284_ID). This is the page-size fix that
 *       gets WICReset PAST the 1284 gate so it proceeds to the encrypted
 *       maintenance session.
 *   (2) frida-wicreset-hook.js   — full in/out hex + sizes for EVERY
 *       DeviceIoControl, plus CreateFile / WinUSB / connect tracing.
 *
 * PURPOSE: capture WICReset's REAL enciphered series-name read — the
 * set_session (0x220038 VENDOR_SET_COMMAND) / get_keyword (0x22003c
 * VENDOR_GET_COMMAND) exchange (and any 0x16000c) on the {28d78fad} usbprint
 * handle — that fails with "Could not read encrypted buffer with the printer
 * series name from the device" BEFORE the key field. NO key is entered; this
 * whole capture precedes key entry.
 *
 * The 0x220038/0x22003c/0x16000c IOCTLs get FULL inHex (onEnter) + FULL
 * outHex/bytesReturned/ret (onLeave) with a RAISED hex cap (these maintenance
 * frames are tiny — ~20-64 B — but we cap at 1024 to never truncate, while the
 * noisy 0x220034 1284-ID stays full-ID-sized).
 *
 * Launch (guest, schtasks /ru cap /it via a .cmd wrapper redirecting stdout):
 *   frida-inject-x86-16.exe -f "C:\PROGRA~2\PRINTE~1\PRINTE~1.EXE"
 *       -s "C:\canon\frida-session-capture-hook.js" -R v8 > log 2> err
 *   (v16.5.9; do NOT use -e with redirect, do NOT use -o on v16.)
 */
'use strict';

// ── tunables ────────────────────────────────────────────────────────────────
const CLAMP = 4096;
const IOCTL_GET_1284 = 0x220034;
const IOCTL_VENDOR_GET = 0x22003c;   // VENDOR_GET_COMMAND — the get_version/series-name read; same >4096 page cap
// the maintenance / vendor IOCTLs we must never truncate
const VENDOR_IOCTLS = { 0x220030: 'GET_LPT_STATUS', 0x220034: 'GET_1284_ID',
                        0x220038: 'VENDOR_SET_COMMAND', 0x22003c: 'VENDOR_GET_COMMAND',
                        0x16000c: 'IOCTL_16000C' };
const HEX_CAP_VENDOR = 1024;   // tiny maintenance frames -> never truncate
const HEX_CAP_OTHER  = 512;    // everything else

// ── Frida-version compat shims (work on v16 and v17) ─────────────────────────
function findExport(libName, symName) {
  try {
    if (libName) {
      var m = Process.getModuleByName ? Process.getModuleByName(libName) : null;
      if (m && m.findExportByName) { var e = m.findExportByName(symName); if (e) return e; }
    }
  } catch (e) {}
  try { if (Module.getGlobalExportByName) return Module.getGlobalExportByName(symName); } catch (e) {}
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(symName); } catch (e) {}
  try { if (Module.findExportByName) return Module.findExportByName(libName, symName); } catch (e) {}
  return null;
}
function findModule(libName) {
  try { if (Process.findModuleByName) return Process.findModuleByName(libName); } catch (e) {}
  try { if (Process.getModuleByName) return Process.getModuleByName(libName); } catch (e) {}
  try {
    var mods = Process.enumerateModules ? Process.enumerateModules() : [];
    for (var i = 0; i < mods.length; i++)
      if (mods[i].name && mods[i].name.toLowerCase() === libName.toLowerCase()) return mods[i];
  } catch (e) {}
  return null;
}

const T0 = Date.now();
function now() { return Date.now() - T0; }
function emit(obj) {
  obj.t = now();
  try { send(obj); } catch (e) {}
  console.log(JSON.stringify(obj));
}
function hexAt(ptr, len, cap) {
  if (ptr.isNull() || len <= 0) return '';
  const c = Math.min(len, cap || HEX_CAP_OTHER);
  try {
    const u8 = new Uint8Array(ptr.readByteArray(c));
    let s = '';
    for (let i = 0; i < u8.length; i++) s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16);
    return s + (len > c ? '..(' + len + 'B)' : '');
  } catch (e) { return '<unreadable:' + e + '>'; }
}

emit({ api: 'HOOK_LOADED', note: 'frida-session-capture-hook active (clamp+full-trace)',
       t0_epoch_ms: T0, clamp: CLAMP });

// ── 1. CreateFile (device opens) ─────────────────────────────────────────────
['CreateFileW', 'CreateFileA'].forEach(function (name) {
  const p = findExport('kernel32.dll', name);
  if (!p) return;
  const wide = name.endsWith('W');
  Interceptor.attach(p, {
    onEnter: function (args) {
      try {
        const path = wide ? args[0].readUtf16String() : args[0].readAnsiString();
        if (path && /usb|\\\\\.\\|usbscan|usbprint|print|\{28d78fad/i.test(path)) this.path = path;
      } catch (e) {}
    },
    onLeave: function (ret) {
      if (this.path) emit({ api: 'CreateFile', path: this.path, handle: ret.toString() });
    }
  });
});

// ── 2. DeviceIoControl — clamp 0x220034 + full in/out trace of ALL ioctls ────
(function () {
  const p = findExport('kernel32.dll', 'DeviceIoControl');
  if (!p) { emit({ api: 'WARN', note: 'DeviceIoControl not found' }); return; }
  Interceptor.attach(p, {
    onEnter: function (args) {
      this.ioctl   = args[1].toUInt32();
      this.inBuf   = args[2];
      this.inSize  = args[3].toUInt32();
      this.outBuf  = args[4];
      this.outSize = args[5].toUInt32();
      this.bytesRet = args[6];
      this.isVendor = (this.ioctl in VENDOR_IOCTLS);
      this.cap = this.isVendor ? HEX_CAP_VENDOR : HEX_CAP_OTHER;

      // --- CLAMP behaviour: usbprint.sys (10.0.26100) caps the OUT buffer at one
      // page (4096). WICReset's deep reads default to 5000 -> rejected. Clamp the
      // affected reads back to 4096. Confirmed for 0x220034 (GET_1284_ID); extended
      // to 0x22003c (VENDOR_GET_COMMAND, the get_version/series-name 8a 00 00 read)
      // which fails the same way (ret:0/0 at 5000). Only clamp READ IOCTLs.
      this.clamped = false;
      if ((this.ioctl === IOCTL_GET_1284 || this.ioctl === IOCTL_VENDOR_GET) && this.outSize > CLAMP) {
        emit({ api: 'CLAMP', ioctl: '0x' + this.ioctl.toString(16), origOutSize: this.outSize, newOutSize: CLAMP });
        args[5] = ptr(CLAMP);
        this.outSize = CLAMP;
        this.clamped = true;
      }

      // --- full input-buffer trace (populated before the call -> dump onEnter)
      emit({
        api: 'DeviceIoControl', dir: 'in',
        ioctl: '0x' + this.ioctl.toString(16),
        name: VENDOR_IOCTLS[this.ioctl] || undefined,
        inSize: this.inSize, outSize: this.outSize,
        clamped: this.clamped,
        inHex: hexAt(this.inBuf, this.inSize, this.cap)
      });
    },
    onLeave: function (ret) {
      let retLen = this.outSize;
      try { if (!this.bytesRet.isNull()) retLen = this.bytesRet.readU32(); } catch (e) {}
      let lastErr = undefined;
      try { lastErr = this.lastError; } catch (e) {}
      emit({
        api: 'DeviceIoControl', dir: 'out',
        ioctl: '0x' + this.ioctl.toString(16),
        name: VENDOR_IOCTLS[this.ioctl] || undefined,
        ret: ret.toInt32(), bytesReturned: retLen,
        clamped: this.clamped,
        outHex: hexAt(this.outBuf, retLen, this.cap)
      });
    }
  });
})();

// ── 3. WinUSB path (in case a build talks WinUSB directly) ───────────────────
function hookWinUsb() {
  const mod = findModule('winusb.dll');
  if (!mod) return false;
  const ct = findExport('winusb.dll', 'WinUsb_ControlTransfer');
  if (ct) Interceptor.attach(ct, {
    onEnter: function (args) {
      this.setup = args[1]; this.buf = args[2]; this.len = args[3].toUInt32();
      let s = ''; try { s = hexAt(this.setup, 8, 16); } catch (e) {}
      emit({ api: 'WinUsb_ControlTransfer', dir: 'in', setup: s, len: this.len,
             dataHex: hexAt(this.buf, this.len, HEX_CAP_VENDOR) });
    },
    onLeave: function (ret) {
      emit({ api: 'WinUsb_ControlTransfer', dir: 'out', ret: ret.toInt32(),
             dataHex: hexAt(this.buf, this.len, HEX_CAP_VENDOR) });
    }
  });
  ['WinUsb_WritePipe', 'WinUsb_ReadPipe'].forEach(function (name) {
    const p = findExport('winusb.dll', name);
    if (!p) return;
    const isWrite = name.endsWith('WritePipe');
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.pipe = args[1].toUInt32() & 0xff; this.buf = args[2]; this.len = args[3].toUInt32();
        if (isWrite) emit({ api: name, dir: 'in', pipe: '0x' + this.pipe.toString(16),
                            len: this.len, hex: hexAt(this.buf, this.len, HEX_CAP_VENDOR) });
      },
      onLeave: function (ret) {
        if (!isWrite) emit({ api: name, dir: 'out', pipe: '0x' + this.pipe.toString(16),
                             ret: ret.toInt32(), hex: hexAt(this.buf, this.len, HEX_CAP_VENDOR) });
      }
    });
  });
  emit({ api: 'WINUSB_HOOKED' });
  return true;
}
if (!hookWinUsb()) {
  const ll = findExport('kernel32.dll', 'LoadLibraryW');
  if (ll) Interceptor.attach(ll, { onLeave: function () { hookWinUsb(); } });
}

// ── 4. network (local-vs-cloud corroboration) ────────────────────────────────
[['wininet.dll', 'InternetConnectA'], ['wininet.dll', 'HttpOpenRequestA'],
 ['winhttp.dll', 'WinHttpConnect'], ['ws2_32.dll', 'connect']].forEach(function (pair) {
  const p = findExport(pair[0], pair[1]);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) {
      let host = '';
      try { if (pair[1] === 'InternetConnectA') host = args[1].readAnsiString(); } catch (e) {}
      emit({ api: pair[1], lib: pair[0], host: host });
    }
  });
});
