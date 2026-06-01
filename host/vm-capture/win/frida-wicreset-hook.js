/*
 * frida-wicreset-hook.js — application-layer capture of the Canon G6020 waste-ink
 * reset as driven by WICReset (PrinterPotty) in the Win11 capture VM.
 *
 * WHY: our static RE proves these tools build only a 3-byte app header
 * [cmd][arg_hi][arg_lo](+payload) and hand it to a kernel minidriver via
 * CreateFile + DeviceIoControl (usbscan 0x220038/0x22003c; service-mode usbprint
 * 0x16-family 0x16000c) — they never assemble a USB setup packet, so the
 * bulk/control pipe choice and several literal bytes are runtime-sourced and
 * invisible to static analysis. A *different* build may instead talk WinUSB
 * directly. This hook intercepts BOTH families so whichever the binary uses is
 * captured: the exact command frame + the runtime-sourced bytes that the wire
 * pcap shows only as opaque payload.
 *
 * Pairs with: host usbmon pcap (wire ground truth) + a wall-clock anchor logged
 * here so the Frida event stream and the pcap correlate to the exact transfer
 * that precedes the EEPROM commit + power-cycle.
 *
 * Output: structured lines to stdout (frida-trace / frida -l redirects to a file).
 * Each line is JSON: {"t":<ms>,"api":...,"dir":"in|out",...,"hex":...}.
 *
 * Usage (guest, no Python needed — standalone frida.exe):
 *   frida.exe -f "C:\\Program Files (x86)\\Printer Potty WICReset\\...exe" -l frida-wicreset-hook.js -o C:\\canon\\frida-events.log
 *   (or attach: frida.exe -n <wicreset.exe> -l frida-wicreset-hook.js -o ...)
 */

'use strict';

// ── Frida-version compat shims ──────────────────────────────────────────────
// Frida 17 removed Module.findExportByName / Process.findModuleByName (the old
// flat statics). Provide forward+backward-compatible helpers.
function findExport(libName, symName) {
  // v17: Module.getGlobalExportByName(name) searches all modules; or per-module.
  try {
    if (libName) {
      var m = Process.getModuleByName ? Process.getModuleByName(libName)
            : (Module.load ? null : null);
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

// hi-res-ish timestamp (ms since script load). Date.now() is fine for ordering;
// the host logs an absolute wall-clock anchor at reset-click for pcap correlation.
const T0 = Date.now();
function now() { return Date.now() - T0; }

function emit(obj) {
  obj.t = now();
  try { send(obj); } catch (e) {}            // to the frida host if -o not used
  console.log(JSON.stringify(obj));          // captured by -o file
}

// hex-dump a NativePointer for `len` bytes, capped so we never dump megabytes
function hexAt(ptr, len) {
  if (ptr.isNull() || len <= 0) return '';
  const cap = Math.min(len, 512);
  try { return hexdumpCompact(ptr.readByteArray(cap)) + (len > cap ? '..(' + len + 'B)' : ''); }
  catch (e) { return '<unreadable:' + e + '>'; }
}
function hexdumpCompact(buf) {
  const u8 = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16);
  return s;
}

emit({ api: 'HOOK_LOADED', note: 'frida-wicreset-hook active', t0_epoch_ms: T0 });

// ───────────────────────────────────────────────────────────────────────────
// 1. The minidriver path: CreateFile + DeviceIoControl (our RE proves this is
//    what ServiceTool v5103 + WICReset use). DeviceIoControl carries the real
//    maintenance command/response.
// ───────────────────────────────────────────────────────────────────────────

['CreateFileW', 'CreateFileA'].forEach(function (name) {
  const p = findExport('kernel32.dll', name);
  if (!p) return;
  const wide = name.endsWith('W');
  Interceptor.attach(p, {
    onEnter: function (args) {
      try {
        const path = wide ? args[0].readUtf16String() : args[0].readAnsiString();
        // only log device-ish opens (USB / printer / usbscan), skip file noise
        if (path && /usb|\\\\\.\\|usbscan|print|\{28d78fad/i.test(path)) {
          this.path = path;
        }
      } catch (e) {}
    },
    onLeave: function (ret) {
      if (this.path) emit({ api: name, path: this.path, handle: ret.toString() });
    }
  });
});

(function () {
  const p = findExport('kernel32.dll', 'DeviceIoControl');
  if (!p) { emit({ api: 'WARN', note: 'DeviceIoControl not found' }); return; }
  // BOOL DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize,
  //                      lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)
  Interceptor.attach(p, {
    onEnter: function (args) {
      this.ioctl = args[1].toUInt32();
      this.inBuf = args[2];
      this.inSize = args[3].toUInt32();
      this.outBuf = args[4];
      this.outSize = args[5].toUInt32();
      this.bytesRet = args[6];
      // input buffer is fully populated before the call → dump in onEnter
      emit({
        api: 'DeviceIoControl', dir: 'in',
        ioctl: '0x' + this.ioctl.toString(16),
        inSize: this.inSize, outSize: this.outSize,
        inHex: hexAt(this.inBuf, this.inSize)
      });
    },
    onLeave: function (ret) {
      // output buffer filled by the kernel during the call → dump in onLeave
      let retLen = this.outSize;
      try { if (!this.bytesRet.isNull()) retLen = this.bytesRet.readU32(); } catch (e) {}
      emit({
        api: 'DeviceIoControl', dir: 'out',
        ioctl: '0x' + this.ioctl.toString(16),
        ret: ret.toInt32(), bytesReturned: retLen,
        outHex: hexAt(this.outBuf, retLen)
      });
    }
  });
})();

// ───────────────────────────────────────────────────────────────────────────
// 2. The WinUSB path: hook winusb.dll if the binary talks WinUSB directly.
//    (Loaded lazily — attach on first module load if not present at start.)
// ───────────────────────────────────────────────────────────────────────────

function hookWinUsb() {
  const mod = findModule('winusb.dll');
  if (!mod) return false;

  // WinUsb_ControlTransfer(handle, WINUSB_SETUP_PACKET setup, pBuffer, len, *transferred, *ovl)
  // The setup packet (8 bytes: bmRequestType,bRequest,wValue,wIndex,wLength) is by value
  // on the stack on x86; on x64 it is passed in registers/shadow. We read it from arg[1].
  const ct = findExport('winusb.dll', 'WinUsb_ControlTransfer');
  if (ct) Interceptor.attach(ct, {
    onEnter: function (args) {
      this.setup = args[1];     // pointer or by-value struct base
      this.buf = args[2];
      this.len = args[3].toUInt32();
      let s = '';
      try { s = hexAt(this.setup, 8); } catch (e) {}
      emit({ api: 'WinUsb_ControlTransfer', dir: 'in', setup: s,
             len: this.len, dataHex: hexAt(this.buf, this.len) });
    },
    onLeave: function (ret) {
      emit({ api: 'WinUsb_ControlTransfer', dir: 'out', ret: ret.toInt32(),
             dataHex: hexAt(this.buf, this.len) });
    }
  });

  ['WinUsb_WritePipe', 'WinUsb_ReadPipe'].forEach(function (name) {
    const p = findExport('winusb.dll', name);
    if (!p) return;
    const isWrite = name.endsWith('WritePipe');
    // WinUsb_(Read|Write)Pipe(handle, pipeID, pBuffer, len, *transferred, *ovl)
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.pipe = args[1].toUInt32() & 0xff;
        this.buf = args[2];
        this.len = args[3].toUInt32();
        if (isWrite) emit({ api: name, dir: 'in', pipe: '0x' + this.pipe.toString(16),
                            len: this.len, hex: hexAt(this.buf, this.len) });
      },
      onLeave: function (ret) {
        if (!isWrite) emit({ api: name, dir: 'out', pipe: '0x' + this.pipe.toString(16),
                             ret: ret.toInt32(), hex: hexAt(this.buf, this.len) });
      }
    });
  });

  emit({ api: 'WINUSB_HOOKED' });
  return true;
}

if (!hookWinUsb()) {
  // winusb.dll not loaded yet — catch it on load
  const ll = findExport('kernel32.dll', 'LoadLibraryW');
  if (ll) Interceptor.attach(ll, {
    onLeave: function () { hookWinUsb(); }
  });
}

// ───────────────────────────────────────────────────────────────────────────
// 3. Optional: catch the WICReset cloud call at the WinINet/WinHTTP layer so the
//    Frida log itself shows whether/when the tool phones home around the reset
//    (corroborates the guest tcpdump for the local-vs-cloud question).
// ───────────────────────────────────────────────────────────────────────────

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
