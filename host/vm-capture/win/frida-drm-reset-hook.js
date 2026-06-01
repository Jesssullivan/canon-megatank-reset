'use strict';
/*
 * frida-drm-reset-hook.js — clear the G6020 5B00 via WICReset's OWN genuine reset,
 * by forcing its three cloud licensing-DRM gates true so clearCounters() (net-free)
 * runs and emits real set_session/get_keyword/set_command frames. usbmon + this
 * hook capture the ground-truth frames.
 *
 * DRM gates (printerpotty.exe, image base 0x400000, ASLR on -> runtime VA via slide),
 * verified byte-exact (sha256 a199447db…564b3e8) + adversarially confirmed:
 *   0x44012d  74 49 -> EB 49   RESET_GUID  cloud gate (UPSTREAM — the real stall)
 *   0x44054a  74 10 -> EB 10   QUERY_KEYS  transport-success gate
 *   0x440563  74 63 -> EB 63   valid-bit / local_2d9 gate
 * Each JZ(0x74)->JMP(0xEB) keeps the rel8 displacement (target unchanged). A 0x74
 * guard aborts loudly if the binary version drifts (offsets exact for this sha256).
 *
 * Plus the proven usbprint page-cap clamps (0x220034 + 0x22003c nOutBufferSize
 * 5000->4096) so the 1284-ID / series-name reads pass, and a full VENDOR IOCTL
 * trace (0x220038 SET in-buffers = the reset frames; 0x22003c GET out-buffer =
 * the 3-byte device keyword).
 *
 * Launch (interactive, schtasks /ru cap /it, .cmd wrapper redirecting stdout):
 *   frida-inject-x86-16.exe -f "C:\PROGRA~2\PRINTE~1\PRINTE~1.EXE"
 *       -s C:\canon\frida-drm-reset-hook.js -R v8 > C:\canon\drm-reset.log 2>&1
 */

const IMAGE_BASE = ptr('0x400000');
const PATCHES = [
  { va: '0x44012d', name: 'RESET_GUID-gate' },
  { va: '0x44054a', name: 'QUERY_KEYS-gate' },
  { va: '0x440563', name: 'valid-bit-gate' },
];

function mainExe() {
  // the main executable module (the one whose path ends in .exe, not a DLL)
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
      const n = (mods[i].name || '').toLowerCase();
      if (n.endsWith('.exe')) return mods[i];
    }
    return mods[0];
  } catch (e) { return null; }
}

function applyPatches() {
  const m = mainExe();
  if (!m) { console.log('[DRM] no main module'); return; }
  const slide = m.base.sub(IMAGE_BASE);
  console.log('[DRM] module=' + m.name + ' base=' + m.base + ' slide=' + slide);
  PATCHES.forEach(function (p) {
    try {
      const at = ptr(p.va).add(slide);
      const cur = at.readU8();
      if (cur !== 0x74) {
        console.log('[DRM] SKIP ' + p.name + ' @' + p.va + ' (slid ' + at + ') = 0x' +
                    cur.toString(16) + ' != 0x74 — version drift, not patching');
        return;
      }
      Memory.patchCode(at, 1, function (code) { code.writeU8(0xEB); });
      console.log('[DRM] PATCHED ' + p.name + ' @' + p.va + ' (slid ' + at + ') 0x74->0xEB');
    } catch (e) { console.log('[DRM] ERR ' + p.name + ': ' + e); }
  });
}

// ── usbprint IOCTL clamp + VENDOR frame trace ───────────────────────────────
const CLAMP = 4096;
const IOCTL_GET_1284 = 0x220034, IOCTL_VENDOR_GET = 0x22003c, IOCTL_VENDOR_SET = 0x220038;
const VENDOR = { 0x220030:'GET_LPT_STATUS',0x220034:'GET_1284_ID',0x220038:'VENDOR_SET',0x22003c:'VENDOR_GET' };
const T0 = Date.now();
function ts() { return ((Date.now() - T0) / 1000).toFixed(3); }
function hx(p, n) { if (p.isNull() || n <= 0) return ''; const c = Math.min(n, 1024);
  try { const u = new Uint8Array(p.readByteArray(c)); let s=''; for (let i=0;i<u.length;i++) s+=(u[i]<16?'0':'')+u[i].toString(16); return s + (n>c?'..('+n+')':''); } catch(e){ return '<err>'; } }

function hookDeviceIoControl() {
  const p = Module.findExportByName('kernel32.dll', 'DeviceIoControl');
  if (!p) { console.log('[IOCTL] DeviceIoControl not found'); return; }
  Interceptor.attach(p, {
    onEnter: function (a) {
      this.ioctl = a[1].toUInt32(); this.inBuf = a[2]; this.inSize = a[3].toUInt32();
      this.outBuf = a[4]; this.outSize = a[5].toUInt32(); this.br = a[6];
      this.vendor = (this.ioctl in VENDOR);
      if ((this.ioctl === IOCTL_GET_1284 || this.ioctl === IOCTL_VENDOR_GET) && this.outSize > CLAMP) {
        a[5] = ptr(CLAMP); this.outSize = CLAMP; this.clamped = true;
      }
      if (this.vendor)
        console.log('[IOCTL ' + ts() + '] ' + (VENDOR[this.ioctl]) + ' in ioctl=0x' +
                    this.ioctl.toString(16) + ' inSize=' + this.inSize + ' inHex=' + hx(this.inBuf, this.inSize) +
                    (this.clamped ? ' (clamped)' : ''));
    },
    onLeave: function (ret) {
      if (!this.vendor) return;
      let n = this.outSize; try { if (!this.br.isNull()) n = this.br.readU32(); } catch (e) {}
      console.log('[IOCTL ' + ts() + '] ' + (VENDOR[this.ioctl]) + ' out ret=' + ret.toInt32() +
                  ' bytesRet=' + n + ' outHex=' + hx(this.outBuf, n));
    }
  });
  console.log('[IOCTL] DeviceIoControl hooked');
}

// ── network connect trace (to confirm the gates skip the cloud) ─────────────
['connect'].forEach(function (nm) {
  const p = Module.findExportByName('ws2_32.dll', nm);
  if (p) Interceptor.attach(p, { onEnter: function () { console.log('[NET ' + ts() + '] ws2_32!connect called'); } });
});

// ── fast-path: kill connect() so the cloud RPCs (RESET_GUID/QUERY_KEYS) fail
// INSTANTLY instead of blocking ~5min/call on a recv-timeout. The reset subtree
// (clearCounters) is net-free, so this only short-circuits the cloud waits; the
// three JZ->JMP gate patches then carry execution straight into the reset emit.
function killConnects() {
  try {
    const c = Module.findExportByName('ws2_32.dll', 'connect');
    if (!c) { console.log('[NET] connect not found'); return; }
    const sle = Module.findExportByName('ws2_32.dll', 'WSASetLastError');
    const SLE = sle ? new NativeFunction(sle, 'void', ['int'], 'stdcall') : null;
    Interceptor.replace(c, new NativeCallback(function (s, name, namelen) {
      if (SLE) SLE(10061); // WSAECONNREFUSED — hard, fast failure (no select wait)
      return -1;           // SOCKET_ERROR
    }, 'int', ['uint', 'pointer', 'int'], 'stdcall'));
    console.log('[NET] connect() replaced -> instant fail (cloud fast-fails; reset is net-free)');
  } catch (e) { console.log('[NET] connect replace err: ' + e); }
}

console.log('[HOOK] frida-drm-reset-hook loaded t0=' + T0);
applyPatches();
killConnects();
hookDeviceIoControl();
