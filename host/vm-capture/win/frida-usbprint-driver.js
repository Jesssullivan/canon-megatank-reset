'use strict';
/*
 * frida-usbprint-driver.js — drive OUR derived functor-3 frames straight through
 * usbprint.sys's VENDOR_SET/GET IOCTLs, bypassing WICReset's cloud licensing DRM
 * entirely. usbprint.sys is just a transport (no DRM); we open the
 * GUID_DEVINTERFACE_USBPRINT handle ourselves and issue DeviceIoControl. The host
 * usbmon capture records the exact URB so the native Linux tool can replicate it.
 *
 * x86 (32-bit) — load under frida-inject-x86-16.exe -f SysWOW64\cmd.exe.
 * Phase 1: set_session (0x220038) -> get_keyword (0x22003c) -> read the live keyword.
 *   (NON-DESTRUCTIVE: opening a session + reading the keyword do not clear anything.)
 */
const PATH = "\\\\?\\usb#vid_04a9&pid_12fe#01807c#{28d78fad-5a12-11d1-ae5b-0000f803a8c2}";

function fn(name, ret, args) {
  const p = Module.findExportByName('kernel32.dll', name);
  return new NativeFunction(p, ret, args);
}
const CreateFileW    = fn('CreateFileW', 'pointer', ['pointer','uint32','uint32','pointer','uint32','uint32','pointer']);
const DeviceIoControl= fn('DeviceIoControl', 'int', ['pointer','uint32','pointer','uint32','pointer','uint32','pointer','pointer']);
const GetLastError   = fn('GetLastError', 'uint32', []);
const CloseHandle    = fn('CloseHandle', 'int', ['pointer']);
const ExitProcess    = fn('ExitProcess', 'void', ['uint32']);

const GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
const FILE_SHARE_RW = 3, OPEN_EXISTING = 3;
const INVALID = ptr('-1');

function buf(bytes) { const m = Memory.alloc(bytes.length || 1); for (let i=0;i<bytes.length;i++) m.add(i).writeU8(bytes[i]); return m; }
function tohex(p, n) { let s=''; for (let i=0;i<n;i++){ const b=p.add(i).readU8(); s+=(b<16?'0':'')+b.toString(16);} return s; }

const pathPtr = Memory.allocUtf16String(PATH);
const h = CreateFileW(pathPtr, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_RW, NULL, OPEN_EXISTING, 0, NULL);
console.log('OPEN handle=' + h + ' gle=' + GetLastError());

if (h.equals(INVALID) || h.isNull()) {
  console.log('RESULT OPEN_FAILED');
  ExitProcess(1);
} else {
  const br = Memory.alloc(4);
  const out = Memory.alloc(4096);
  function ioctl(code, inBytes, outLen, label) {
    const inBuf = buf(inBytes);
    br.writeU32(0);
    for (let i=0;i<outLen && i<4096;i++) out.add(i).writeU8(0);
    const ok = DeviceIoControl(h, code, inBuf, inBytes.length, out, outLen, br, NULL);
    const n = br.readU32();
    console.log(label + ' ok=' + ok + ' gle=' + (ok ? 0 : GetLastError()) +
                ' bytesReturned=' + n + ' out=' + tohex(out, Math.min(n, 64)));
  }
  // 1) set_session (0x220038) — enciphered set_session frame (default keyword)
  ioctl(0x220038, [0x81,0x00,0x00,0x03,0x2d,0x2d,0xba,0x2b], 256, 'SET_SESSION[0x220038 81000003.2d2dba2b]');
  // 2) get_keyword (0x22003c) — 3-byte prime, like get_version (0x8a 00 00)
  ioctl(0x22003c, [0x82,0x00,0x00], 4096, 'GET_KEYWORD[0x22003c 820000]');
  // 3) get_keyword (0x22003c) — full enciphered get_keyword frame variant
  ioctl(0x22003c, [0x82,0x00,0x00,0x00,0x00,0x40,0x40,0x8f,0xec], 4096, 'GET_KEYWORD[0x22003c enc9]');
  // 4) get_version (0x22003c 8a0000) — handle-health sanity (must be e790...)
  ioctl(0x22003c, [0x8a,0x00,0x00], 4096, 'GET_VERSION[0x22003c 8a0000]');
  CloseHandle(h);
  console.log('RESULT DONE');
  ExitProcess(0);
}
