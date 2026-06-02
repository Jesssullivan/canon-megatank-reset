'use strict';
/*
 * appbin-dump.js - Lane B in-memory cleartext dump for printerpotty.exe (WICReset).
 *
 * printerpotty.exe decrypts + mounts its embedded APP.BIN resource tree at startup,
 * BEFORE any printer/key/cloud interaction. This script hooks the decrypt/mount/
 * inflate path and the dotted-path accessor and dumps the CLEARTEXT bytes straight
 * out of process memory - NO key, NO device, NO cloud.
 *
 * frida-inject has no host process to receive send(), so every dump is emitted as
 * framed base64 lines on console.log (captured by the injector's redirected stdout).
 * The host reassembler (scripts) globs the markers back into binary artifacts.
 *
 * Target VAs (default imagebase 0x00400000; runtime base computed below):
 *   FUN_00530ae0  decrypt/mount entry        (orchestrator)
 *   FUN_004d2a10  header/footer strip        (dump OUTPUT buffer = stripped cleartext)
 *   FUN_004d2510  buffer-append / resource copy (dst,src,len  -> the assembled tree)
 *   FUN_00794130  inflate                    (dump z_stream OUTPUT = decompressed tree)
 *   FUN_00522ac0  dotted-path accessor       (key in, node value out)
 *
 * Frida 17 API. Robust against ASLR: never hardcode runtime addresses.
 */

var IMAGEBASE = ptr('0x400000');
var TARGET = 'printerpotty.exe';

/* -- module/base resolution ------------------------------------------------- */
function mainModule() {
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      if (mods[i].name && mods[i].name.toLowerCase() === TARGET) return mods[i];
    }
    // fallback: first module is the main image on Windows
    if (mods.length) return mods[0];
  } catch (e) {}
  return null;
}
var MOD = mainModule();
var BASE = MOD ? MOD.base : ptr(0);

function va(addr) {
  // addr is a number/string VA at default imagebase; rebase to runtime.
  var off = ptr(addr).sub(IMAGEBASE);
  return BASE.add(off);
}

/* -- logging ------------------------------------------------------------------
 * frida-inject stdout is buffered and unreliable when the injector is killed, and
 * a session-0 vs session-1 mismatch can swallow it entirely. So we ALSO persist
 * every event line to a guest file via Frida's File API (authoritative artifact),
 * and write raw dumped bytes to per-id .bin files directly - no host reassembly,
 * no base64, no stdout dependency.
 */
var EVT_PATH = 'C:\\canon\\appbin-events.log';
var BIN_DIR  = 'C:\\canon\\appbin-out\\';
var evtFile = null;
try { evtFile = new File(EVT_PATH, 'wb'); } catch (e) { evtFile = null; }
function fwrite(f, s) { try { if (f) { f.write(s); f.flush(); } } catch (e) {} }

var T0 = Date.now();
function log(o) {
  o.t = Date.now() - T0;
  var line = 'PPDUMP ' + JSON.stringify(o) + '\n';
  console.log(line.slice(0, -1));
  fwrite(evtFile, line);
}

// Write a raw memory region straight to a .bin file in the guest (the cleartext).
function writeBin(tag, ptrBuf, len) {
  if (ptrBuf.isNull() || len <= 0) return null;
  if (len > DUMP_CAP) len = DUMP_CAP;
  var safe = tag.replace(/[^A-Za-z0-9_.+-]/g, '_');
  var path = BIN_DIR + 'dump_' + (binSeq++) + '_' + safe + '.bin';
  try {
    var f = new File(path, 'wb');
    var done = 0;
    while (done < len) {
      var n = Math.min(65536, len - done);
      var ba = ptrBuf.add(done).readByteArray(n);
      f.write(ba);
      done += n;
    }
    f.flush(); f.close();
    log({ ev: 'WROTE_BIN', tag: tag, path: path, bytes: done, addr: ptrBuf.toString() });
    return path;
  } catch (e) {
    log({ ev: 'WRITE_BIN_ERR', tag: tag, err: '' + e });
    return null;
  }
}
var binSeq = 0;

/* base64 without relying on btoa availability (qjs/v8 differ) */
var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64(u8) {
  var s = '', i;
  for (i = 0; i + 2 < u8.length; i += 3) {
    var n = (u8[i] << 16) | (u8[i + 1] << 8) | u8[i + 2];
    s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  var rem = u8.length - i;
  if (rem === 1) {
    var n1 = u8[i] << 16;
    s += B64[(n1 >> 18) & 63] + B64[(n1 >> 12) & 63] + '==';
  } else if (rem === 2) {
    var n2 = (u8[i] << 16) | (u8[i + 1] << 8);
    s += B64[(n2 >> 18) & 63] + B64[(n2 >> 12) & 63] + B64[(n2 >> 6) & 63] + '=';
  }
  return s;
}

var CHUNK = 240; // bytes/line (-> ~320 b64 chars; safe for stdout line buffering)
var dumpSeq = 0;
var DUMP_CAP = 8 * 1024 * 1024; // never exfil more than 8 MB per buffer

// Dump a memory region. Primary path: write raw bytes to a guest .bin file via the
// File API (robust). Secondary: a short framed-base64 echo on stdout for live
// visibility (capped low so it never floods the log).
function dumpMem(tag, ptrBuf, len) {
  if (ptrBuf.isNull() || len <= 0) return;
  if (len > DUMP_CAP) len = DUMP_CAP;
  var id = (dumpSeq++);
  var sane = sniff(ptrBuf, len);
  log({ ev: 'DUMP_BEGIN', tag: tag, id: id, addr: ptrBuf.toString(), len: len, sniff: sane });
  // authoritative: raw bytes -> file
  writeBin(tag, ptrBuf, len);
  // secondary: echo only the first 4 KB as base64 to stdout for a quick live peek
  var echo = Math.min(len, 4096);
  var done = 0;
  while (done < echo) {
    var n = Math.min(CHUNK, echo - done);
    var bytes;
    try { bytes = new Uint8Array(ptrBuf.add(done).readByteArray(n)); }
    catch (e) { break; }
    console.log('PPD ' + id + ' ' + done + ' ' + b64(bytes));
    done += n;
  }
  log({ ev: 'DUMP_END', tag: tag, id: id, echoed: done, total: len });
}

// quick ASCII sniff so the log is human-skimmable for the G6020/key markers
function sniff(p, len) {
  try {
    var n = Math.min(len, 64);
    var u8 = new Uint8Array(p.readByteArray(n));
    var s = '';
    for (var i = 0; i < u8.length; i++) {
      var c = u8[i];
      s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
    }
    return s;
  } catch (e) { return '<unreadable>'; }
}

// Scan a buffer for our keyword markers and report any hits (so we don't have to
// reassemble offline just to know if we hit gold).
var MARKERS = ['G6020', 'G6000', 'default/userdata', 'command.codes', 'command.index',
  'keyword.index', 'keyword.codes', 'functions.waste', 'functor', 'userdata',
  'waste', 'command.shift', 'shift'];
function scanMarkers(tag, p, len) {
  try {
    var cap = Math.min(len, 2 * 1024 * 1024);
    var u8 = new Uint8Array(p.readByteArray(cap));
    var text = '';
    for (var i = 0; i < u8.length; i++) {
      var c = u8[i];
      text += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : ' ';
    }
    var hits = [];
    for (var m = 0; m < MARKERS.length; m++) {
      var idx = text.indexOf(MARKERS[m]);
      if (idx >= 0) hits.push({ k: MARKERS[m], at: idx, ctx: text.substr(idx, 48).replace(/ /g, '.') });
    }
    if (hits.length) log({ ev: 'MARKER_HIT', tag: tag, addr: p.toString(), len: len, hits: hits });
  } catch (e) {}
}

/* -- boot banner ------------------------------------------------------------ */
log({
  ev: 'HOOK_LOADED', mod: MOD ? MOD.name : '<none>',
  base: BASE.toString(), imagebase: IMAGEBASE.toString(),
  rebased: MOD ? (BASE.compare(IMAGEBASE) !== 0) : false,
  fridaVer: (typeof Frida !== 'undefined' && Frida.version) ? Frida.version : '?'
});

if (!MOD) {
  log({ ev: 'FATAL', note: 'could not resolve printerpotty.exe module' });
} else {

  /* -- inflate FUN_00794130 - THE GOLD: decompressed cleartext output -------
   * Calling convention unknown precisely; from the prologue (push ebp; mov ebp,esp;
   * mov edx,[ebp+8]) the first stack arg is at [ebp+8]. Many inflate-wrappers take
   * (z_streamp strm) or (src,srclen,dst,dstcap,*outlen). We capture the args on
   * enter, then on leave dump whatever output buffer we can identify:
   *   - if arg0 looks like a z_stream (has next_out/avail_out fields), dump the
   *     produced output window.
   *   - else treat args as (src,srclen,dst,dstcap[,*outlen]) and dump dst..outlen.
   * We also stash dst/cap so onLeave can read the post-inflate length.
   */
  (function () {
    var p = va(0x00794130);
    Interceptor.attach(p, {
      onEnter: function (args) {
        // capture up to 6 potential 32-bit stack args (cdecl/x86: args[0..])
        this.a = [];
        for (var i = 0; i < 6; i++) {
          try { this.a.push(args[i]); } catch (e) { this.a.push(ptr(0)); }
        }
        // Snapshot next_out BEFORE the call so onLeave dumps EXACTLY the bytes
        // produced this call: [pre_next_out, post_next_out).
        this.preNextOut = ptr(0);
        try { var s = this.a[0]; if (!s.isNull()) this.preNextOut = s.add(12).readPointer(); } catch (e) {}
      },
      onLeave: function (ret) {
        var a = this.a;
        // Heuristic A: zlib z_stream*. struct z_stream layout (x86):
        //   +0  next_in   +4 avail_in  +8 total_in
        //   +12 next_out  +16 avail_out +20 total_out  ...
        try {
          var strm = a[0];
          if (!strm.isNull()) {
            var next_out = strm.add(12).readPointer();
            var total_out = strm.add(20).readU32();
            // produced THIS call = post_next_out - pre_next_out (the fresh cleartext)
            if (!this.preNextOut.isNull() && !next_out.isNull() && next_out.compare(this.preNextOut) > 0) {
              var produced = next_out.sub(this.preNextOut).toInt32();
              if (produced > 0 && produced < DUMP_CAP) {
                scanMarkers('inflate.produced', this.preNextOut, produced);
                dumpMem('inflate.produced', this.preNextOut, produced);
                return;
              }
            }
            if (total_out > 0 && total_out < DUMP_CAP && !next_out.isNull()) {
              var outStart = next_out.sub(total_out);
              scanMarkers('inflate.zstream', outStart, total_out);
              dumpMem('inflate.zstream.out', outStart, total_out);
              return;
            }
          }
        } catch (e) {}
        // Heuristic B: (src, srclen, dst, dstcap, *outlen). Dump dst.
        try {
          var dst = a[2];
          var dstcap = a[3].toUInt32();
          var outlen = dstcap;
          if (!a[4].isNull()) { try { outlen = a[4].readU32(); } catch (e) {} }
          if (!dst.isNull() && outlen > 0 && outlen < DUMP_CAP) {
            scanMarkers('inflate.dst', dst, outlen);
            dumpMem('inflate.dst', dst, outlen);
            return;
          }
        } catch (e) {}
        // Heuristic C: return value is the dst pointer or produced length.
        try {
          if (!ret.isNull()) {
            // peek: if ret points to readable memory, sniff it
            var sn = sniff(ret, 32);
            log({ ev: 'inflate.ret', ret: ret.toString(), sniff: sn });
          }
        } catch (e) {}
      }
    });
    log({ ev: 'HOOKED', fn: 'inflate FUN_00794130', at: p.toString() });
  })();

  /* -- FUN_004d2a10 - header/footer strip. Dump its OUTPUT (the stripped tree). --
   * Prologue is a wxString/wxMemoryBuffer-style method (mov ecx-thiscall likely).
   * x86 thiscall: this=ecx (not in args[]); explicit args start at args[0].
   * We capture this(ecx) via the CpuContext on enter, and on leave inspect the
   * returned object + the explicit dst arg for the stripped cleartext.
   */
  (function () {
    var p = va(0x004d2a10);
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.ecx = this.context.ecx;     // thiscall `this` (wx buffer/string)
        this.a0 = args[0];
        this.a1 = args[1];
      },
      onLeave: function (ret) {
        // wxString/wxMemoryBuffer commonly carry {ptr,len} or a heap-data pointer.
        // Try the return value as a struct {data*, len} and as a direct buffer.
        probeWxBuffer('strip.ret', ret);
        probeWxBuffer('strip.this', this.ecx);
        probeWxBuffer('strip.a0', this.a0);
      }
    });
    log({ ev: 'HOOKED', fn: 'strip FUN_004d2a10', at: p.toString() });
  })();

  /* -- FUN_004d2510(dst, src, len) - buffer append / resource copy. ----------
   * Decompiled signature from static RE: FUN_004d2510(dst_buf, src, len). src..len
   * is a slice of cleartext being assembled into the tree. Dump src for len bytes.
   */
  (function () {
    var p = va(0x004d2510);
    Interceptor.attach(p, {
      onEnter: function (args) {
        try {
          var src = args[1];
          var len = args[2].toUInt32();
          if (!src.isNull() && len > 0 && len < DUMP_CAP) {
            // Only dump sizeable / interesting slices to keep the log sane.
            scanMarkers('copy.src', src, len);
            if (len >= 8) dumpMem('copy.src', src, len);
          }
        } catch (e) {}
      }
    });
    log({ ev: 'HOOKED', fn: 'copy FUN_004d2510', at: p.toString() });
  })();

  /* -- FUN_00522ac0 - dotted-path accessor. key in, node value out. ----------
   * Hook it; when the key contains a marker (default/userdata, command.codes, -),
   * dump the key and the returned value node. thiscall `this`=ecx; key likely a
   * wxString pointer in args[0] or args[1].
   */
  (function () {
    var p = va(0x00522ac0);
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.ecx = this.context.ecx;
        this.keyStr = readAnyString(args[0]) || readAnyString(args[1]) || readAnyString(this.ecx);
        this.a0 = args[0]; this.a1 = args[1];
        if (this.keyStr) {
          var interesting = MARKERS.some(function (m) { return this.keyStr.indexOf(m) >= 0; }, this);
          this.interesting = interesting || this.keyStr.indexOf('.') >= 0 || this.keyStr.indexOf('/') >= 0;
        }
      },
      onLeave: function (ret) {
        if (!this.keyStr) return;
        if (!this.interesting) return;
        log({ ev: 'ACCESS', key: this.keyStr, ret: ret.toString(), retSniff: sniff(ret, 48) });
        probeWxBuffer('access.ret[' + this.keyStr + ']', ret);
        // Also: dump a bounded blob from the returned node + one deref, so the
        // resident tree node bytes (model list, command template) land on disk for
        // offline parsing even if it is not a plain char buffer.
        if (!ret.isNull() && isReadable(ret)) {
          var safeKey = this.keyStr.replace(/[^A-Za-z0-9_.+-]/g, '_');
          dumpMem('node[' + safeKey + ']', ret, 4096);
          try {
            var inner = ret.readPointer();
            if (!inner.isNull() && isReadable(inner)) dumpMem('node1[' + safeKey + ']', inner, 4096);
          } catch (e) {}
        }
      }
    });
    log({ ev: 'HOOKED', fn: 'accessor FUN_00522ac0', at: p.toString() });
  })();

  /* -- FUN_00530ae0 - decrypt/mount orchestrator. Just trace entry/leave + probe
   * the returned object for the mounted tree root. */
  (function () {
    var p = va(0x00530ae0);
    Interceptor.attach(p, {
      onEnter: function () { this.ecx = this.context.ecx; log({ ev: 'MOUNT_ENTER', this: this.ecx.toString() }); },
      onLeave: function (ret) {
        log({ ev: 'MOUNT_LEAVE', ret: ret.toString(), retSniff: sniff(ret, 48) });
        probeWxBuffer('mount.ret', ret);
        probeWxBuffer('mount.this', this.ecx);
      }
    });
    log({ ev: 'HOOKED', fn: 'mount FUN_00530ae0', at: p.toString() });
  })();
}

/* -- helpers: wx buffer/string probing + flexible string reads -------------- */

// Try to interpret p as a wx-style {data_ptr, length} struct (several layouts),
// and/or as a direct char buffer; dump whatever yields a plausible cleartext run.
function probeWxBuffer(tag, p) {
  if (!p || p.isNull()) return;
  // Layout 1: p -> {char* data; size_t len; ...} (wxMemoryBuffer-ish)
  for (var off = 0; off <= 8; off += 4) {
    try {
      var data = p.add(off).readPointer();
      var len = p.add(off + 4).readU32();
      if (!data.isNull() && len > 4 && len < DUMP_CAP && isReadable(data)) {
        var sn = sniff(data, 48);
        if (looksTexty(sn)) {
          scanMarkers(tag + '.struct+' + off, data, len);
          dumpMem(tag + '.struct+' + off, data, len);
          return;
        }
      }
    } catch (e) {}
  }
  // Layout 2: p is itself a char* (NUL-terminated or wx ref-counted string body)
  try {
    if (isReadable(p)) {
      var s = readAnyString(p);
      if (s && s.length > 3) {
        log({ ev: 'STR', tag: tag, addr: p.toString(), str: s.substr(0, 256) });
        // also try to dump a bounded blob from here in case it's a tree
        var blobLen = strlenBounded(p, 64 * 1024);
        if (blobLen > 16) { scanMarkers(tag + '.cstr', p, blobLen); }
      }
    }
  } catch (e) {}
}

function isReadable(p) {
  try { p.readU8(); return true; } catch (e) { return false; }
}
function looksTexty(s) {
  if (!s) return false;
  var printable = 0;
  for (var i = 0; i < s.length; i++) if (s[i] !== '.') printable++;
  return printable >= s.length * 0.4;
}
function strlenBounded(p, cap) {
  var n = 0;
  try { while (n < cap && p.add(n).readU8() !== 0) n++; } catch (e) {}
  return n;
}
// Read utf8 OR utf16 OR a wxString (pointer-to-pointer) - best effort.
function readAnyString(p) {
  if (!p || p.isNull()) return null;
  try {
    // direct utf8
    var s = p.readUtf8String();
    if (s && /^[\x20-\x7e\/\.\-_]+$/.test(s) && s.length >= 2) return s;
  } catch (e) {}
  try {
    var s2 = p.readUtf16String();
    if (s2 && /^[\x20-\x7e\/\.\-_]+$/.test(s2) && s2.length >= 2) return s2;
  } catch (e) {}
  try {
    // wxString often: p -> body* -> chars. deref once.
    var body = p.readPointer();
    if (!body.isNull()) {
      var s3 = body.readUtf8String();
      if (s3 && /^[\x20-\x7e\/\.\-_]+$/.test(s3) && s3.length >= 2) return s3;
    }
  } catch (e) {}
  return null;
}
