/*
 * frida-1284clamp-hook.js — Lane A fix for the WICReset G6020 1284-ID gate.
 *
 * ROOT CAUSE (proven live): IOCTL 0x220034 (IOCTL_USBPRINT_GET_1284_ID) is
 * serviced by usbprint.sys. usbprint.sys on Win11 26100.8328 caps the GET_1284_ID
 * output buffer at exactly 4096 bytes (one page). WICReset's deep read
 * (USBPipe::do_read_1284ID) requests 5000 bytes -> usbprint.sys returns
 * ok=FALSE, bytesReturned=0, err=23 (ERROR_CRC). The discovery path (Site B)
 * uses 4096 and SUCCEEDS, which is why the printer still ENUMERATES/DETECTS.
 *
 * FIX: clamp nOutBufferSize (args[5]) of DeviceIoControl for ioctl 0x220034 down
 * to 4096 so usbprint.sys returns the 120-byte 1284 ID. The device/driver are
 * unchanged (still usbprint.sys, still printer-class enumeration). Purely an
 * app->kernel argument fix; no driver bind, no key.
 */
'use strict';
const CLAMP = 4096;
const IOCTL_GET_1284 = 0x220034;
const T0 = Date.now();
function emit(o){ o.t = Date.now()-T0; try{ console.log(JSON.stringify(o)); }catch(e){} }
function hexAt(p,len){ if(p.isNull()||len<=0) return ''; const cap=Math.min(len,256);
  try{ const u8=new Uint8Array(p.readByteArray(cap)); let s=''; for(let i=0;i<u8.length;i++) s+=(u8[i]<16?'0':'')+u8[i].toString(16); return s+(len>cap?'..('+len+'B)':''); }catch(e){ return '<unreadable>'; } }
function findExport(lib,sym){
  try{ if(Module.getGlobalExportByName) return Module.getGlobalExportByName(sym); }catch(e){}
  try{ if(Module.findExportByName) return Module.findExportByName(lib,sym); }catch(e){}
  return null;
}
emit({api:'CLAMP_HOOK_LOADED', clamp:CLAMP, ioctl:'0x220034'});
(function(){
  const p = findExport('kernel32.dll','DeviceIoControl');
  if(!p){ emit({api:'WARN', note:'DeviceIoControl not found'}); return; }
  Interceptor.attach(p, {
    onEnter:function(args){
      this.ioctl = args[1].toUInt32();
      this.outBuf = args[4];
      this.outSize = args[5].toUInt32();
      this.bytesRet = args[6];
      if(this.ioctl === IOCTL_GET_1284 && this.outSize > CLAMP){
        emit({api:'CLAMP', ioctl:'0x220034', origOutSize:this.outSize, newOutSize:CLAMP});
        args[5] = ptr(CLAMP);          // overwrite nOutBufferSize -> 4096
        this.clamped = true;
        this.outSize = CLAMP;
      }
      if(this.ioctl === IOCTL_GET_1284)
        emit({api:'DeviceIoControl', dir:'in', ioctl:'0x220034', outSize:this.outSize, clamped:!!this.clamped});
    },
    onLeave:function(ret){
      if(this.ioctl !== IOCTL_GET_1284) return;
      let n = this.outSize;
      try{ if(!this.bytesRet.isNull()) n = this.bytesRet.readU32(); }catch(e){}
      emit({api:'DeviceIoControl', dir:'out', ioctl:'0x220034', ret:ret.toInt32(),
            bytesReturned:n, clamped:!!this.clamped, outHex:hexAt(this.outBuf,n)});
    }
  });
})();
