<#
  sess1-dump.ps1 -- runs INSIDE interactive session 1 (via a Scheduled Task that
  runs as the logged-on 'cap' user). Spawns printerpotty.exe in session 1, attaches
  frida-inject by pid with appbin-dump.js, holds while the APP.BIN decrypt+mount and
  the dump run, then tears down. All artifacts land in C:\canon\.

  Why session 1: WinRM is session 0; frida's agent bootstrap stalls when the target
  lives in session 0 (no interactive window station). Running here (session 1, the
  autologon desktop) lets the agent thread actually execute the script.
#>
param(
  [string]$Tool   = 'C:\Program Files (x86)\Printer Potty WICReset\printerpotty.exe',
  [string]$Frida  = 'C:\canon\frida-inject-16-x86.exe',
  [string]$Script = 'C:\canon\appbin-dump.js',
  [int]$SettleMs  = 1300,
  [int]$HoldSecs  = 20
)
$ErrorActionPreference = 'Continue'
$log = 'C:\canon\sess1-dump.runlog'
function L($m){ ("{0} {1}" -f (Get-Date -Format o), $m) | Out-File -FilePath $log -Append -Encoding ascii }

# fresh state
New-Item -ItemType Directory -Force -Path 'C:\canon\appbin-out' | Out-Null
Get-ChildItem 'C:\canon\appbin-out' -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
Remove-Item 'C:\canon\appbin-events.log','C:\canon\appbin-dump.log','C:\canon\appbin-dump.log.err' -EA SilentlyContinue
Get-Process printerpotty,frida-inject-16-x86,frida-inject-x86 -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Milliseconds 300

L "SESSION=$([System.Diagnostics.Process]::GetCurrentProcess().SessionId)"
$p = Start-Process -FilePath $Tool -PassThru -WindowStyle Minimized
L "SPAWNED printerpotty pid=$($p.Id) session=$((Get-Process -Id $p.Id).SessionId)"

Start-Sleep -Milliseconds $SettleMs

# attach WITHOUT -e so the injector stays and the script keeps running; its stdout
# (base64 echo) goes to the redirect, but the AUTHORITATIVE output is the File-API
# .bin files + appbin-events.log the script writes itself.
$a = @('-p', "$($p.Id)", '-s', $Script, '-R', 'qjs')
L ("ATTACH " + ($a -join ' '))
$inj = Start-Process -FilePath $Frida -ArgumentList $a `
  -RedirectStandardOutput 'C:\canon\appbin-dump.log' -RedirectStandardError 'C:\canon\appbin-dump.log.err' `
  -WindowStyle Hidden -PassThru
L "INJECTOR pid=$($inj.Id)"

Start-Sleep -Seconds $HoldSecs

Stop-Process -Id $inj.Id -Force -EA SilentlyContinue
Get-Process frida-inject-16-x86 -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Milliseconds 400
$bins = Get-ChildItem 'C:\canon\appbin-out' -EA SilentlyContinue
L ("BINS=" + (($bins | Measure-Object).Count) + " events=" + ((Test-Path 'C:\canon\appbin-events.log')))
foreach($b in $bins){ L ("  bin " + $b.Name + " " + $b.Length) }
Stop-Process -Id $p.Id -Force -EA SilentlyContinue
L "DONE"
