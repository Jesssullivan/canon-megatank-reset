<#
  run-frida-capture.ps1 -- guest-side launcher for the instrumented WICReset capture.

  Downloads the STANDALONE frida CLI (no Python needed in the guest), launches the
  target tool under Frida with frida-wicreset-hook.js, and writes the app-layer
  event stream + a wall-clock anchor to C:\canon\. The host orchestrator
  (scripts/wicreset-instrumented-capture.sh) runs usbmon + a guest pktmon around
  this and correlates by the anchor.

  Frida standalone: github.com/frida/frida releases ship a single PyInstaller-frozen
  CLI exe, so no guest Python/pip is required.

  Modes:
    -Setup    download + stage frida.exe + verify the hook (idempotent), no launch
    -Launch   spawn the tool under frida and stream events (operator drives the GUI
              over VNC; this only instruments + logs -- it never enters the key)
    -Tool <path>  the WICReset exe to instrument (default: discovered)

  This script does NOT enter the key or click reset -- the operator/VNC does that so
  the human controls the single-use key. Frida is purely observational.
#>
[CmdletBinding()]
param(
  [switch]$Setup,
  [switch]$Launch,
  [string]$Tool = '',
  [string]$FridaVer = '16.5.9',
  [string]$WorkDir = 'C:\canon',
  [string]$Hook = 'C:\canon\frida-wicreset-hook.js',
  [string]$EventLog = 'C:\canon\frida-events.log',
  [string]$Anchor = 'C:\canon\capture-anchor.txt'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
# We use the STANDALONE frida-inject.exe (no Python). The host win_copies it in;
# in-guest download is a fallback only.
$fridaExe = Join-Path $WorkDir 'frida-inject.exe'

function Find-Tool {
  if ($Tool -and (Test-Path $Tool)) { return $Tool }
  $cands = @(
    'C:\Program Files (x86)\Printer Potty WICReset\*.exe',
    'C:\Program Files\Printer Potty WICReset\*.exe',
    'C:\canon\PrinterPotty_WICReset*.exe'
  )
  foreach ($c in $cands) {
    $f = Get-ChildItem $c -ErrorAction SilentlyContinue |
         Where-Object { $_.Name -notmatch 'unins' } | Select-Object -First 1
    if ($f) { return $f.FullName }
  }
  return $null
}

if ($Setup) {
  if (-not (Test-Path $fridaExe)) {
    $base = 'https://github.com/frida/frida/releases/download/' + $FridaVer
    $xz = Join-Path $WorkDir 'frida.exe.xz'
    $url = $base + '/frida-' + $FridaVer + '-windows-x86_64.exe.xz'
    Write-Output ('downloading frida CLI ' + $FridaVer)
    try {
      Invoke-WebRequest -Uri $url -OutFile $xz -UseBasicParsing
      if (Get-Command tar -ErrorAction SilentlyContinue) {
        & tar -xf $xz -C $WorkDir 2>$null
        $extracted = Get-ChildItem $WorkDir -Filter 'frida-*-windows-x86_64.exe' | Select-Object -First 1
        if ($extracted) { Move-Item $extracted.FullName $fridaExe -Force }
      }
    } catch {
      Write-Output ('frida CLI fetch/decompress failed: ' + $_)
      Write-Output 'FALLBACK: stage frida.exe manually into C:\canon (host can win_copy it in).'
    }
  }
  if (Test-Path $fridaExe) {
    $sig = Get-AuthenticodeSignature $fridaExe
    Write-Output ('frida.exe present. Authenticode: ' + $sig.Status)
  }
  Write-Output ('hook present: ' + (Test-Path $Hook))
  Write-Output ('SETUP_DONE frida=' + (Test-Path $fridaExe) + ' hook=' + (Test-Path $Hook))
  return
}

if ($Launch) {
  $t = Find-Tool
  if (-not $t) { throw 'WICReset tool not found -- pass -Tool <path> or install it first' }
  if (-not (Test-Path $fridaExe)) { throw 'frida.exe not staged -- run -Setup first (or win_copy it in)' }
  if (-not (Test-Path $Hook)) { throw ('hook not staged at ' + $Hook) }

  $epochMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $iso = [DateTime]::UtcNow.ToString('o')
  ('ANCHOR_LAUNCH epoch_ms=' + $epochMs + ' iso=' + $iso + ' tool=' + $t) |
    Out-File -FilePath $Anchor -Encoding ascii
  Write-Output ('ANCHOR epoch_ms=' + $epochMs + ' tool=' + $t)

  # frida-inject flags (verified from --help): -f spawn FILE, -s SCRIPT, -R runtime
  # (qjs|v8), -e eternalize (script keeps running after the injector exits -> WICReset
  # stays hooked while the operator drives the GUI over VNC). The hook's console.log
  # goes to the injector stdout, which we redirect to the event log.
  Write-Output ('launching under frida-inject -> ' + $EventLog)
  $procName = [IO.Path]::GetFileName($t)
  $fridaArgs = @('-f', $t, '-s', $Hook, '-R', 'v8', '-e')
  Start-Process -FilePath $fridaExe -ArgumentList $fridaArgs -WorkingDirectory $WorkDir `
    -RedirectStandardOutput $EventLog -RedirectStandardError ($EventLog + '.err') -WindowStyle Minimized
  Start-Sleep -Seconds 3
  Write-Output ('LAUNCHED frida-inject on ' + $procName + ' ; events -> ' + $EventLog)
  return
}

Write-Output 'specify -Setup or -Launch'
