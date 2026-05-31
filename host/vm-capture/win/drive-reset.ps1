<#
  Lane B headless, layer 3 — drive ONE absorber reset in the Windows maintenance
  tool via UIAutomation (control-name invoke, NOT pixel-clicking), so the
  host-side usbmon capture records the real session-open -> preamble -> payload
  handshake.

  UIAutomation finds controls by Name/AutomationId and Invokes them — robust and
  scriptable. BUT the exact control names of the closed-source Service Tool /
  WICReset aren't known until we see the live tree. So this script is
  DISCOVERY-FIRST: with -Dump it prints the full control tree (copy that back to
  refine the selectors); without it, it attempts the reset using best-guess
  selectors and falls back to dumping if they miss.

  Usage in the guest (or via Ansible win_shell):
    powershell -ExecutionPolicy Bypass -File C:\canon\drive-reset.ps1 -Dump
    powershell -ExecutionPolicy Bypass -File C:\canon\drive-reset.ps1 -Tool servicetool
#>
[CmdletBinding()]
param(
  [ValidateSet('servicetool','wicreset')] [string]$Tool = 'servicetool',
  [switch]$Dump,
  [int]$LaunchWaitSec = 8
)

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

function Find-ToolExe {
  param([string]$tool)
  $pats = if ($tool -eq 'wicreset') { @('*printerpotty*','*wicreset*') }
          else { @('ServiceTool*','TOOL0006*') }
  foreach ($p in $pats) {
    $f = Get-ChildItem 'C:\canon' -Recurse -Filter $p -ErrorAction SilentlyContinue |
         Where-Object { $_.Extension -eq '.exe' } | Select-Object -First 1
    if ($f) { return $f.FullName }
  }
  return $null
}

function Dump-Tree {
  param($element, [int]$depth = 0)
  if ($depth -gt 6) { return }
  $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
  $child = $walker.GetFirstChild($element)
  while ($child) {
    $nm = $child.Current.Name; $ct = $child.Current.ControlType.ProgrammaticName
    $aid = $child.Current.AutomationId
    Write-Output ((' ' * ($depth*2)) + "[$ct] name='$nm' id='$aid'")
    Dump-Tree -element $child -depth ($depth+1)
    $child = $walker.GetNextSibling($child)
  }
}

$exe = Find-ToolExe -tool $Tool
if (-not $exe) { Write-Error "tool exe not found under C:\canon for '$Tool'"; exit 2 }
Write-Output "launching: $exe"
$proc = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds $LaunchWaitSec

# Attach to the main window
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition(
  [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { Write-Error "could not attach to tool window (pid $($proc.Id))"; exit 3 }

if ($Dump) {
  Write-Output "===== CONTROL TREE (refine selectors from this) ====="
  Dump-Tree -element $win
  exit 0
}

# Best-guess reset flow. Service Tool: pick the absorber counter, click "Set"
# under "Ink Absorber Counter" (dialog 137 button id 1100 per our RE). WICReset:
# click "Reset". These names are guesses — if they miss, we dump + you refine.
function Invoke-ByName {
  param($win, [string[]]$names)
  foreach ($n in $names) {
    $c = New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::NameProperty, $n)
    $el = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
    if ($el) {
      $ip = $el.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
      $ip.Invoke()
      Write-Output "invoked '$n'"
      return $true
    }
  }
  return $false
}

$targets = if ($Tool -eq 'wicreset') { @('Reset','Reset Waste Counter','OK') }
           else { @('Set','Reset','Main') }

Write-Output ">>> usbmon should be capturing NOW on the host <<<"
Start-Sleep -Seconds 2
if (Invoke-ByName -win $win -names $targets) {
  Start-Sleep -Seconds 5   # let the reset exchange complete
  Write-Output "RESET invoked — check the host usbmon capture."
} else {
  Write-Output "could not find a reset control by name. Dumping tree to refine:"
  Dump-Tree -element $win
  Write-Output "Re-run with corrected -names, or click manually over VNC for this one capture."
}
