<#
  Configure WinRM for Ansible — runs as SYSTEM from SetupComplete.cmd (before any
  user logon, no UAC, no network-profile race). A compact version of the canonical
  ansible ConfigureRemotingForAnsible.ps1: HTTP listener + Basic auth +
  AllowUnencrypted + a firewall rule open on ALL profiles (Public included — the
  Public profile blocking 5985 is what defeated the FirstLogon attempt).

  Lab VM on throwaway user-mode NAT, so Basic/unencrypted is acceptable. Tighten
  to HTTPS/Kerberos if this ever leaves the lab.
#>
$ErrorActionPreference = 'Stop'

# Ensure WinRM service is running + quick-config (creates the HTTP listener).
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM
winrm quickconfig -quiet -force 2>&1 | Out-Null

# Auth + transport: Basic + allow unencrypted (lab NAT).
Set-Item -Path WSMan:\localhost\Service\Auth\Basic        -Value $true  -Force
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted  -Value $true  -Force
Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP       -Value $true  -Force 2>$null

# Make sure an HTTP listener exists on 5985.
if (-not (Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -match 'Transport=HTTP\b' })) {
  New-Item -Path WSMan:\localhost\Listener -Transport HTTP -Address * -Force | Out-Null
}

# Firewall: open 5985 on ALL profiles (the fix — Public was blocking it).
New-NetFirewallRule -DisplayName 'WinRM-HTTP-In-All' -Direction Inbound -Action Allow `
  -Protocol TCP -LocalPort 5985 -Profile Any -ErrorAction SilentlyContinue | Out-Null
# Belt-and-suspenders: also force any network the NAT NIC is on to Private.
Get-NetConnectionProfile | ForEach-Object {
  Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private -ErrorAction SilentlyContinue
}

# LocalAccountTokenFilterPolicy=1 so the local admin gets a full token over the
# network (otherwise UAC remote-restriction blocks admin ops via WinRM).
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
  -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null

Restart-Service -Name WinRM
'WINRM_CONFIGURED ' + (Get-Date -Format o) | Out-File C:\winrm_configured.txt -Encoding ascii
