@echo off
REM Runs automatically as SYSTEM at the end of Windows Setup (before first logon).
REM Windows executes %WINDIR%\Setup\Scripts\SetupComplete.cmd if present.
REM We configure WinRM here (SYSTEM context, no UAC, network profile settled).
echo SetupComplete running %DATE% %TIME% > C:\setupcomplete_ran.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Setup\Scripts\ConfigureRemotingForAnsible.ps1 >> C:\setupcomplete_ran.txt 2>&1
exit /b 0
