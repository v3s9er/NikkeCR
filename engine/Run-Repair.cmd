@echo off
echo NIKKE Recovery Kit preview - save work and close NIKKE first.
echo Known-incident repair only. This cannot certify the whole computer is clean.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-NikkeRecovery.ps1" -Mode Apply
set "NIKKE_RECOVERY_EXIT=%ERRORLEVEL%"
echo Exit code: %NIKKE_RECOVERY_EXIT%
echo.
pause
exit /b %NIKKE_RECOVERY_EXIT%
