@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-NikkeRecovery.ps1" -Mode Audit
set "NIKKE_RECOVERY_EXIT=%ERRORLEVEL%"
echo Exit code: %NIKKE_RECOVERY_EXIT%
echo.
pause
exit /b %NIKKE_RECOVERY_EXIT%
