@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-NikkeAftercare.ps1"
set "NIKKE_RECOVERY_EXIT=%ERRORLEVEL%"
echo Exit code: %NIKKE_RECOVERY_EXIT%
pause
exit /b %NIKKE_RECOVERY_EXIT%
