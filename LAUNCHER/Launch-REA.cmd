@echo off
setlocal EnableExtensions DisableDelayedExpansion
title REA Git bootstrap - guest only
if /I not "%USERNAME%"=="WDAGUtilityAccount" (
  echo Refusing to execute outside Windows Sandbox.
  exit /b 1
)
if not exist "%~dp0Bootstrap-Git.ps1" (
  echo ERROR: Missing bootstrap: "%~dp0Bootstrap-Git.ps1"
  exit /b 1
)
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -STA -NoExit -ExecutionPolicy Bypass -File "%~dp0Bootstrap-Git.ps1"
echo Bootstrap returned. No automatic restart.
