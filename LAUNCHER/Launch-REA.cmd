@echo off
setlocal EnableExtensions DisableDelayedExpansion
title REA Git bootstrap - guest only
if /I not "%USERNAME%"=="WDAGUtilityAccount" (
  echo Refusing to execute outside Windows Sandbox.
  exit /b 1
)
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -STA -NoExit -ExecutionPolicy Bypass -File "C:\SandboxBootstrap\launcher\Bootstrap-Git.ps1"
echo Bootstrap returned. No automatic restart.
