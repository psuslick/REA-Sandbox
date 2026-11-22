@echo off
if not exist "%REA_NODE%" (
  echo REA_NODE unavailable. Use the launcher-created Sandbox shell.
  exit /b 2
)
if not exist "%REA_SCRIPT%" (
  echo REA_SCRIPT unavailable. Stage the complete REA npm package first.
  exit /b 3
)
"%REA_NODE%" "%REA_SCRIPT%" %*
exit /b %errorlevel%
