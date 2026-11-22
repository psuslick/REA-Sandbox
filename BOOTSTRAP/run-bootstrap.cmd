@echo off
setlocal
set "SBROOT=C:\SandboxBootstrap\REA"
set "JAVA_HOME=%SBROOT%\Tools\jdk25"
set "GHIDRA_INSTALL_DIR=%SBROOT%\Tools\ghidra_12.2_PUBLIC"
set "REA_NODE=%SBROOT%\Tools\node\node.exe"
set "REA_SCRIPT=%SBROOT%\Tools\rea\node_modules\rea-agents\scripts\rea.mjs"
set "PATH=%SBROOT%\BOOTSTRAP;%SBROOT%\Tools\node;%JAVA_HOME%\bin;%PATH%"
echo.
echo ========= REA Windows Sandbox bootstrap =========
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SBROOT%\BOOTSTRAP\bootstrap.ps1"
if errorlevel 1 (
    echo.
    echo ERROR: bootstrap failed. Review the first error and private configuration.
    echo No Intel scanner executable was launched.
    cmd.exe /k
    exit /b 1
)
cd /d C:\App
echo.
echo Ready. Type:  rea doctor --provider ghidra --json
echo          or: rea analyze "C:\App\Targets\YOUR_FILE.exe" --provider ghidra --json
echo.
echo Network: guest outbound policy set to BLOCK. No automatic target execution.
cmd.exe /k
