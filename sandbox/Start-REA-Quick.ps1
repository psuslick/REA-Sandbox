# REA Windows Sandbox v0.12.4: guest-only REA + restricted MCP + outbound tunnel policy.
# Run ONLY from the .wsb in Windows Sandbox; NEVER on the Windows host.
param([string]$LaunchVersion = '')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:USERNAME -ine 'WDAGUtilityAccount') {
    throw "REFUSING to run outside Windows Sandbox. Current user: $env:USERNAME"
}

if ($LaunchVersion -ne 'git-v1') { throw 'Wrong launcher. Close this Sandbox and open REA-MCP.wsb.' }

# The bridge is the ONLY writable host mapping. It is provisioned by extracting the ZIP;
# no file in the main tool/bootstrap mapping can be modified from the guest.
$bridge = 'C:\REA-Exchange'
if (-not (Test-Path -LiteralPath $bridge -PathType Container)) {
    throw 'Diagnostics bridge missing. Create C:\SandboxBootstrap\REA-Exchange on the host before opening the .wsb.'
}
if (Test-Path -LiteralPath 'C:\App\mcp\ready.json') { Remove-Item -LiteralPath 'C:\App\mcp\ready.json' -Force }
$transcriptFile = Join-Path $bridge 'bootstrap.log'
Start-Transcript -LiteralPath $transcriptFile -Force -ErrorAction Stop | Out-Null
Write-Host "Diagnostics export active: C:\SandboxBootstrap\REA-Exchange\bootstrap.log on HOST" -ForegroundColor Cyan

# Optional guest-only prevention for Windows Console QuickEdit/selection pauses.
# The script does not depend on success; the event is recorded in diagnostics.
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class REAConsoleInput {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetStdHandle(int n);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetConsoleMode(IntPtr h, out uint mode);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleMode(IntPtr h, uint mode);
  public static bool DisableQuickEdit() {
    IntPtr h = GetStdHandle(-10); uint mode;
    if (h == IntPtr.Zero || h == new IntPtr(-1) || !GetConsoleMode(h, out mode)) return false;
    return SetConsoleMode(h, (mode | 0x0080u) & ~0x0040u);
  }
}
'@ -ErrorAction Stop
    if ([REAConsoleInput]::DisableQuickEdit()) { Write-Host 'Console QuickEdit disabled for this session.' }
    else { Write-Warning 'Could not disable QuickEdit; avoid selecting console text while copying.' }
} catch {
    Write-Warning 'Console QuickEdit adjustment unavailable; not fatal.'
}

# All guest-only provisioning errors, including EARLY preflight failures, trigger
# an emergency outbound BLOCK. The outer guard above must remain outside this try.
try {

$source = $PSScriptRoot
$mirror = 'C:\SandboxBootstrap'     # Host root mapped READ-ONLY in .wsb.
$guest  = 'C:\App'                  # Disposable guest-only workspace.
# These are the read-only MAPPING ROOTS. Vendor ZIPs sometimes add one nested folder.
# The actual tool root is resolved only after verifying all required executables.
$nodeMap = Join-Path $mirror 'node-v24.22.3-win-x64'
$jdkMap = Join-Path $mirror 'jdk25'
$ghidraMap = Join-Path $mirror 'ghidra_12.2_PUBLIC'
$nodeGuest = Join-Path $guest 'tools\node'
$jdkGuest = Join-Path $guest 'tools\jdk25'
$ghidraGuest = Join-Path $guest 'tools\ghidra_12.2_PUBLIC'
$reaRuntime = Join-Path $guest 'rea-runtime'
$reaExe = Join-Path $reaRuntime 'node_modules\.bin\rea.cmd'


# Dependency check happens BEFORE Ghidra copy and npm install. Never rely on the
# downloaded archive having one exact filename: inspect ZIP entries instead.
function Find-TunnelInput([string] $root) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $scanDirs = @($root)
    $scanDirs += @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop |
        Where-Object { $_.Name -match '^(tunnel|download|rea-)' } |
        Select-Object -ExpandProperty FullName)
    $scanFiles = @($scanDirs | ForEach-Object {
        Get-ChildItem -LiteralPath $_ -File -ErrorAction SilentlyContinue
    })
    # Also support ZIPs or extracted client under a named one-level directory.
    $scopedDirs = @($scanDirs | Where-Object { $_ -ne $root })
    foreach ($d in $scopedDirs) {
        $scanFiles += @(Get-ChildItem -LiteralPath $d -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -File -ErrorAction SilentlyContinue })
    }
    $choices = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $scanFiles) {
        if ($f.Extension -ieq '.zip' -and $f.Name -match '^tunnel-client.*windows.*amd64') {
            try {
                $z = [IO.Compression.ZipFile]::OpenRead($f.FullName)
                try {
                    # Inspect actual entry basenames, not the outer archive's variant label.
                    $entries = @($z.Entries | Where-Object {
                        [IO.Path]::GetFileName($_.FullName.Replace('\','/')) -in @('tunnel-client.exe','tunnel-client-runtime.exe','tunnel-client-runtime-cloudflared.exe') -and
                        $_.Length -gt 1024 -and $_.Length -le 104857600
                    })
                    if ($entries.Count -ne 1) { Write-Warning "Skipping $($f.Name): expected one supported executable, found $($entries.Count). Entries: $($z.Entries.FullName -join ', ')" }
                    if ($entries.Count -eq 1) {
                        $choices.Add([pscustomobject]@{Kind='ZIP'; Source=$f.FullName; Entry=$entries[0].FullName; Modified=$f.LastWriteTimeUtc})
                    }
                } finally { $z.Dispose() }
            } catch {
                Write-Warning "Cannot read ZIP archive $($f.Name): $($_.Exception.Message)"
            }
        } elseif ($f.Name -in @('tunnel-client.exe', 'tunnel-client-runtime.exe', 'tunnel-client-runtime-cloudflared.exe')) {
            $choices.Add([pscustomobject]@{Kind='EXE'; Source=$f.FullName; Entry=$f.Name; Modified=$f.LastWriteTimeUtc})
        }
    }
    if ($choices.Count -eq 0) {
        Write-Host 'Tunnel-related files visible in the mapped folder:' -ForegroundColor Yellow
        $names = @($scanFiles | Where-Object { $_.Name -match 'tunnel|\.zip$' } | Select-Object -ExpandProperty FullName)
        if ($names.Count) { $names | ForEach-Object { Write-Host "  $_" } }
        else { Write-Host '  (none)' }
        throw 'No supported Windows AMD64 tunnel-client executable was found in the staged archives or as an extracted executable. Use the official tunnel-client Windows AMD64 archive in C:\SandboxBootstrap (suffixes such as (1) are accepted). See bootstrap.log on host.'
    }
    # Prefer a ZIP to a loose EXE; prefer the highest version, then newest timestamp.
    $ranked = @($choices | Sort-Object -Property @(
       @{Expression={if ($_.Kind -eq 'ZIP') {1} else {0}};Descending=$true},
       @{Expression={if ($_.Source -match 'v(\d+)\.(\d+)\.(\d+)') { ([int]$Matches[1]*1000000)+([int]$Matches[2]*1000)+[int]$Matches[3] } else {0}};Descending=$true},
       @{Expression={$_.Modified};Descending=$true}
    ))
    return $ranked

}

function Stage-TunnelInput($choice, [string] $destination) {
    New-Item -Path (Split-Path -Parent $destination) -ItemType Directory -Force | Out-Null
    if ($choice.Kind -eq 'EXE') {
        Copy-Item -LiteralPath $choice.Source -Destination $destination -Force -ErrorAction Stop
    } else {
        $archive = [IO.Compression.ZipFile]::OpenRead($choice.Source)
        try {
            $match = @($archive.Entries | Where-Object { $_.FullName -ceq $choice.Entry })
            if ($match.Count -ne 1 -or $match[0].Length -le 0 -or $match[0].Length -gt 104857600) {
                throw 'Selected archive entry changed or is too large.'
            }
            $reader = $match[0].Open()
            try {
                $writer = [IO.File]::Open($destination, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try { $reader.CopyTo($writer) } finally { $writer.Dispose() }
            } finally { $reader.Dispose() }
        } finally { $archive.Dispose() }
    }
    $file = [IO.File]::ReadAllBytes($destination)
    if ($file.Length -lt 1024 -or $file[0] -ne 0x4D -or $file[1] -ne 0x5A) { throw 'Tunnel executable failed MZ header check.' }
    $peOffset = [BitConverter]::ToInt32($file, 0x3c)
    if ($peOffset -lt 0x40 -or $peOffset -gt ($file.Length-24)) { throw 'Tunnel executable has invalid PE offset.' }
    if ($file[$peOffset] -ne 0x50 -or $file[$peOffset+1] -ne 0x45 -or $file[$peOffset+2] -ne 0 -or $file[$peOffset+3] -ne 0) { throw 'Tunnel executable has invalid PE signature.' }
    if ([BitConverter]::ToUInt16($file, $peOffset+4) -ne 0x8664) { throw 'Tunnel executable is not Windows x64 (AMD64).' }
    $digest = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "PASS tunnel executable: Windows PE x64, guest-local; SHA256 $digest" -ForegroundColor Green
}

function Require-File([string] $path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "MISSING REQUIRED FILE: $path"
    }
    Write-Host " OK  $path" -ForegroundColor Green
}

function Copy-GuestTool([string] $source, [string] $destination) {
    New-Item -Path $destination -ItemType Directory -Force | Out-Null
    Write-Host "Copying $source to disposable $destination" -ForegroundColor Yellow
    & "$env:SystemRoot\System32\robocopy.exe" $source $destination /E /R:1 /W:1 /XJ /MT:8 /ETA /NDL
    $code = $LASTEXITCODE
    if ($code -ge 8) { throw "Robocopy failed (code $code) copying $source" }
    Write-Host "Copy complete: $destination (robocopy $code)" -ForegroundColor Green
}

function Resolve-ToolRoot {
    param(
        [Parameter(Mandatory = $true)][string] $MappedFolder,
        [Parameter(Mandatory = $true)][string[]] $RequiredFiles,
        [Parameter(Mandatory = $true)][string] $ToolName
    )
    if (-not (Test-Path -LiteralPath $MappedFolder -PathType Container)) {
        throw "MISSING MAPPED FOLDER for ${ToolName}: $MappedFolder"
    }
    # Check the mapping root, then exactly one child-folder level. This handles
    # Windows 'Extract All' wrapping a ZIP that itself contains a top-level folder.
    $candidates = @($MappedFolder)
    $candidates += @(Get-ChildItem -LiteralPath $MappedFolder -Directory -ErrorAction Stop |
        ForEach-Object { $_.FullName })
    $matches = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in $candidates) {
        $complete = $true
        foreach ($required in $RequiredFiles) {
            if (-not (Test-Path -LiteralPath (Join-Path $candidate $required) -PathType Leaf)) {
                $complete = $false
                break
            }
        }
        if ($complete) { $matches.Add($candidate) }
    }
    if ($matches.Count -eq 0) {
        $checked = ($candidates -join '; ')
        throw "NO COMPLETE $ToolName INSTALLATION FOUND. Checked: $checked. Required: $($RequiredFiles -join ', '). No downloads attempted."
    }
    if ($matches.Count -gt 1) {
        throw "AMBIGUOUS $ToolName ROOTS: $($matches -join '; '). Refusing to guess. No downloads attempted."
    }
    Write-Host " OK  $ToolName root: $($matches[0])" -ForegroundColor Green
    return $matches[0]
}

if ($source -ine 'C:\App\repo\sandbox' -or $env:REA_BOOTSTRAP_COMMIT -notmatch '^[0-9a-f]{40}$') { throw 'Launch using the Git bootstrap.' }
Write-Host "Source commit: $env:REA_BOOTSTRAP_COMMIT"
Write-Host '=== REA Sandbox v0.12.4: restricted MCP setup ===' -ForegroundColor Cyan
if (-not (Test-Path -LiteralPath $mirror -PathType Container)) {
    throw "Missing mapped folder: $mirror. Open the CORRECT .wsb and check the host folder exists."
}
Write-Host "Mapped folder: $mirror (configured read-only in the .wsb)"
# User-requested single-folder staging: whole host C:\SandboxBootstrap mapped READ-ONLY.
# IMPORTANT: Windows Sandbox cannot filter files within a mapped folder.
# Everything under this root is guest-readable, including unrelated subfolders.
# This is less restrictive than v0.8's five individual mappings. Never store
# personal documents, credentials, or secret files in the mapped host root.
Write-Warning 'The ENTIRE C:\SandboxBootstrap host folder is guest-readable (READ-ONLY). Keep unrelated/private files outside it.'
Write-Host 'One read-only source mapping and one narrowly scoped writable diagnostics mapping.'
if (Test-Path -LiteralPath (Join-Path $bridge 'connect-once.txt')) { throw 'Legacy plaintext credential file found. Remove connect-once.txt from REA-Exchange on the host before launching; this release never reads it.' }
$nodeHost = Resolve-ToolRoot -MappedFolder $nodeMap -RequiredFiles @('node.exe', 'npm.cmd') -ToolName 'Node.js'
$jdkHost = Resolve-ToolRoot -MappedFolder $jdkMap -RequiredFiles @('bin\java.exe', 'bin\javac.exe') -ToolName 'JDK'
$ghidraHost = Resolve-ToolRoot -MappedFolder $ghidraMap -RequiredFiles @('support\analyzeHeadless.bat', 'Ghidra\application.properties') -ToolName 'Ghidra'
$nodeExe = Join-Path $nodeHost 'node.exe'
$npmCmd = Join-Path $nodeHost 'npm.cmd'
foreach ($item in @(
    $nodeExe,
    $npmCmd,
    (Join-Path $jdkHost 'bin\java.exe'),
    (Join-Path $jdkHost 'bin\javac.exe'),
    (Join-Path $ghidraHost 'support\analyzeHeadless.bat'),
    (Join-Path $ghidraHost 'Ghidra\application.properties')
)) { Require-File $item }

# The Intel scanner may be present in the single read-only mapped host folder from startup.
# Presence alone cannot execute it. Validate its identity before any analysis.
$sampleName = 'Intel_HST_f59fdc8a-40f4-48f3-baa6-51b9a27e64b1_3.exe'
$sampleExpectedSha256 = 'dd3ff68bc5c326691e787a8967807a144535fcb334e315c42053bf68ac9df25b'
$sampleHost = Join-Path $mirror $sampleName
$hasIntel = Test-Path -LiteralPath $sampleHost -PathType Leaf
if ($hasIntel) {
$sampleHash = (Get-FileHash -LiteralPath $sampleHost -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sampleHash -ne $sampleExpectedSha256) { throw "Intel sample SHA-256 mismatch: $sampleHash" }
Write-Host 'PASS: Intel sample already present in base folder; original hash verified. Sample will not be executed.' -ForegroundColor Green
}
$inspectionRoot = Join-Path $mirror 'reaSourceInspection'
if (-not (Test-Path -LiteralPath $inspectionRoot -PathType Container)) { throw "Create $inspectionRoot on the host before launching." }
if ((Get-Item -LiteralPath $inspectionRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Inspection root cannot be a reparse point.' }
# No interactive confirmation: launch from the .wsb is the user's requested action.
# The WDAGUtilityAccount guard and guest-only workspace checks above remain required.
$tunnelInputs = @(Find-TunnelInput -root $mirror)
$tunnelRoot = Join-Path $guest 'tools\tunnel-client'
$tunnelExe = $null
foreach ($candidate in $tunnelInputs) {
    $candidatePath = Join-Path $tunnelRoot ([IO.Path]::GetFileName($candidate.Entry.Replace('\','/')))
    try {
        Write-Host "Checking tunnel candidate: $($candidate.Source) [$($candidate.Entry)]"
        Stage-TunnelInput -choice $candidate -destination $candidatePath
        # Help is local, no credentials, no network connection. Verify this exact binary's run contract.
        $oldPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $helpText = (& $candidatePath run --help 2>&1 | Out-String)
            $helpCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $oldPreference }
        if ($helpCode -ne 0 -or $helpText -notmatch 'mcp\.command' -or $helpText -notmatch 'control-plane\.tunnel-id' -or $helpText -notmatch 'health\.listen-addr') { throw 'Run help did not confirm required polling/stdio flags.' }
        $tunnelExe = $candidatePath
        break
    } catch {
        Write-Warning "Rejected tunnel candidate: $($_.Exception.Message)"
        Remove-Item -LiteralPath $candidatePath -Force -ErrorAction SilentlyContinue
    }
}
if (-not $tunnelExe) { throw 'All tunnel-client candidates failed PE or CLI verification. See candidate diagnostics above.' }
Write-Host "PASS tunnel client: $tunnelExe" -ForegroundColor Green
$guardSource = Join-Path $source 'rea-mcp-guard.js'
Require-File $guardSource
Require-File (Join-Path $source 'rea-smoke.js')
Require-File (Join-Path $source 'REA-Common.ps1')
Require-File (Join-Path $source 'Start-Tunnel.ps1')
Require-File (Join-Path $source 'REA-Credentials.ps1')
# Verify the interactive credential UI dependency before expensive provisioning.
Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
Add-Type -AssemblyName System.Drawing -ErrorAction Stop
. (Join-Path $source 'REA-Common.ps1')
Write-Host 'Preflight passed. Continuing automatically inside Windows Sandbox.' -ForegroundColor Green

Write-Host '=== Copy tools to a true guest-local directory ===' -ForegroundColor Cyan
New-Item -Path (Join-Path $guest 'tools') -ItemType Directory -Force | Out-Null
Copy-GuestTool $nodeHost $nodeGuest
$nodeExe = Join-Path $nodeGuest 'node.exe'
$npmCmd = Join-Path $nodeGuest 'npm.cmd'
Require-File $nodeExe
Require-File $npmCmd
& $nodeExe --version
if ($LASTEXITCODE -ne 0) { throw 'Guest-local Node failed' }
Copy-GuestTool $jdkHost $jdkGuest
Copy-GuestTool $ghidraHost $ghidraGuest
Require-File (Join-Path $jdkGuest 'bin\java.exe')
Require-File (Join-Path $jdkGuest 'bin\javac.exe')
Require-File (Join-Path $ghidraGuest 'support\analyzeHeadless.bat')

# All package installs, caches and temp data are in disposable, UNMAPPED C:\App.
foreach ($folder in @(
    $reaRuntime,
    (Join-Path $guest 'npm-cache'),
    (Join-Path $guest 'npm-prefix'),
    (Join-Path $guest 'temp')
)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
$env:JAVA_HOME = $jdkGuest
$env:GHIDRA_INSTALL_DIR = $ghidraGuest
$env:REA_ANALYSIS_PROVIDER = 'ghidra'
$env:REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS = '120'
foreach ($name in @('REA_MCP_TOOL_FAMILIES','REA_MCP_INPUT_SCHEMA_PROFILE','REA_MCP_OUTPUT_SCHEMA_PROFILE')) { Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue }
# Keep the same environment in the interactive PowerShell shell when provisioning finishes.
# The launcher starts PowerShell with -NoExit; this PATH includes the guest-only REA CLI.
$env:PATH = "$reaRuntime\node_modules\.bin;$nodeGuest;$jdkGuest\bin;$env:PATH"
$env:npm_config_cache = Join-Path $guest 'npm-cache'
$env:npm_config_prefix = Join-Path $guest 'npm-prefix'
$env:npm_config_userconfig = Join-Path $guest '.npmrc'
$env:npm_config_globalconfig = Join-Path $guest 'npm-globalrc'
$env:npm_config_update_notifier = 'false'
$env:npm_config_audit = 'false'
$env:npm_config_fund = 'false'
$env:TEMP = Join-Path $guest 'temp'
$env:TMP = $env:TEMP
$env:npm_config_registry = 'https://registry.npmjs.org/'
& $nodeExe --version
if ($LASTEXITCODE -ne 0) { throw 'Guest-local Node failed' }
& $npmCmd --version
if ($LASTEXITCODE -ne 0) { throw 'Guest-local npm failed' }

& (Join-Path $jdkGuest 'bin\java.exe') -version
if ($LASTEXITCODE -ne 0) { throw 'Guest-local Java failed' }
& (Join-Path $jdkGuest 'bin\javac.exe') -version
if ($LASTEXITCODE -ne 0) { throw 'Guest-local javac failed' }

Write-Host '=== Installing rea-agents@6.10.1 in guest only ===' -ForegroundColor Cyan
Push-Location $reaRuntime
try {
    & $npmCmd install --prefix $reaRuntime --no-save --no-audit --no-fund 'rea-agents@6.10.1'
    if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit code $LASTEXITCODE)" }
} finally { Pop-Location }
Require-File $reaExe

$mcpDir = Join-Path $guest 'mcp'
New-Item -Path $mcpDir -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath $guardSource -Destination (Join-Path $mcpDir 'rea-mcp-guard.js') -Force
Copy-Item -LiteralPath (Join-Path $source 'rea-source-scope.js') -Destination $mcpDir -Force
New-Item -Path (Join-Path $guest 'source-samples') -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $source 'rea-smoke.js') -Destination $mcpDir -Force
New-Item -Path (Join-Path $guest 'samples') -ItemType Directory -Force | Out-Null

Write-Host '=== FAIL-CLOSED GUEST OUTBOUND FIREWALL ===' -ForegroundColor Cyan
# Resolve before cutting unrestricted provisioning egress. Pin one resolved HTTPS
# address in the GUEST hosts file, and permit only tunnel-client.exe to that IP:443.
# It may need re-resolution in a future Sandbox session if OpenAI rotates its IPs.
try {
    $ipChoices = @(Resolve-DnsName -Name 'api.openai.com' -Type A -DnsOnly -ErrorAction Stop |
        Where-Object { $_.Type -eq 'A' -and $_.IPAddress -match '^\d{1,3}(\.\d{1,3}){3}$' } |
        Select-Object -ExpandProperty IPAddress -Unique)
} catch {
    $ipChoices = @()
    Write-Warning 'OpenAI API DNS resolution failed; will lock outbound networking and stop.'
}
$ipPin = if ($ipChoices.Count) { $ipChoices[0] } else { $null }
# Lockdown MUST happen, even if DNS fails, so exceptions are never treated as offline success.
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop
    # Remove inherited Windows outbound-ALLOW exceptions from this disposable guest.
    $oldAllow = @(Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Direction Outbound -Action Allow -ErrorAction Stop)
    foreach ($r in $oldAllow) { $r | Disable-NetFirewallRule -ErrorAction Stop | Out-Null }
    if (-not $ipPin) { throw 'Failed to resolve api.openai.com before lockdown; no tunnel exception can be created.' }
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    Add-Content -LiteralPath $hostsPath -Value ("`r`n$ipPin api.openai.com # REA-Sandbox ephemeral pin") -Encoding Ascii -ErrorAction Stop
    Clear-DnsClientCache -ErrorAction Stop # Refresh resolution after the hosts-file pin.
    $allowName = 'REA-VM-Tunnel-Only-HTTPS'
    New-NetFirewallRule -Name $allowName -DisplayName $allowName -Direction Outbound -Action Allow -Program $tunnelExe -Protocol TCP -RemotePort 443 -RemoteAddress $ipPin -Profile Any -Enabled True -ErrorAction Stop | Out-Null
    # REA's Windows bridge uses IPv4 loopback; allow the local analysis processes only.
    $nodeLoop = 'REA-VM-Node-Loopback'
    $javaLoop = 'REA-VM-Java-Loopback'
    New-NetFirewallRule -Name $nodeLoop -DisplayName $nodeLoop -Direction Outbound -Action Allow -Program $nodeExe -Protocol TCP -RemoteAddress '127.0.0.1' -Profile Any -Enabled True -ErrorAction Stop | Out-Null
    New-NetFirewallRule -Name $javaLoop -DisplayName $javaLoop -Direction Outbound -Action Allow -Program (Join-Path $jdkGuest 'bin\java.exe') -Protocol TCP -RemoteAddress '127.0.0.1' -Profile Any -Enabled True -ErrorAction Stop | Out-Null
    Assert-REAFirewall -Tunnel $tunnelExe -Node $nodeExe -Java (Join-Path $jdkGuest 'bin\java.exe') -Ip $ipPin
    Write-Host "PASS: effective firewall rules checked for exact application, address, protocol and port." -ForegroundColor Green
} catch {
    Write-Warning "NETWORK LOCKDOWN FAILED: $($_.Exception.Message)"
    # Block overrides any inherited Allow. This intentionally also blocks MCP.
    $emergency = 'REA-VM-EMERGENCY-BLOCK-ALL'
    if (-not (Get-NetFirewallRule -Name $emergency -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $emergency -DisplayName $emergency -Direction Outbound -Action Block -RemoteAddress Any -Profile Any -Enabled True -ErrorAction Stop | Out-Null
    }
    throw 'STOP: firewall could not be verified; do NOT add an executable, key, or start the tunnel in this Sandbox.'
}

Write-Host '=== STAGING INTEL SAMPLE INTO GUEST STORAGE (NO EXECUTION) ===' -ForegroundColor Cyan
$sampleGuest = Join-Path (Join-Path $guest 'samples') $sampleName
if ($hasIntel) {
Copy-Item -LiteralPath $sampleHost -Destination $sampleGuest -Force
$guestHash = (Get-FileHash -LiteralPath $sampleGuest -Algorithm SHA256).Hash.ToLowerInvariant()
if ($guestHash -ne $sampleExpectedSha256) { throw "Intel sample guest copy SHA-256 mismatch: $guestHash" }
Write-Host 'PASS: Intel scanner is available in disposable C:\App\samples; original SHA-256 verified.' -ForegroundColor Green
}

Write-Host '=== OFFLINE GHIDRA / REA DIAGNOSTICS ===' -ForegroundColor Cyan
& $reaExe --version
if ($LASTEXITCODE -ne 0) { throw "REA --version returned $LASTEXITCODE" }
$doctorRaw = (& $reaExe doctor --provider ghidra --json | Out-String)
$doctorExit = $LASTEXITCODE
$doctorRaw | Write-Host
if ($doctorExit -ne 0) { throw "REA Ghidra doctor returned code $doctorExit." }
$doctor = ConvertFrom-Json -InputObject $doctorRaw
if ($doctor.healthy -ne $true -or @($doctor.providerInspections | Where-Object { $_.id -eq 'ghidra' -and $_.available -eq $true }).Count -ne 1) { throw 'Ghidra scoped doctor did not confirm readiness.' }
Write-Host '=== LOCAL MCP SMOKE TEST (no remote key) ===' -ForegroundColor Cyan
& $nodeExe (Join-Path $mcpDir 'rea-smoke.js')
if ($LASTEXITCODE -ne 0) { throw 'Local MCP smoke test failed. See preceding output.' }
Assert-REAFirewall -Tunnel $tunnelExe -Node $nodeExe -Java (Join-Path $jdkGuest 'bin\java.exe') -Ip $ipPin
$ready = [ordered]@{ commit=$env:REA_BOOTSTRAP_COMMIT; version='0.12.4'; ip=$ipPin; tunnel=$tunnelExe; tunnelSha256=(Get-FileHash -LiteralPath $tunnelExe -Algorithm SHA256).Hash; scopeSha256=(Get-FileHash -LiteralPath (Join-Path $mcpDir 'rea-source-scope.js') -Algorithm SHA256).Hash; guardSha256=(Get-FileHash -LiteralPath (Join-Path $mcpDir 'rea-mcp-guard.js') -Algorithm SHA256).Hash }
$ready | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $mcpDir 'ready.json') -Encoding Ascii
Write-Host '=== REA VM HARDENING CHECKPOINT ===' -ForegroundColor Green
Write-Host 'Bootstrap diagnostics saved to C:\SandboxBootstrap\REA-Exchange\bootstrap.log on the HOST.' -ForegroundColor Green
Write-Host 'The Sandbox is provisioned; outbound-default-deny and selected tunnel-client HTTPS exception installed.'
Write-Host 'Clipboard redirection is enabled; printer, audio/video input and vGPU remain disabled.'
Write-Host 'The ENTIRE C:\SandboxBootstrap base folder is mapped READ-ONLY. Do not put secrets or private files in it.'
Write-Host 'Read-only source inspection is enabled at C:\SandboxBootstrap\reaSourceInspection. Optional Intel sample remains hash-pinned.'
Write-Host 'The credential dialog opens automatically after diagnostics logging stops.' -ForegroundColor Cyan
Write-Host 'Diagnostics are available on the HOST in REA-Exchange\bootstrap.log.'
Write-Host 'The REA-VM tunnel ID and restricted runtime key will be requested locally; NEVER paste them into ChatGPT.'
Write-Host 'C:\App is disposable. Closing this Sandbox loses installed tools and runtime credentials.'

} catch {
    $fatal = $_
    Remove-Item -LiteralPath 'C:\App\mcp\ready.json' -Force -ErrorAction SilentlyContinue
    Write-Warning "REA v0.12.4 provisioning stopped: $($fatal.Exception.Message)"
    try {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop
        if (-not (Get-NetFirewallRule -Name 'REA-VM-EMERGENCY-BLOCK-ALL' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name 'REA-VM-EMERGENCY-BLOCK-ALL' -DisplayName 'REA-VM-EMERGENCY-BLOCK-ALL' -Direction Outbound -Action Block -RemoteAddress Any -Profile Any -Enabled True -ErrorAction Stop | Out-Null
        }
        Write-Warning 'Guest outbound BLOCK applied after failure. This is not a usable Sandbox session.'
    } catch {
        Write-Warning "Could not verify emergency guest network block: $($_.Exception.Message). Close this Sandbox immediately."
    }
    throw $fatal
} finally {
    # Do not collect credentials if transcript shutdown cannot be verified.
    Stop-Transcript -ErrorAction Stop | Out-Null
}

# A failed provisioning try rethrows; this point is reached only on success,
# after the transcript has stopped. Retry connection without reinstalling.
while ($true) {
    try {
        & (Join-Path $source 'Start-Tunnel.ps1')
        break
    } catch {
        Write-Warning ('Tunnel startup or connection stopped: ' + $_.Exception.Message)
        $retry = [System.Windows.Forms.MessageBox]::Show('The tunnel did not start or exited with an error. See the guest console. Retry the connection without reinstalling?', 'REA connection', [System.Windows.Forms.MessageBoxButtons]::RetryCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($retry -ne [System.Windows.Forms.DialogResult]::Retry) { break }
    }
}
