# Trusted, inspectable guest-only launcher. No downloads, installs or execution of target samples.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = 'C:\SandboxBootstrap\REA'
$configPath = Join-Path $root 'repo-config.psd1'
$git = 'C:\SandboxBootstrap\git\cmd\git.exe'
$node = Join-Path $root 'Tools\node\node.exe'
$java = Join-Path $root 'Tools\jdk25\bin\java.exe'
$javac = Join-Path $root 'Tools\jdk25\bin\javac.exe'
$ghidra = Join-Path $root 'Tools\ghidra_12.2_PUBLIC'
$headless = Join-Path $ghidra 'support\analyzeHeadless.bat'
$rea = Join-Path $root 'Tools\rea\node_modules\rea-agents\scripts\rea.mjs'
$targetDir = Join-Path $root 'Targets'
$guestCheckout = 'C:\App'

function Require-File([string]$Path, [string]$Help) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing $Help : $Path" }
}

try {
    Write-Host '[1/5] Inspecting the read-only tool store and private Git configuration...'
    foreach ($pair in @(
        @($git,'portable Git'), @($node,'portable Node.js'), @($java,'JDK 25'),
        @($javac,'full JDK 25'), @($headless,'Ghidra 12.2+ headless runner'),
        @($rea,'REA package entrypoint'), @($configPath,'repo-config.psd1')
    )) { Require-File $pair[0] $pair[1] }

    $config = Import-PowerShellDataFile -LiteralPath $configPath
    $repo = [string]$config.RepositoryUrl
    $ref = [string]$config.Ref
    if ($repo -notmatch '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$') {
        throw 'RepositoryUrl must be a public GitHub HTTPS repository, e.g. https://github.com/YOURNAME/rea-sandbox.git'
    }
    if ($ref -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,80}$' -or $ref.Contains('..') -or $ref.EndsWith('.lock')) {
        throw 'Ref must be a simple branch name (for example main).'
    }
    if (Test-Path -LiteralPath $guestCheckout) {
        throw 'C:\App already exists: refusing to delete or overwrite it. Relaunch a fresh Windows Sandbox.'
    }

    Write-Host '[2/5] Guarding home LAN IP ranges before the public Git clone...'
    # Best-effort LAN guard. Sandbox NAT DNS/gateway can live inside 172.16/12;
    # blocking that whole range here may break the Git clone. Security limits documented.
    if (-not (Get-NetFirewallRule -DisplayName 'REA Block RFC1918 LAN' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'REA Block RFC1918 LAN' -Direction Outbound `
            -Action Block -Profile Any -RemoteAddress '10.0.0.0/8','192.168.0.0/16','169.254.0.0/16' `
            -Enabled True | Out-Null
    }

    Write-Host '[3/5] Cloning PUBLIC project source into disposable C:\App...'
    Write-Host "Repository: $repo"
    Write-Host "Ref: $ref"
    # Git can only read the public repository. No checked-out project code is executed.
    $env:GIT_TERMINAL_PROMPT = '0'
    $env:GIT_CONFIG_NOSYSTEM = '1'
    $env:GIT_CONFIG_GLOBAL = 'NUL'
    & $git -c 'protocol.file.allow=never' -c 'protocol.ext.allow=never' clone `
       '--no-recurse-submodules' '--depth' '1' '--branch' $ref '--' $repo $guestCheckout
    if ($LASTEXITCODE -ne 0) { throw "Git clone exited with code $LASTEXITCODE" }
    & $git -C $guestCheckout rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Could not identify cloned commit.' }
}
catch {
    Write-Error "Bootstrap preflight/clone failure: $($_.Exception.Message)"
    exit 1
}
finally {
    # Mandatory networking cutoff, including on failed clone.
    try {
        Write-Host '[4/5] Closing all outbound access from the guest...'
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Block -ErrorAction Stop
    }
    catch { Write-Warning "COULD NOT VERIFY OUTBOUND NETWORK LOCKDOWN: $($_.Exception.Message)" }
}

# Verify lockdown before proceeding to the private targets.
$profiles = Get-NetFirewallProfile -Profile Domain,Private,Public
if (@($profiles | Where-Object { $_.DefaultOutboundAction -ne 'Block' -or -not $_.Enabled }).Count -gt 0) {
    Write-Error 'Outbound firewall policy was not successfully locked down. Private targets will NOT be staged.'
    exit 2
}

Write-Host '[5/5] Staging private targets INSIDE guest (read-only source, no execution)...'
$guestTargets = Join-Path $guestCheckout 'Targets'
New-Item -ItemType Directory -Path $guestTargets -Force | Out-Null
if (Test-Path -LiteralPath $targetDir -PathType Container) {
    $candidates = @(Get-ChildItem -LiteralPath $targetDir -Filter '*.exe' -File)
    foreach ($candidate in $candidates) {
        Copy-Item -LiteralPath $candidate.FullName -Destination $guestTargets -ErrorAction Stop
        $guestCopy = Join-Path $guestTargets $candidate.Name
        if ((Get-FileHash -LiteralPath $candidate.FullName -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $guestCopy -Algorithm SHA256).Hash) {
            throw "Hash mismatch copying $($candidate.Name)"
        }
        Write-Host "  Prepared (not run): $guestCopy"
    }
    if ($candidates.Count -eq 0) { Write-Host '  No .exe targets found. You can stage them privately later.' }
} else { Write-Host '  Optional private Targets folder is absent.' }
Write-Host 'Ready: no dependency installations, no host writes, and no target execution.'
