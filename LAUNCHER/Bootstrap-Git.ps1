# Stable local trust anchor. Run only from the WSB. Never fetch or execute audit targets here.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:USERNAME -ine 'WDAGUtilityAccount') { throw 'Refusing to run outside Windows Sandbox.' }
$mirror = 'C:\SandboxBootstrap'
$guest = 'C:\App'
$repo = Join-Path $guest 'repo'
$gitRoot = Join-Path $guest 'tools\git'
$git = Join-Path $gitRoot 'cmd\git.exe'
try {
    if (Test-Path -LiteralPath $guest) { throw 'Expected fresh guest workspace. Close and reopen Sandbox.' }
    New-Item -ItemType Directory -Path $guest, (Join-Path $guest 'temp'), (Join-Path $guest 'git-empty-hooks'), (Join-Path $guest 'git-empty-template') -Force | Out-Null
    Set-Location -LiteralPath $guest
    $env:TEMP = Join-Path $guest 'temp'; $env:TMP = $env:TEMP
    # Remove any inherited Git controls or credentials; use empty guest config.
    Get-ChildItem Env: | Where-Object { $_.Name -match '^(GIT_|GH_TOKEN$|GITHUB_TOKEN$|HTTP_PROXY$|HTTPS_PROXY$|ALL_PROXY$)' } | ForEach-Object { Remove-Item -LiteralPath "Env:\$($_.Name)" }
    $env:GIT_CONFIG_NOSYSTEM = '1'; $env:GIT_TERMINAL_PROMPT = '0'
    $env:GIT_CONFIG_GLOBAL = Join-Path $guest 'git-empty-config'
    New-Item -ItemType File -Path $env:GIT_CONFIG_GLOBAL | Out-Null
    $env:GIT_ALLOW_PROTOCOL = 'https'
    $env:GIT_LFS_SKIP_SMUDGE = '1'
    $env:GIT_TEMPLATE_DIR = Join-Path $guest 'git-empty-template'
    $configPath = Join-Path $mirror 'launcher\repo.json'
    $localConfig = Join-Path $mirror 'launcher\repo.local.json'
    if (Test-Path -LiteralPath $localConfig -PathType Leaf) { $configPath = $localConfig }
    $cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    if ($cfg.repository -cnotmatch '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git$' -or $cfg.repository -match '/(?:OWNER|REPOSITORY)(?:/|\.git$)') { throw 'Configure the exact public GitHub HTTPS clone URL in launcher\repo.json or repo.local.json.' }
    if ($cfg.branch -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$' -or $cfg.branch -match '\.\.|//|/\.|\.lock(?:/|$)|/$') { throw 'Invalid branch.' }
    if ($cfg.mode -cnotin @('pinned','latest','confirm-latest')) { throw 'Invalid mode.' }
    if ($cfg.mode -ceq 'pinned' -and $cfg.commit -cnotmatch '^[0-9a-f]{40}$') { throw 'Pinned mode requires a full lowercase Git commit SHA.' }
    if ($cfg.mode -cne 'pinned' -and $cfg.commit -ne '') { throw 'Clear commit for latest mode.' }
    $src = Join-Path $mirror 'git'
    if (-not (Test-Path -LiteralPath (Join-Path $src 'cmd\git.exe') -PathType Leaf)) { throw 'Existing shared Git not found: C:\SandboxBootstrap\git\cmd\git.exe. No download or host changes attempted.' }
    Write-Host "Using existing shared Git: $src" -ForegroundColor Cyan
    # All Git executable files and all clone writes remain guest-local.
    New-Item -ItemType Directory -Path $gitRoot -Force | Out-Null
    & "$env:SystemRoot\System32\robocopy.exe" $src $gitRoot /E /XJ /R:1 /W:1 /NP /NFL /NDL
    if ($LASTEXITCODE -ge 8 -or -not (Test-Path -LiteralPath $git -PathType Leaf)) { throw 'Shared Git guest copy failed.' }
    $opts = @('-c','credential.helper=','-c','http.sslVerify=true','-c','http.followRedirects=false','-c','core.hooksPath=C:/App/git-empty-hooks','-c','protocol.file.allow=never','-c','protocol.ext.allow=never','-c','submodule.recurse=false','-c','core.protectNTFS=true')
    & $git @opts --version
    if ($LASTEXITCODE -ne 0) { throw 'Git failed.' }
    Write-Host "Cloning trusted launcher source: $($cfg.repository) [$($cfg.branch)]" -ForegroundColor Cyan
    & $git @opts clone --no-checkout --no-tags --single-branch --branch $cfg.branch -- $cfg.repository $repo
    if ($LASTEXITCODE -ne 0) { throw 'Git clone failed.' }
    $tip = (& $git @opts -C $repo rev-parse --verify HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $tip -cnotmatch '^[0-9a-f]{40}$') { throw 'Cannot resolve branch commit.' }
    $commit = $tip
    if ($cfg.mode -ceq 'pinned') {
        $commit = $cfg.commit
        & $git @opts -C $repo merge-base --is-ancestor $commit $tip
        if ($LASTEXITCODE -ne 0) { throw 'Pinned commit not found in configured branch history.' }
    }
    # Latest mode (including legacy confirm-latest config) runs without an interactive approval.
    Write-Host "Selected launcher commit: $commit" -ForegroundColor Cyan
    # Reject symlinks and submodules in this trusted launcher checkout before materializing it.
    $tree = @(& $git @opts -C $repo ls-tree -r --full-tree $commit)
    if ($LASTEXITCODE -ne 0 -or $tree.Count -eq 0 -or @($tree | Where-Object { $_ -notmatch '^100(?:644|755) blob [0-9a-f]{40}\t' }).Count -ne 0) { throw 'Unexpected Git tree modes (symlink/submodule or invalid tree).' }
    & $git @opts -C $repo checkout --detach $commit
    if ($LASTEXITCODE -ne 0) { throw 'Checkout failed.' }
    $actual = (& $git @opts -C $repo rev-parse --verify HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actual -cne $commit) { throw 'Checkout commit mismatch.' }
    $entry = Join-Path $repo 'sandbox\Start-REA-Quick.ps1'
    if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) { throw 'Repository lacks expected sandbox entrypoint.' }
    $env:REA_BOOTSTRAP_COMMIT = $commit
    Write-Host "Launching commit: $commit" -ForegroundColor Green
    & $entry -LaunchVersion git-v1
} catch {
    # Never initiate a tunnel after a failed clone or checkout.
    try {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop
        $name = 'REA-VM-EMERGENCY-BLOCK-ALL'
        if (-not (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound -Action Block -RemoteAddress Any -Profile Any -Enabled True -ErrorAction Stop | Out-Null }
    } catch { Write-Warning 'Emergency firewall policy could not be applied. Close Sandbox immediately.' }
    throw
}
