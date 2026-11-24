# Automatic launch INSIDE the already-provisioned v0.12.0 Windows Sandbox, in its REA PowerShell shell.
# Refuses to run unless guest-only provisioning and firewall lockdown have passed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:USERNAME -ine 'WDAGUtilityAccount') { throw 'STOP: must run inside Windows Sandbox.' }
$guest = 'C:\App'
$source = $PSScriptRoot
$mirror = 'C:\SandboxBootstrap'
$bridge = 'C:\REA-Exchange'
$sampleName = 'Intel_HST_f59fdc8a-40f4-48f3-baa6-51b9a27e64b1_3.exe'
$expectedSha256 = 'dd3ff68bc5c326691e787a8967807a144535fcb334e315c42053bf68ac9df25b'
$sampleHost = Join-Path $mirror $sampleName
$sampleGuest = Join-Path $guest "samples\$sampleName"
$readyPath = Join-Path $guest 'mcp\ready.json'
if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) { throw 'STOP: bootstrap did not complete. Close this Sandbox and launch the new WSB.' }
$ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
if ($ready.version -ne '0.12.0' -or $ready.commit -ne $env:REA_BOOTSTRAP_COMMIT) { throw 'STOP: wrong bootstrap version.' }
$tunnelExe = $ready.tunnel
$allowedTunnels = @('tunnel-client.exe','tunnel-client-runtime.exe','tunnel-client-runtime-cloudflared.exe') | ForEach-Object { Join-Path $guest "tools\tunnel-client\$_" }
if ($tunnelExe -notin $allowedTunnels) { throw 'STOP: unexpected tunnel path.' }
$guard = Join-Path $guest 'mcp\rea-mcp-guard.js'
$nodeHost = Join-Path $guest 'tools\node\node.exe'
$java = Join-Path $guest 'tools\jdk25\bin\java.exe'
foreach ($p in @($sampleHost, $sampleGuest, $tunnelExe, $guard, $nodeHost, $java)) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "STOP: missing $p." }
}
if ((Get-FileHash -LiteralPath $tunnelExe -Algorithm SHA256).Hash -ne $ready.tunnelSha256 -or (Get-FileHash -LiteralPath $guard -Algorithm SHA256).Hash -ne $ready.guardSha256) { throw 'STOP: staged tunnel or guard changed after checkpoint.' }
. (Join-Path $source 'REA-Common.ps1')
$ip = $ready.ip
Assert-REAFirewall -Tunnel $tunnelExe -Node $nodeHost -Java $java -Ip $ip
$original = (Get-FileHash -LiteralPath $sampleHost -Algorithm SHA256).Hash.ToLowerInvariant()
if ($original -ne $expectedSha256) { throw "STOP: original Intel sample hash mismatch: $original" }
# The guest-local sample was staged automatically after firewall lockdown.
# Do not re-copy from a mapped host directory after provisioning.
$copied = (Get-FileHash -LiteralPath $sampleGuest -Algorithm SHA256).Hash.ToLowerInvariant()
if ($copied -ne $expectedSha256) { throw "STOP: guest-local Intel sample copy hash mismatch: $copied" }
Write-Host 'PASS: original and guest-local Intel scanner SHA-256 match.' -ForegroundColor Green
Write-Host "PASS: firewall outbound-default-deny, tunnel-client restricted to $ip TCP 443; no unexpected enabled outbound-allow rules." -ForegroundColor Green
Write-Host 'MCP gateway will expose ONLY approved static REA tools and exactly one pinned binary path.' -ForegroundColor Green
Write-Host 'Paste the REA-VM ID and restricted key into the dialog. Never share a runtime key in ChatGPT.' -ForegroundColor Yellow
. (Join-Path $source 'REA-Credentials.ps1')
Remove-Item Env:\CONTROL_PLANE_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:\CONTROL_PLANE_TUNNEL_ID -ErrorAction SilentlyContinue
$exitCode = 'not started'
$credentials = $null
try {
    $idFile = Join-Path $mirror 'rea-vm-tunnel-id.txt'
    $initialId = ''
    if (Test-Path -LiteralPath $idFile -PathType Leaf) {
        $initialId = (Get-Content -LiteralPath $idFile -Raw).Trim()
        if ($initialId -notmatch '^tunnel_[A-Za-z0-9_-]{12,128}$') { $initialId = '' }
    }
    $credentials = Get-REACredentials -InitialId $initialId
    if ($null -eq $credentials) { Write-Host 'Connection cancelled; no tunnel started.'; return }
    $tunnelId = $credentials.Id
    $env:CONTROL_PLANE_API_KEY = $credentials.Key
    $credentials.Key = $null
    $credentials = $null
    # Recheck policy after the operator interaction and before starting the tunnel.
    Assert-REAFirewall -Tunnel $tunnelExe -Node $nodeHost -Java $java -Ip $ip
$env:CONTROL_PLANE_TUNNEL_ID = $tunnelId
$env:REA_GUARD_TARGET = $sampleGuest
$env:JAVA_HOME = Join-Path $guest 'tools\jdk25'
$env:GHIDRA_INSTALL_DIR = Join-Path $guest 'tools\ghidra_12.2_PUBLIC'
$env:TEMP = Join-Path $guest 'temp'
$env:TMP = $env:TEMP
$env:PATH = "$guest\tools\node;$env:JAVA_HOME\bin;$env:PATH"
$env:REA_ANALYSIS_PROVIDER = 'ghidra'
$env:REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS = '120'
# Clear inherited tunnel configuration and proxy settings, preserving only the key and tunnel ID.
Get-ChildItem Env: | Where-Object { $_.Name -match '^(CONTROL_PLANE_|MCP_|CLOUDFLARED_|TUNNEL_CLIENT_|HARPOON_|OPENAI_|HTTP_PROXY$|HTTPS_PROXY$|ALL_PROXY$)' -and $_.Name -notin @('CONTROL_PLANE_API_KEY','CONTROL_PLANE_TUNNEL_ID') } | ForEach-Object { Remove-Item -LiteralPath "Env:\$($_.Name)" }
$env:CONTROL_PLANE_BASE_URL = 'https://api.openai.com'
$env:TUNNEL_CLIENT_STATE_DIR = Join-Path $guest 'tunnel-state'
# tunnel-client parses --mcp.command as a command string; use forward slashes.
$cmd = ($nodeHost.Replace('\','/') + ' ' + $guard.Replace('\','/'))
Write-Host 'Starting authenticated OpenAI tunnel inside Windows Sandbox. Press Ctrl+C to stop.' -ForegroundColor Cyan
'Connection attempt started (runtime key not logged).' | Set-Content -LiteralPath (Join-Path $bridge 'tunnel-status.txt') -ErrorAction SilentlyContinue
Write-Host 'The tunnel has no arbitrary filesystem, shell, update, or execution tools.' -ForegroundColor Green
    & $tunnelExe run --control-plane.tunnel-id $tunnelId --mcp.command $cmd --health.listen-addr '127.0.0.1:0'
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "tunnel-client exited with code $exitCode" }
} finally {
    if ($null -ne $credentials) { $credentials.Key = $null; $credentials = $null }
    Remove-Item Env:\CONTROL_PLANE_API_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:\CONTROL_PLANE_TUNNEL_ID -ErrorAction SilentlyContinue
    Remove-Item Env:\REA_GUARD_TARGET -ErrorAction SilentlyContinue
    ('Tunnel process stopped; last exit code: ' + $exitCode + '. No credentials logged. Inspect guest console for details.') | Set-Content -LiteralPath (Join-Path $bridge 'tunnel-status.txt') -ErrorAction SilentlyContinue
    Write-Host 'Tunnel stopped. Credentials removed from this PowerShell environment. Guest storage is disposable.' -ForegroundColor Yellow
}
