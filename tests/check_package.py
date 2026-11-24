"""Source-only checks. No PowerShell, dependencies, or supplied binaries executed."""
from pathlib import Path
import xml.etree.ElementTree as ET
p=Path(__file__).resolve().parent.parent
b=(p/'sandbox/Start-REA-Quick.ps1').read_text(encoding='utf-8-sig')
t=(p/'sandbox/Start-Tunnel.ps1').read_text(encoding='utf-8-sig')
g=(p/'launcher/Bootstrap-Git.ps1').read_text()
cmd=(p/'launcher/Launch-REA.cmd').read_text()
x=ET.parse(p/'launcher/REA-MCP.wsb').getroot()
assert all(x.findtext(k)=='Disable' for k in ['VGpu','PrinterRedirection','AudioInput','VideoInput'])
assert x.findtext('ProtectedClient')=='Enable' and x.findtext('ClipboardRedirection')=='Enable'
assert r'C:\SandboxBootstrap\launcher\Launch-REA.cmd' in x.findtext('LogonCommand/Command')
assert '-STA' in cmd and 'Bootstrap-Git.ps1' in cmd
assert [(f.findtext('SandboxFolder'),f.findtext('ReadOnly')) for f in x.findall('MappedFolders/MappedFolder')]==[(r'C:\SandboxBootstrap','true'),(r'C:\REA-Exchange','false')]
assert g.index('WDAGUtilityAccount')<g.index('robocopy.exe')<g.index('clone --no-checkout')<g.index('merge-base --is-ancestor')<g.index('ls-tree -r')<g.index('checkout --detach')<g.index('& $entry -LaunchVersion git-v1')
assert "Read-Host 'Type the full commit SHA" in g and 'GIT_CONFIG_NOSYSTEM' in g and 'http.sslVerify=true' in g
assert 'GIT_ALLOW_PROTOCOL' in g and 'credential.helper=' in g and 'core.hooksPath=' in g and 'submodule.recurse=false' in g
assert "Join-Path $guest 'repo'" in g and "Join-Path $guest 'tools\\mingit'" in g
assert 'REA-VM-EMERGENCY-BLOCK-ALL' in g
assert "$LaunchVersion -ne 'git-v1'" in b and '$source = $PSScriptRoot' in b and '$source = $PSScriptRoot' in t
assert b.index('$ready | ConvertTo-Json') < b.index('Stop-Transcript -ErrorAction Stop') < b.index("& (Join-Path $source 'Start-Tunnel.ps1')")
assert b.index('Stage-TunnelInput -choice $candidate')<b.index('Copy-GuestTool $nodeHost')<b.index('& $npmCmd install')<b.index('Assert-REAFirewall -Tunnel')<b.index('LOCAL MCP SMOKE TEST')<b.index('$ready | ConvertTo-Json')
assert t.index('Assert-REAFirewall -Tunnel')<t.index('$credentials = Get-REACredentials')<t.index('& $tunnelExe run')
assert "Join-Path $guest 'tools\\node\\node.exe'" in t and "Join-Path $nodeGuest 'npm.cmd'" in b
assert "($nodeHost.Replace('\\','/') + ' ' + $guard.Replace('\\','/'))" in t
assert 'commit=$env:REA_BOOTSTRAP_COMMIT' in b and '$ready.commit -ne $env:REA_BOOTSTRAP_COMMIT' in t
assert 'connect-once.txt' not in t and 'Remove-Item Env:\\CONTROL_PLANE_API_KEY' in t
assert 'UseSystemPasswordChar = $true' in (p/'sandbox/REA-Credentials.ps1').read_text(encoding='utf-8-sig')
assert 'Get-Clipboard' not in (p/'sandbox/REA-Credentials.ps1').read_text(encoding='utf-8-sig')
assert "'npm-cache'" in b and "'npm-prefix'" in b and 'rea-agents@6.10.1' in b
assert 'tunnel-client-runtime-cloudflared.exe' in b
sha='dd3ff68bc5c326691e787a8967807a144535fcb334e315c42053bf68ac9df25b'
assert sha in b and sha in t and sha in (p/'sandbox/rea-mcp-guard.js').read_text()
assert not any(f.suffix.lower() in ('.exe','.dll','.zip','.jar','.msi') for f in p.rglob('*') if f.is_file() and '.git' not in f.parts)
assert not (p/'launcher/repo.local.json').exists()
print('PASS: source-only tree, Git approval and checkout ordering, guest-local paths, WSB flags, inherited firewall and credential markers, pinned target and tunnel hotfix')
