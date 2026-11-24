# Shared guest-only effective policy verification. No changes to firewall here.
function Assert-REAFirewall {
    param([string]$Tunnel,[string]$Node,[string]$Java,[string]$Ip)
    if ($env:USERNAME -ine 'WDAGUtilityAccount') { throw 'Not Windows Sandbox.' }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -Profile Domain,Private,Public -ErrorAction Stop)
    if ($profiles.Count -ne 3) { throw 'Cannot verify all effective firewall profiles.' }
    foreach ($profile in $profiles) {
        if ($profile.Enabled -ne 'True' -or $profile.DefaultOutboundAction -ne 'Block' -or $profile.DefaultInboundAction -ne 'Block') { throw "Firewall profile $($profile.Name) not locked down." }
    }
    $expected = @{
        'REA-VM-Tunnel-Only-HTTPS' = @($Tunnel,$Ip,'443')
        'REA-VM-Node-Loopback' = @($Node,'127.0.0.1','Any')
        'REA-VM-Java-Loopback' = @($Java,'127.0.0.1','Any')
    }
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound -Action Allow -ErrorAction Stop)
    if ($rules.Count -ne $expected.Count) { throw 'Unexpected number of effective outbound ALLOW rules.' }
    foreach ($rule in $rules) {
        if (-not $expected.ContainsKey($rule.Name)) { throw "Unexpected outbound ALLOW rule: $($rule.Name)" }
        $want = $expected[$rule.Name]
        $app = $rule | Get-NetFirewallApplicationFilter
        $addr = $rule | Get-NetFirewallAddressFilter
        $port = $rule | Get-NetFirewallPortFilter
        if ($app.Program -ine $want[0] -or (@($addr.RemoteAddress).Count -ne 1) -or @($addr.RemoteAddress)[0] -ine $want[1] -or "$($port.Protocol)" -notin @('TCP','6') -or (@($port.RemotePort).Count -ne 1) -or @($port.RemotePort)[0] -ne $want[2] -or "$($rule.Profile)" -ne 'Any') { throw "Firewall scope mismatch: $($rule.Name)" }
        $expected.Remove($rule.Name)
    }
    if ($expected.Count) { throw 'Missing effective outbound ALLOW rule.' }
    $emergency = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'REA-VM-EMERGENCY-BLOCK-ALL' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
    if ($emergency.Count) { throw 'Emergency block active; restart with a fresh Sandbox.' }
}
