$ErrorActionPreference = "Continue"
$result = [ordered]@{
  collected_at = (Get-Date).ToUniversalTime().ToString("o")
  host = $env:COMPUTERNAME
  operating_system = "Windows"
  checks = @()
}
try {
  $defender = Get-MpComputerStatus
  $result.checks += [ordered]@{
    id = "WIN-DEF-001"; title = "Microsoft Defender real-time protection"
    status = if ($defender.RealTimeProtectionEnabled) { "pass" } else { "review" }
    finding = "RealTimeProtectionEnabled=$($defender.RealTimeProtectionEnabled)"
    recommendation = "Verify endpoint protection is enabled according to your organization's approved baseline."
  }
} catch {
  $result.checks += [ordered]@{
    id = "WIN-DEF-001"; title = "Microsoft Defender status"; status = "review"
    finding = "Defender status query unavailable: $($_.Exception.Message)"
    recommendation = "Check endpoint protection using the approved security management console."
  }
}
try {
  foreach ($profile in Get-NetFirewallProfile) {
    $result.checks += [ordered]@{
      id = "WIN-FW-$($profile.Name.ToUpper())"; title = "Windows Firewall $($profile.Name) profile"
      status = if ($profile.Enabled) { "pass" } else { "review" }
      finding = "Enabled=$($profile.Enabled)"
      recommendation = "Review whether the firewall profile should be enabled under local policy."
    }
  }
} catch {
  $result.checks += [ordered]@{
    id = "WIN-FW-001"; title = "Windows Firewall profiles"; status = "review"
    finding = "Firewall profile query unavailable: $($_.Exception.Message)"
    recommendation = "Inspect Windows Firewall status using an approved administrative tool."
  }
}
$result | ConvertTo-Json -Depth 6 | Set-Content -Path ".\windows-posture.json" -Encoding UTF8
Write-Host "Read-only posture report written to .\windows-posture.json"
