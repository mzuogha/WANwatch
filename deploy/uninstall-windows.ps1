param([string]$ServiceName = "WANWatch")
$ErrorActionPreference = "Continue"
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if (-not $nssm -and (Test-Path "$PSScriptRoot\nssm.exe")) { $nssm = Get-Item "$PSScriptRoot\nssm.exe" }
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
  Stop-Service $ServiceName -ErrorAction SilentlyContinue
  if ($nssm) { & $nssm remove $ServiceName confirm } else { sc.exe delete $ServiceName }
}
Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "WANWatch dashboard" -ErrorAction SilentlyContinue
Write-Host "Service removed. Data, reports and config remain in $env:ProgramFiles\WANWatch."
