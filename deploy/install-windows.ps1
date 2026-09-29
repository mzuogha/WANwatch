<#
.SYNOPSIS  Install WANWatch as a Windows service.
.DESCRIPTION
  Copies WANWatch to C:\Program Files\WANWatch, creates a Python virtual environment and
  registers an auto-start service. Uses NSSM (nssm.exe on PATH or next to this script) when
  available, which gives a real service with restart-on-failure and log rotation. Without NSSM it
  registers a SYSTEM scheduled task that starts at boot and restarts on failure.
  Run from an elevated PowerShell in the project folder:
     powershell -ExecutionPolicy Bypass -File .\deploy\install-windows.ps1
#>
param(
  [string]$InstallDir = "$env:ProgramFiles\WANWatch",
  [string]$ServiceName = "WANWatch",
  [int]$Port = 8080
)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run this from an elevated (Administrator) PowerShell." }

$src = Split-Path -Parent $PSScriptRoot
$py = (Get-Command py -ErrorAction SilentlyContinue)
if ($py) { $pyExe = "py"; $pyArgs = @("-3") } else {
  $py = Get-Command python -ErrorAction SilentlyContinue
  if (-not $py) { throw "Python 3.10+ is required. Install it for all users from python.org first." }
  $pyExe = "python"; $pyArgs = @()
}

New-Item -ItemType Directory -Force -Path $InstallDir, "$InstallDir\data", "$InstallDir\logs", "$InstallDir\reports" | Out-Null
Copy-Item -Recurse -Force "$src\wanwatch" $InstallDir
Copy-Item -Force "$src\requirements.txt" $InstallDir
if (-not (Test-Path "$InstallDir\config.yaml"))  { Copy-Item "$src\config.example.yaml" "$InstallDir\config.yaml" }
if (-not (Test-Path "$InstallDir\wanwatch.env")) { Copy-Item "$src\wanwatch.env.example" "$InstallDir\wanwatch.env" }

Write-Host "Creating virtual environment..."
& $pyExe @pyArgs -m venv "$InstallDir\venv"
& "$InstallDir\venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
& "$InstallDir\venv\Scripts\python.exe" -m pip install --quiet -r "$InstallDir\requirements.txt"

# lock down secrets: Administrators and SYSTEM only
foreach ($f in @("wanwatch.env", "config.yaml")) {
  icacls "$InstallDir\$f" /inheritance:r /grant:r "*S-1-5-32-544:(F)" "*S-1-5-18:(F)" | Out-Null
}

$pythonw = "$InstallDir\venv\Scripts\python.exe"
$svcArgs = "-m wanwatch run -c `"$InstallDir\config.yaml`""
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if (-not $nssm -and (Test-Path "$PSScriptRoot\nssm.exe")) { $nssm = Get-Item "$PSScriptRoot\nssm.exe" }

if ($nssm) {
  $n = $nssm.Source; if (-not $n) { $n = $nssm.FullName }
  if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { & $n stop $ServiceName | Out-Null; & $n remove $ServiceName confirm | Out-Null }
  & $n install $ServiceName $pythonw $svcArgs | Out-Null
  & $n set $ServiceName AppDirectory $InstallDir | Out-Null
  & $n set $ServiceName DisplayName "WANWatch FortiGate WAN monitor" | Out-Null
  & $n set $ServiceName Description "Monitors FortiGate WAN link health and SLA, alerts on degradation and failover." | Out-Null
  & $n set $ServiceName Start SERVICE_AUTO_START | Out-Null
  & $n set $ServiceName AppExit Default Restart | Out-Null
  & $n set $ServiceName AppRestartDelay 5000 | Out-Null
  & $n set $ServiceName AppStdout "$InstallDir\logs\service-stdout.log" | Out-Null
  & $n set $ServiceName AppStderr "$InstallDir\logs\service-stderr.log" | Out-Null
  & $n set $ServiceName AppRotateFiles 1 | Out-Null
  & $n set $ServiceName AppRotateBytes 5000000 | Out-Null
  $how = "Windows service '$ServiceName' (NSSM). Start: Start-Service $ServiceName"
} else {
  $action = New-ScheduledTaskAction -Execute $pythonw -Argument $svcArgs -WorkingDirectory $InstallDir
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
      -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
  $how = "scheduled task '$ServiceName' running as SYSTEM at boot (install NSSM and re-run for a true service). Start: Start-ScheduledTask $ServiceName"
}

if (-not (Get-NetFirewallRule -DisplayName "WANWatch dashboard" -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName "WANWatch dashboard" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Domain,Private | Out-Null
}

Write-Host ""
Write-Host "Installed as $how"
Write-Host "Before starting:"
Write-Host "  1. notepad `"$InstallDir\wanwatch.env`"     (FortiGate API token, SMTP password)"
Write-Host "  2. notepad `"$InstallDir\config.yaml`"      (firewall URL, link names, alert channels)"
Write-Host "  3. & `"$pythonw`" -m wanwatch hash-password   -> paste into web.password_hash"
Write-Host "  4. & `"$pythonw`" -m wanwatch check -c `"$InstallDir\config.yaml`""
Write-Host "Then open http://localhost:$Port"
