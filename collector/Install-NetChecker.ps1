#Requires -RunAsAdministrator
param([string]$Server='https://netchecker.example.com/netchecker/')
$ErrorActionPreference='Stop'
if(-not [Environment]::Is64BitOperatingSystem){throw 'NetChecker 0.3 requires 64-bit Windows.'}
$netRelease=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction SilentlyContinue).Release
if(-not $netRelease -or $netRelease -lt 528040){throw 'Please install .NET Framework 4.8 or later before NetChecker.'}
$uri=[uri]$Server
if ($uri.Scheme -ne 'https' -or -not $uri.Host) { throw 'HTTPS server required' }
$dest=Join-Path $env:ProgramData 'NetChecker'
New-Item -ItemType Directory -Path $dest -Force | Out-Null
# Only SYSTEM and local Administrators can read the per-device key and queue.
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
    $identity=New-Object Security.Principal.SecurityIdentifier($sid)
    $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $dest -AclObject $acl
Stop-ScheduledTask -TaskName 'NetCheckerCollector' -ErrorAction SilentlyContinue
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Collector.ps1') -Destination (Join-Path $dest 'Collector.ps1') -Force
Remove-Item -LiteralPath (Join-Path $dest 'flow-approval.lease') -Force -ErrorAction SilentlyContinue
$logman=Join-Path $env:SystemRoot 'System32\logman.exe'
Start-Process -FilePath $logman -ArgumentList 'stop NetChecker-Network-Observation -ets' -WindowStyle Hidden -Wait | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Read-PortEvents.ps1') -Destination (Join-Path $dest 'Read-PortEvents.ps1') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Uninstall-NetChecker.ps1') -Destination (Join-Path $dest 'Uninstall-NetChecker.ps1') -Force
$ownedHelper=Join-Path $dest 'flow\NetChecker.Flow.exe'
Get-Process -Name 'NetChecker.Flow' -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $ownedHelper} | Stop-Process -Force -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath (Join-Path $PSScriptRoot 'flow.zip') -DestinationPath (Join-Path $dest 'flow') -Force

$configFile=Join-Path $dest 'config.json'
if (Test-Path -LiteralPath $configFile) {
    $saved=Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
    if ($saved.server.TrimEnd('/') -ne $Server.TrimEnd('/')) { throw 'Existing configuration uses a different server.' }
} else {
    $bytes=New-Object byte[] 32
    $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes); $rng.Dispose()
    $deviceToken=([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant()
    @{server=$Server;token=$deviceToken;installation_id=[guid]::NewGuid().ToString()} | ConvertTo-Json | Set-Content -LiteralPath $configFile -Encoding UTF8
}
$exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action=New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+(Join-Path $dest 'Collector.ps1')+'"')
$trigger=New-ScheduledTaskTrigger -AtStartup
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'NetCheckerCollector' -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'NetCheckerCollector'
Write-Host 'NetChecker installed. Approve this computer in the dashboard Pending devices list. Monitoring starts only after approval.'
