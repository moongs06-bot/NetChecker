#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
Stop-ScheduledTask -TaskName 'NetCheckerCollector' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'NetCheckerCollector' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:ProgramData 'NetChecker\flow-approval.lease') -Force -ErrorAction SilentlyContinue
Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\logman.exe') -ArgumentList 'stop NetChecker-Network-Observation -ets' -WindowStyle Hidden -Wait | Out-Null
Write-Host 'Collector stopped and startup task removed. Revoke the device in the dashboard. Local configuration is retained in ProgramData\NetChecker.'
