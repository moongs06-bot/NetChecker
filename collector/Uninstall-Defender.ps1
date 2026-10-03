#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
foreach($name in @('NetCheckerDefender','NetCheckerDefenderActions','NetCheckerDefenderExpiry','NetCheckerDefenderInventory')){
 Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
 Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
}
# Remove only explicitly owned rules created by this product during uninstall.
Get-NetFirewallRule -Group 'NetCheckerDefender' -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^NetCheckerDefender-[0-9a-f-]{36}$'} | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Output 'Defender stopped. Existing NetChecker collector and local configuration are preserved.'
