#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$base=Join-Path $env:ProgramData 'NetChecker'
if(-not (Test-Path -LiteralPath (Join-Path $base 'config.json'))) {
    & (Join-Path $PSScriptRoot 'Install-NetChecker.ps1')
}
$conf=Get-Content -LiteralPath (Join-Path $base 'config.json') -Raw | ConvertFrom-Json
if(([uri]$conf.server).Scheme -ne 'https'){throw 'HTTPS server required'}
if($conf.installation_id){
 try {
  $request=@{installation_id=$conf.installation_id;token=$conf.token;hostname=$env:COMPUTERNAME;ips=@();macs=@();os_name=[Environment]::OSVersion.VersionString}
  $response=Invoke-RestMethod -Uri ($conf.server.TrimEnd('/')+'/api/enrollment/request') -Method Post -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Compress))) -TimeoutSec 15
  if($response.status -eq 'rejected'){
   $configPath=Join-Path $base 'config.json';Copy-Item -LiteralPath $configPath -Destination (Join-Path $base ('config.before-reinstall-'+[guid]::NewGuid().ToString()+'.json'))
   $bytes=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
   $conf.token=([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant();$conf.installation_id=[guid]::NewGuid().ToString()
   [IO.File]::WriteAllText($configPath,($conf|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
   schtasks /End /TN NetCheckerCollector | Out-Null;schtasks /Run /TN NetCheckerCollector | Out-Null
  }
 }catch{Write-Output 'Registration availability will be checked by the collector.'}
}
$dest=Join-Path $env:ProgramData 'NetCheckerDefender'
New-Item -ItemType Directory -Path $dest -Force | Out-Null
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
 $id=New-Object Security.Principal.SecurityIdentifier($sid)
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
Set-Acl -LiteralPath $dest -AclObject $acl
foreach($name in @('NetCheckerDefender','NetCheckerDefenderActions','NetCheckerDefenderExpiry','NetCheckerDefenderInventory')){Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Collector-Defender.ps1') -Destination $dest -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Uninstall-Defender.ps1') -Destination $dest -Force
foreach($file in @('Actions-Defender.ps1','Inventory-Defender.ps1','Scan-Defender.ps1')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $dest -Force}
$public=Join-Path $env:ProgramData 'NetCheckerDefenderStatus'
New-Item -ItemType Directory -Path $public -Force|Out-Null
$publicAcl=New-Object Security.AccessControl.DirectorySecurity
$publicAcl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')){
 $id=New-Object Security.Principal.SecurityIdentifier($sid)
 $publicAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
$id=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
$publicAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -LiteralPath $public -AclObject $publicAcl
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'NetChecker-Defender.exe') -Destination $public -Force
$shell=New-Object -ComObject WScript.Shell
$shortcut=$shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'NetChecker AI Agent 디펜더.lnk'))
$shortcut.TargetPath=Join-Path $public 'NetChecker-Defender.exe';$shortcut.WorkingDirectory=$public;$shortcut.Save()
$programs=Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'NetChecker'
New-Item -ItemType Directory -Path $programs -Force|Out-Null
$shortcut=$shell.CreateShortcut((Join-Path $programs 'AI Agent 디펜더.lnk'));$shortcut.TargetPath=Join-Path $public 'NetChecker-Defender.exe';$shortcut.Save()
$startup=$shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonStartup')) 'NetChecker AI Agent Defender.lnk'));$startup.TargetPath=Join-Path $public 'NetChecker-Defender.exe';$startup.Arguments='/tray';$startup.Save()
$exe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action=New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+(Join-Path $dest 'Collector-Defender.ps1')+'"')
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'NetCheckerDefender' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'NetCheckerDefender'

foreach($spec in @(@{name='NetCheckerDefenderActions';file='Actions-Defender.ps1';extra=''},@{name='NetCheckerDefenderExpiry';file='Actions-Defender.ps1';extra=' -ExpireOnly'})){
 $a=New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+(Join-Path $dest $spec.file)+'"'+$spec.extra)
 Register-ScheduledTask -TaskName $spec.name -Action $a -Trigger $trigger -Principal $principal -Settings $settings -Force|Out-Null
 Start-ScheduledTask -TaskName $spec.name
}
$inventoryAction=New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+(Join-Path $dest 'Inventory-Defender.ps1')+'"')
$inventoryTrigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1)
$inventorySettings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'NetCheckerDefenderInventory' -Action $inventoryAction -Trigger $inventoryTrigger -Principal $principal -Settings $inventorySettings -Force|Out-Null
Start-ScheduledTask -TaskName 'NetCheckerDefenderInventory'
