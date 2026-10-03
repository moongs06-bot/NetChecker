$ErrorActionPreference='Stop'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$root=$PSScriptRoot
$queue=Join-Path $root 'queue'
New-Item -ItemType Directory -Path $queue -Force | Out-Null
$utf8=New-Object Text.UTF8Encoding($false)
$channels=@{Security=@(4625,1102);'Microsoft-Windows-Windows Defender/Operational'=@(1116,1117,5001)}

function Write-LocalState($value){
 $public=Join-Path $env:ProgramData 'NetCheckerDefenderStatus'
 if(-not (Test-Path -LiteralPath $public)){return}
 $value | Add-Member -NotePropertyName local_updated_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
 $tmp=Join-Path $public 'status.next.json';$file=Join-Path $public 'status.json'
 [IO.File]::WriteAllText($tmp,($value|ConvertTo-Json -Depth 12 -Compress),$utf8)
 if(Test-Path -LiteralPath $file){[IO.File]::Replace($tmp,$file,$null)}else{[IO.File]::Move($tmp,$file)}
}

while($true){
 try {
  $conf=Get-Content -LiteralPath (Join-Path $env:ProgramData 'NetChecker\config.json') -Raw | ConvertFrom-Json
  $server=([string]$conf.server).TrimEnd('/')
  if(([uri]$server).Scheme -ne 'https'){throw 'HTTPS required'}
  if($conf.installation_id){
   $ips=@();$macs=@()
   foreach($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()){
    if($nic.OperationalStatus -ne 'Up' -or $nic.NetworkInterfaceType -eq 'Loopback' -or $nic.NetworkInterfaceType -eq 'Tunnel'){continue}
    $mac=$nic.GetPhysicalAddress().ToString();if($mac.Length -eq 12){$macs+=$mac}
    foreach($item in $nic.GetIPProperties().UnicastAddresses){$addr=($item.Address.ToString() -split '%')[0];if($addr -ne '127.0.0.1' -and $addr -ne '::1'){$ips+=$addr}}
   }
   $enroll=@{installation_id=$conf.installation_id;token=$conf.token;hostname=$env:COMPUTERNAME;ips=@($ips | Select-Object -Unique -First 32);macs=@($macs | Select-Object -Unique -First 32);os_name=[Environment]::OSVersion.VersionString}
   $approved=Invoke-RestMethod -Uri ($server+'/api/enrollment/request') -Method Post -ContentType 'application/json' -Body ($enroll | ConvertTo-Json -Compress) -TimeoutSec 20
   if($approved.status -ne 'approved'){Write-LocalState @{state=$approved.status;observed_at=[DateTime]::UtcNow.ToString('o');label=$env:COMPUTERNAME;alerts=@();recent_events=@();actions=@()};Start-Sleep -Seconds 3600;continue}
  }
  $events=@();$health=@();$since=(Get-Date).AddHours(-1)
  foreach($channel in $channels.Keys){
   try {
    # Check channel readability independently: no matching events is not access denied.
    $log=Get-WinEvent -ListLog $channel -ErrorAction Stop
    if(-not $log.IsEnabled){throw 'Log disabled'}
    $found=@(Get-WinEvent -FilterHashtable @{LogName=$channel;Id=$channels[$channel];StartTime=$since} -MaxEvents 201 -ErrorAction SilentlyContinue -ErrorVariable eventErrors)
    if($eventErrors -and ($eventErrors[0].FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound')){throw 'Event query failed'}
    $health+=@{channel=$channel;status=$(if($found.Count -gt 200){'truncated'}elseif($channel -eq 'Security'){'policy_unverified'}else{'ok'})}
    foreach($e in ($found | Select-Object -First 200)){
     $xml=[xml]$e.ToXml();$fields=@{}
     foreach($d in $xml.Event.EventData.Data){$fields[[string]$d.Name]=[string]$d.'#text'}
     $ip=$fields['IpAddress'];$parsed=$null
     if(-not [Net.IPAddress]::TryParse($ip,[ref]$parsed)){$ip=$null}
     $events+=@{channel=$channel;record_id=[string]$e.RecordId;event_id=[int]$e.Id;observed_at=$e.TimeCreated.ToUniversalTime().ToString('o');source_ip=$ip}
    }
   }catch{$health+=@{channel=$channel;status='unavailable'}}
  }
  $mp=$null;$mpJob=$null
  try {$mpJob=Start-Job -ScriptBlock {Get-MpComputerStatus -ErrorAction Stop};$null=Wait-Job -Job $mpJob -Timeout 10;if($mpJob.State -ne 'Completed'){throw 'Status timeout'};$m=Receive-Job -Job $mpJob -ErrorAction Stop;if(-not $m){throw 'Status unavailable'};$mp=@{realtime=[bool]$m.RealTimeProtectionEnabled;antivirus=[bool]$m.AntivirusEnabled;signature_at=$(if($m.AntivirusSignatureLastUpdated){$m.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')}else{$null})}}catch{}finally{if($mpJob){Stop-Job -Job $mpJob -ErrorAction SilentlyContinue;Remove-Job -Job $mpJob -Force -ErrorAction SilentlyContinue}}
  $sample=@{batch_id=[guid]::NewGuid().ToString();observed_at=[DateTime]::UtcNow.ToString('o');version='0.3.0';os_build=[Environment]::OSVersion.VersionString;firewall_enabled=$null;channels=$health;defender=$mp;events=$events}
  $inventoryPath=Join-Path $root 'inventory.json'
  if(Test-Path -LiteralPath $inventoryPath){try{$inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json;$sample.firewall_enabled=$inventory.firewall_enabled}catch{}}
  $path=Join-Path $queue ($sample.batch_id+'.json')
  [IO.File]::WriteAllText($path,($sample | ConvertTo-Json -Depth 7 -Compress),$utf8)
  $files=@(Get-ChildItem -LiteralPath $queue -Filter '*.json' | Sort-Object LastWriteTime)
  if($files.Count -gt 120){$files | Select-Object -First ($files.Count-120) | Remove-Item -Force}
  # Server accepts events from the last two days. Never let expired uploads block new samples.
  foreach($expired in (Get-ChildItem -LiteralPath $queue -Filter '*.json' | Where-Object {$_.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddHours(-46)})){Remove-Item -LiteralPath $expired.FullName -Force}
  foreach($f in (Get-ChildItem -LiteralPath $queue -Filter '*.json' | Sort-Object LastWriteTime | Select-Object -First 2)){
   try {$raw=Invoke-WebRequest -UseBasicParsing -Uri ($server+'/api/defender/ingest') -Method Post -Headers @{Authorization=('Bearer '+$conf.token)} -ContentType 'application/json' -Body ($utf8.GetBytes([IO.File]::ReadAllText($f.FullName,$utf8))) -TimeoutSec 20;$raw.RawContentStream.Position=0;$reader=New-Object IO.StreamReader($raw.RawContentStream,[Text.Encoding]::UTF8);try{$response=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()};if($response.device){Write-LocalState $response.device};Remove-Item -LiteralPath $f.FullName -Force}catch{break}
  }
  if($inventoryPath -and (Test-Path -LiteralPath $inventoryPath)){try{$data=[IO.File]::ReadAllText($inventoryPath,$utf8);$null=Invoke-RestMethod -Uri ($server+'/api/defender/inventory') -Method Post -Headers @{Authorization=('Bearer '+$conf.token)} -ContentType 'application/json' -Body ($utf8.GetBytes($data)) -TimeoutSec 15}catch{}}
 }catch{Write-LocalState @{state='unavailable';label=$env:COMPUTERNAME;observed_at=[DateTime]::UtcNow.ToString('o');alerts=@();recent_events=@();actions=@()};[IO.File]::WriteAllText((Join-Path $root 'last-error.txt'),('Collection/upload unavailable at '+[DateTime]::UtcNow.ToString('o')),$utf8)}
 Start-Sleep -Seconds 3600
}
