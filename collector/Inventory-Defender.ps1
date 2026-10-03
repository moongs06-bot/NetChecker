param([string]$Root=$PSScriptRoot)
$ErrorActionPreference='Stop'
$out=Join-Path $Root 'inventory.json'
$result=@{observed_at=[DateTime]::UtcNow.ToString('o');status='unavailable';updates=@();os_build=[Environment]::OSVersion.VersionString;firewall_enabled=$null}
try {
 $conf=Get-Content -LiteralPath (Join-Path $env:ProgramData 'NetChecker\config.json') -Raw|ConvertFrom-Json
 if(([uri]$conf.server).Scheme -ne 'https'){throw 'HTTPS required'}
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $null=Invoke-RestMethod -Uri ($conf.server.TrimEnd('/')+'/api/defender/identity') -Headers @{Authorization=('Bearer '+$conf.token)} -TimeoutSec 15
 $session=New-Object -ComObject Microsoft.Update.Session
 $search=$session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
 foreach($u in $search.Updates){
  $security=$false
  foreach($category in $u.Categories){if($category.CategoryID -in @('0fa1201d-4330-4fa8-8ae9-b877473b6441','e6cf1350-c01b-414d-a61f-263d14d133b4')){$security=$true}}
  if(-not $security -or $u.InstallationBehavior.CanRequestUserInput){continue}
  if($result.updates.Count -ge 100){break}
  $result.updates+=@{id=$u.Identity.UpdateID;revision=[int]$u.Identity.RevisionNumber;title=([string]$u.Title).Substring(0,[Math]::Min(300,([string]$u.Title).Length));kb=@($u.KBArticleIDs | Select-Object -First 20);reboot_may_be_needed=($u.InstallationBehavior.RebootBehavior -ne 0)}
 }
 $result.status='available';$result.observed_at=[DateTime]::UtcNow.ToString('o')
}catch{}
try{if($result.status -ne 'available'){throw 'Inventory not authorized or incomplete'};$profiles=@(Get-NetFirewallProfile -ErrorAction Stop);$result.firewall_enabled=($profiles.Count -gt 0 -and @($profiles | Where-Object {-not $_.Enabled}).Count -eq 0)}catch{}
[IO.File]::WriteAllText($out,($result | ConvertTo-Json -Depth 6 -Compress),(New-Object Text.UTF8Encoding($false)))
