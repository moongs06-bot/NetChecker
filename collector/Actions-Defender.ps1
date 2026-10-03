param([string]$Root=$PSScriptRoot,[switch]$ExpireOnly)
$ErrorActionPreference='Stop'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$utf8=New-Object Text.UTF8Encoding($false)
function Send-Result($conf,$id,$result){
 $null=Invoke-RestMethod -Uri ($conf.server.TrimEnd('/')+'/api/defender/actions/'+$id+'/result') -Method Post -Headers @{Authorization=('Bearer '+$conf.token)} -ContentType 'application/json' -Body ($utf8.GetBytes(($result | ConvertTo-Json -Compress))) -TimeoutSec 20
}
function Is-PublicIP([string]$value){
 $ip=$null;if(-not [Net.IPAddress]::TryParse($value,[ref]$ip)){return $false}
 if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){return $false}
 $b=$ip.GetAddressBytes()
 return ($b[0] -ne 0 -and $b[0] -ne 10 -and $b[0] -ne 127 -and $b[0] -lt 224 -and -not ($b[0] -eq 169 -and $b[1] -eq 254) -and -not ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -and -not ($b[0] -eq 192 -and $b[1] -eq 168) -and -not ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127))
}
function Invoke-ApprovedAction($action,$conf){
 $id=[guid]::Parse([string]$action.id).ToString();$p=$action.payload
 $result=@{claim=$action.claim;success=$false;verified=$false;reboot_required=$false;detail='Action failed; manual review required.'}
 if([DateTime]::Parse($action.expires).ToUniversalTime() -lt [DateTime]::UtcNow){$result.detail='Approval expired before execution.';return $result}
 try {
  switch($action.kind){
   'firewall_block' {
    $ip=[string]$p.remote_ip
    if(-not (Is-PublicIP $ip)){throw 'Only public IPv4 supported'}
    $serverIPs=@([Net.Dns]::GetHostAddresses(([uri]$conf.server).Host) | ForEach-Object {$_.ToString()})
    if($ip -in $serverIPs){throw 'Control server address cannot be blocked'}
    $rule='NetCheckerDefender-'+$id
    $expires=[DateTime]::UtcNow.AddMinutes(60).ToString('o')
    # Expiry is recorded before creation so a crash cannot leave an untracked rule.
    [IO.File]::WriteAllText((Join-Path $Root ($rule+'.lease.json')),(@{rule=$rule;expires=$expires}|ConvertTo-Json -Compress),$utf8)
    $null=New-NetFirewallRule -Name $rule -DisplayName ('NetChecker approved temporary block '+$ip) -Group 'NetCheckerDefender' -Direction Inbound -RemoteAddress $ip -Action Block -Profile Any -Enabled True -ErrorAction Stop
    $r=Get-NetFirewallRule -Name $rule -ErrorAction Stop
    $filter=$r | Get-NetFirewallAddressFilter -ErrorAction Stop
    $result.success=$true;$result.verified=([string]$r.Enabled -eq 'True' -and [string]$r.Action -eq 'Block' -and $ip -in @($filter.RemoteAddress));$result.detail='Inbound rule applied and read back. 60-minute expiry; attack cessation is not proven.'
   }
   'firewall_remove' {
    $prior=[guid]::Parse([string]$p.rule_id).ToString();$rule='NetCheckerDefender-'+$prior
    $r=Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
    if($r){if($r.Group -ne 'NetCheckerDefender'){throw 'Rule ownership mismatch'};$r | Remove-NetFirewallRule -ErrorAction Stop}
    $result.success=$true;$result.verified=(-not (Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue));$result.detail='Owned firewall rule removal verified.'
   }
   'verify_action' {
    $original=$p.original_payload
    switch($p.original_kind){
     'update_install' {
      $uid=[guid]::Parse([string]$original.update_id).ToString();$rev=[int]$original.revision
      $session=New-Object -ComObject Microsoft.Update.Session
      $found=$session.CreateUpdateSearcher().Search("UpdateID='$uid' and RevisionNumber=$rev and IsInstalled=1")
      $info=New-Object -ComObject Microsoft.Update.SystemInfo
      $result.success=$true;$result.reboot_required=[bool]$info.RebootRequired;$result.verified=($found.Updates.Count -eq 1 -and -not $result.reboot_required)
      $result.detail='Read-only update installation and reboot-state recheck. Service health needs separate review.'
     }
     'firewall_block' {
      $rule='NetCheckerDefender-'+[guid]::Parse([string]$p.original_id).ToString()
      $r=Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
      $result.success=$true;$result.verified=($r -and $r.Group -eq 'NetCheckerDefender' -and [string]$r.Enabled -eq 'True' -and [string]$r.Action -eq 'Block')
      $result.detail='Read-only rule check; expired blocks may be absent. Attack cessation is not proven.'
     }
     'firewall_remove' {
      $rule='NetCheckerDefender-'+[guid]::Parse([string]$original.rule_id).ToString()
      $result.success=$true;$result.verified=(-not (Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue));$result.detail='Read-only owned rule removal check.'
     }
     default {throw 'Unsupported original kind'}
    }
   }
   'update_install' {
    $updateID=[guid]::Parse([string]$p.update_id).ToString();$revision=[int]$p.revision
    $session=New-Object -ComObject Microsoft.Update.Session
    $searcher=$session.CreateUpdateSearcher()
    $found=$searcher.Search("UpdateID='$updateID' and RevisionNumber=$revision and IsInstalled=0")
    if($found.Updates.Count -ne 1){throw 'Approved update no longer applicable'}
    $u=$found.Updates.Item(0);$security=$false
    foreach($category in $u.Categories){if($category.CategoryID -in @('0fa1201d-4330-4fa8-8ae9-b877473b6441','e6cf1350-c01b-414d-a61f-263d14d133b4')){$security=$true}}
    if(-not $security -or $u.InstallationBehavior.CanRequestUserInput){throw 'Unsupported update category or user interaction required'}
    if(-not $u.EulaAccepted){throw 'Accept Microsoft update license locally before approval; agent does not accept licenses'}
    $collection=New-Object -ComObject Microsoft.Update.UpdateColl;$null=$collection.Add($u)
    $installer=$session.CreateUpdateInstaller();if($installer.RebootRequiredBeforeInstallation){throw 'Existing reboot required; resolve in maintenance window'}
    $downloader=$session.CreateUpdateDownloader();$downloader.Updates=$collection;$download=$downloader.Download()
    if([int]$download.ResultCode -ne 2){throw 'Update download did not succeed'}
    $installer.Updates=$collection;$installed=$installer.Install()
    $result.success=([int]$installed.ResultCode -eq 2);$result.reboot_required=[bool]$installed.RebootRequired
    $check=$searcher.Search("UpdateID='$updateID' and RevisionNumber=$revision and IsInstalled=1")
    $result.verified=($check.Updates.Count -eq 1 -and -not $result.reboot_required)
    $result.detail=if($result.success){'Windows Update result checked. No restart was initiated. Service health must also be reviewed.'}else{'Windows Update failed; manual review required.'}
   }
   default {throw 'Unsupported action kind'}
  }
 }catch{$result.detail='Action could not be verified: '+$_.Exception.Message.Substring(0,[Math]::Min(500,$_.Exception.Message.Length))}
 return $result
}
# Standalone expiry worker removes only this product's rules, never broad firewall groups.
if($env:NETCHECKER_DEFENDER_TEST -eq '1'){return}
while($true){
 try {
  foreach($file in (Get-ChildItem -LiteralPath $Root -Filter 'NetCheckerDefender-*.lease.json')){
   $lease=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
   if($lease.rule -notmatch '^NetCheckerDefender-[0-9a-f-]{36}$'){continue}
   if([DateTime]::Parse($lease.expires).ToUniversalTime() -le [DateTime]::UtcNow){
    $r=Get-NetFirewallRule -Name $lease.rule -ErrorAction SilentlyContinue
    if($r -and $r.Group -eq 'NetCheckerDefender'){$r | Remove-NetFirewallRule -ErrorAction Stop}
    Remove-Item -LiteralPath $file.FullName -Force
   }
  }
  if($ExpireOnly){Start-Sleep -Seconds 30;continue}
  $conf=Get-Content -LiteralPath (Join-Path $env:ProgramData 'NetChecker\config.json') -Raw | ConvertFrom-Json
  if(([uri]$conf.server).Scheme -ne 'https'){throw 'HTTPS required'}
  $pending=Join-Path $Root 'action-result.json'
  if(Test-Path -LiteralPath $pending){$v=Get-Content -LiteralPath $pending -Raw | ConvertFrom-Json;Send-Result $conf $v.id $v.result;Remove-Item -LiteralPath $pending -Force}
  else {
   $response=Invoke-RestMethod -Uri ($conf.server.TrimEnd('/')+'/api/defender/actions/claim') -Method Post -Headers @{Authorization=('Bearer '+$conf.token)} -TimeoutSec 20
   if($response.action){
    $result=Invoke-ApprovedAction $response.action $conf
    [IO.File]::WriteAllText($pending,(@{id=$response.action.id;result=$result}|ConvertTo-Json -Depth 5 -Compress),$utf8)
    Send-Result $conf $response.action.id $result;Remove-Item -LiteralPath $pending -Force
   }
  }
 }catch{}
 Start-Sleep -Seconds 60
}
