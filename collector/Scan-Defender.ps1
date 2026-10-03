param([ValidateSet('QuickScan','FullScan')][string]$Mode='QuickScan')
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator required'}
$mutex=New-Object Threading.Mutex($false,'Global\NetCheckerDefenderScan')
if(-not $mutex.WaitOne(0)){exit 2}
$started=[DateTime]::UtcNow
$path=Join-Path $env:ProgramData 'NetCheckerDefenderStatus\scan.json'
function Save-Scan([string]$state,[string]$detail){
 $data=@{mode=$Mode;state=$state;detail=$detail;started_at=$started.ToString('o');updated_at=[DateTime]::UtcNow.ToString('o')}
 $tmp=$path+'.tmp';[IO.File]::WriteAllText($tmp,($data|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)));Move-Item -LiteralPath $tmp -Destination $path -Force
}
try{
 Save-Scan 'checking' 'Windows Defender 검사 가능 여부를 확인하고 있습니다.'
 $before=Get-MpComputerStatus -ErrorAction Stop
 if(-not $before.AntivirusEnabled -or -not $before.AMServiceEnabled -or ($before.AMRunningMode -and $before.AMRunningMode -ne 'Normal')){Save-Scan 'unavailable' 'Windows Defender 검사가 비활성화되어 있습니다. Windows 보안에서 사용 중인 백신을 확인해 주세요. 백신 설정은 변경하지 않았습니다.';exit 3}
 Save-Scan 'running' '검사 중입니다. 완료될 때까지 기다려 주세요. 위협 조치는 기존 백신 정책을 따릅니다.'
 Start-MpScan -ScanType $Mode -ErrorAction Stop
 $after=Get-MpComputerStatus -ErrorAction Stop
 $ended=if($Mode -eq 'QuickScan'){$after.QuickScanEndTime}else{$after.FullScanEndTime}
 if($ended -and ([datetime]$ended).ToUniversalTime() -ge $started.AddSeconds(-2)){
  Save-Scan 'completed' 'Windows Defender 검사 완료 시각을 확인했습니다. 위협 발견·격리 결과는 Windows 보안의 보호 기록에서 확인해 주세요.'
 }else{Save-Scan 'verification_needed' '검사 요청은 반환되었으나 완료 시각을 확인하지 못했습니다. Windows 보안에서 검사 상태를 확인해 주세요.'}
}catch{Save-Scan 'failed' '검사를 실행하거나 완료 상태를 확인하지 못했습니다. Windows 보안에서 백신 상태와 보호 기록을 확인해 주세요.'}finally{$mutex.ReleaseMutex();$mutex.Dispose()}
