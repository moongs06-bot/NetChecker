param([string]$ConfigPath = "$PSScriptRoot\config.json")
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$queuePath = Join-Path $PSScriptRoot 'queue'
New-Item -ItemType Directory -Path $queuePath -Force | Out-Null
$previous = @{}; $previousAt = $null
$flowProcess=$null; $flowLease=Join-Path $PSScriptRoot 'flow-approval.lease'
. (Join-Path $PSScriptRoot 'Read-PortEvents.ps1')
while ($true) {
    if ($config.installation_id) {
        try {
            $ips=@(); $macs=@()
            foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
                if ($nic.OperationalStatus -ne 'Up' -or $nic.NetworkInterfaceType -eq 'Loopback' -or $nic.NetworkInterfaceType -eq 'Tunnel') { continue }
                $mac=$nic.GetPhysicalAddress().ToString()
                if ($mac.Length -eq 12) { $macs += $mac }
                foreach ($item in $nic.GetIPProperties().UnicastAddresses) {
                    $addr=($item.Address.ToString() -split '%')[0]
                    if ($addr -ne '127.0.0.1' -and $addr -ne '::1') { $ips += $addr }
                }
            }
            $reg=@{installation_id=$config.installation_id;token=$config.token;hostname=$env:COMPUTERNAME;ips=@($ips | Select-Object -Unique -First 32);macs=@($macs | Select-Object -Unique -First 32);os_name=[Environment]::OSVersion.VersionString}
            $payload=[Text.Encoding]::UTF8.GetBytes(($reg | ConvertTo-Json -Depth 4 -Compress))
            $approval=Invoke-RestMethod -Uri ($config.server.TrimEnd('/')+'/api/enrollment/request') -Method Post -ContentType 'application/json' -Body $payload -TimeoutSec 10
            if ($approval.status -ne 'approved') { Remove-Item -LiteralPath $flowLease -Force -ErrorAction SilentlyContinue; $previous=@{}; $previousAt=$null; Start-Sleep -Seconds 60; continue }
        } catch { Remove-Item -LiteralPath $flowLease -Force -ErrorAction SilentlyContinue; $previous=@{}; $previousAt=$null; Start-Sleep -Seconds 60; continue }
    }
    $flowWindow=$null; $flowFile=$null; $flowStatus='not_collected'
    $helper=Join-Path $PSScriptRoot 'flow\NetChecker.Flow.exe'
    if (Test-Path -LiteralPath $helper) {
        try {
            [IO.File]::WriteAllText($flowLease,[DateTime]::UtcNow.ToString('o'))
            if(-not $flowProcess -or $flowProcess.HasExited){$flowProcess=Start-Process -FilePath $helper -ArgumentList ('"'+$PSScriptRoot+'"') -WindowStyle Hidden -PassThru}
            $flowStatus='waiting'
            $statusPath=Join-Path $PSScriptRoot 'flow-status.json'
            if(Test-Path -LiteralPath $statusPath){$fs=Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json; if(([DateTime]::UtcNow-[DateTime]::Parse($fs.updated_at).ToUniversalTime()).TotalSeconds -lt 150){$flowStatus=$fs.status}}
            $flowFile=Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'flow-windows') -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First 1
            if($flowFile){
                $flowWindow=Get-Content -LiteralPath $flowFile.FullName -Raw | ConvertFrom-Json
                $flowEnd=[DateTime]::Parse($flowWindow.ended_at).ToUniversalTime()
                $span=($flowEnd-[DateTime]::Parse($flowWindow.started_at).ToUniversalTime()).TotalSeconds
                if($span -le 0 -or $span -gt 180 -or ([DateTime]::UtcNow-$flowEnd).TotalDays -ge 2){Remove-Item -LiteralPath $flowFile.FullName -Force;$flowWindow=$null;$flowFile=$null;$flowStatus='unavailable'}
            }
        } catch {$flowWindow=$null; $flowFile=$null; $flowStatus='unavailable'}
    }
    $portData=Get-NetCheckerPortEvents
    $started = [DateTime]::UtcNow
    $tx = 0L; $rx = 0L; $valid = $false
    try {
        $current = @{}
        $interfaces = [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' -and $_.NetworkInterfaceType -ne 'Tunnel' }
        foreach ($nic in $interfaces) {
            $s = $nic.GetIPStatistics()
            $current[$nic.Id] = @([long]$s.BytesSent, [long]$s.BytesReceived)
            if ($previous.ContainsKey($nic.Id)) {
                $a = $s.BytesSent - $previous[$nic.Id][0]; $b = $s.BytesReceived - $previous[$nic.Id][1]
                if ($a -ge 0 -and $b -ge 0) { $tx += $a; $rx += $b; $valid = $true }
            }
        }
        $previous = $current
    } catch { $valid = $false }
    $interval = 0
    if ($previousAt) { $interval = ($started - $previousAt).TotalSeconds }
    if ($interval -gt 3600 -or $interval -le 0) { $valid = $false; $interval = 0; $tx = 0; $rx = 0 }
    $previousAt = $started
    $cpu = 0; $memory = 0; $disk = 0; $resourcesOk = $false
    try {
        $cpu = [double](Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
        $os = Get-CimInstance Win32_OperatingSystem
        $memory = 100 * (1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize)
        $drives = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Where-Object { $_.Size -gt 0 }
        $disk = [double](($drives | ForEach-Object { 100 * (1 - $_.FreeSpace / $_.Size) }) | Measure-Object -Maximum).Maximum
        $resourcesOk = $true
    } catch {}
    $connections = @(); $total = 0; $connectionsOk = $false
    try {
        $rows = @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { $_.RemotePort -gt 0 })
        $total = $rows.Count
        $names = @{}; Get-Process | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
        $connections = @($rows | Select-Object -First 250 | ForEach-Object {
            $name = $names[[int]$_.OwningProcess]; if (-not $name) { $name = 'unknown' }
            @{ remote_ip = ($_.RemoteAddress -split '%')[0]; remote_port = [int]$_.RemotePort; process = $name.Substring(0,[Math]::Min(100,$name.Length)); state = 'Established' }
        })
        $connectionsOk = $true
    } catch {}
    $batch = [guid]::NewGuid().ToString()
    $sample = @{ batch_id=$batch; observed_at=$started.ToString('o'); interval_seconds=$interval; tx_bytes=$tx; rx_bytes=$rx; counter_valid=$valid; cpu_percent=0; memory_percent=0; disk_percent=0; connections=$connections; connections_total=$total; connection_collection_ok=$connectionsOk; resource_collection_ok=$resourcesOk; collector_version='0.3.0';flow_window=$flowWindow;flow_status=$flowStatus;port_events=@($portData.port_events);port_status=$portData.port_status }
    # PowerShell 5.1 does not support Math.Clamp; values below are bounded without it.
    $sample.cpu_percent = [Math]::Min(100,[Math]::Max(0,$cpu))
    $sample.memory_percent = [Math]::Min(100,[Math]::Max(0,$memory))
    $sample.disk_percent = [Math]::Min(100,[Math]::Max(0,$disk))
    try {
        $json = $sample | ConvertTo-Json -Depth 6 -Compress
        [IO.File]::WriteAllText((Join-Path $queuePath "$($started.Ticks)-$batch.json"),$json,(New-Object Text.UTF8Encoding($false)))
        if($flowFile){Remove-Item -LiteralPath $flowFile.FullName -Force -ErrorAction SilentlyContinue}
        $files = @(Get-ChildItem -LiteralPath $queuePath -Filter '*.json' | Sort-Object Name)
        # Bound retry storage to 120 samples (about 2 hours), never infinite growth.
        if ($files.Count -gt 120) { $files | Select-Object -First ($files.Count-120) | Remove-Item -Force }
        foreach ($file in @(Get-ChildItem -LiteralPath $queuePath -Filter '*.json' | Sort-Object Name | Select-Object -First 4)) {
            try {
                $body = [IO.File]::ReadAllBytes($file.FullName)
                Invoke-RestMethod -Uri ($config.server.TrimEnd('/')+'/api/ingest') -Method Post -Headers @{Authorization='Bearer '+$config.token} -ContentType 'application/json' -Body $body -TimeoutSec 10 | Out-Null
                Remove-Item -LiteralPath $file.FullName -Force
            } catch { break }
        }
    } catch {}
    $elapsed = ([DateTime]::UtcNow - $started).TotalSeconds
    Start-Sleep -Seconds ([Math]::Max(1,60-[int]$elapsed))
}

