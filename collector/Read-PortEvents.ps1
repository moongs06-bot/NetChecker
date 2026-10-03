function Get-NetCheckerPortEvents {
    $result=@{port_status='unavailable';port_events=@()}
    try {
        $records=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=5156,5157;StartTime=(Get-Date).AddSeconds(-120)} -MaxEvents 101 -ErrorAction Stop)
        $result.port_status=if($records.Count -gt 100){'truncated'}else{'readable_policy_unverified'}
        foreach($record in ($records | Select-Object -First 100)) {
            [xml]$xml=$record.ToXml();$data=@{}
            foreach($item in $xml.Event.EventData.Data){$data[[string]$item.Name]=[string]$item.'#text'}
            if($data.Protocol -ne '6' -and $data.Protocol -ne '17'){continue}
            $source=$null;$dest=$null;$sport=0;$dport=0
            if(-not [Net.IPAddress]::TryParse($data.SourceAddress,[ref]$source) -or -not [Net.IPAddress]::TryParse($data.DestAddress,[ref]$dest)){continue}
            if(-not [int]::TryParse($data.SourcePort,[ref]$sport) -or -not [int]::TryParse($data.DestPort,[ref]$dport)){continue}
            if($sport -lt 0 -or $sport -gt 65535 -or $dport -lt 0 -or $dport -gt 65535){continue}
            $result.port_events+=@{record_id=[string]$record.RecordId;time=$record.TimeCreated.ToUniversalTime().ToString('o');source_ip=($source.ToString() -split '%')[0];destination_ip=($dest.ToString() -split '%')[0];source_port=$sport;destination_port=$dport;protocol=$(if($data.Protocol -eq '6'){'TCP'}else{'UDP'});action=$(if($record.Id -eq 5157){'blocked'}else{'allowed'})}
        }
    } catch {
        if($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound'){$result.port_status='readable_policy_unverified'}
    }
    return $result
}
