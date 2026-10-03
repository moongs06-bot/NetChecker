$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
Push-Location (Split-Path -Parent $PSScriptRoot)
try{
 & $compiler /nologo /target:winexe /platform:anycpu /optimize+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /out:collector\NetChecker-Defender.exe installer\DefenderApp.cs
 if($LASTEXITCODE -ne 0){throw 'UI build failed'}
 $options=@('/nologo','/target:winexe','/platform:anycpu','/optimize+','/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/win32manifest:installer\app.manifest','/out:NetChecker-Defender-Setup.exe')
 foreach($name in @('Install-Defender.ps1','Collector-Defender.ps1','Uninstall-Defender.ps1','Install-NetChecker.ps1','Collector.ps1','Uninstall-NetChecker.ps1','Read-PortEvents.ps1','flow.zip','NetChecker-Defender.exe','Actions-Defender.ps1','Inventory-Defender.ps1','Scan-Defender.ps1')){$file=if($name -eq 'Collector.ps1' -and (Test-Path -LiteralPath 'collector\Collector-Server.ps1')){'Collector-Server.ps1'}else{$name};$options+=('/resource:collector\'+$file+','+$name)}
 & $compiler @options installer\Setup-Defender.cs
 if($LASTEXITCODE -ne 0){throw 'Installer build failed'}
 Get-FileHash NetChecker-Defender-Setup.exe -Algorithm SHA256
}finally{Pop-Location}
