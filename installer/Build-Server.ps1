$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { $compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$options=@('/nologo','/target:winexe','/platform:anycpu','/optimize+','/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll',('/win32manifest:'+(Join-Path $PSScriptRoot 'app.manifest')),('/out:'+(Join-Path $root 'NetChecker-Server-Setup.exe')))
foreach($name in @('Install-NetChecker.ps1','Collector.ps1','Uninstall-NetChecker.ps1','Read-PortEvents.ps1','flow.zip')) {$options+=('/resource:'+(Join-Path $root ('collector\'+$(if($name -eq 'Collector.ps1'){'Collector-Server.ps1'}else{$name})))+','+$name)}
& $compiler @options (Join-Path $PSScriptRoot 'Setup-Server.cs')
if($LASTEXITCODE -ne 0){throw 'Installer build failed'}
Get-FileHash -LiteralPath (Join-Path $root 'NetChecker-Server-Setup.exe') -Algorithm SHA256 | Format-List
