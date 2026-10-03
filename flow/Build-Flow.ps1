$ErrorActionPreference='Stop'
$out=Join-Path (Split-Path -Parent $PSScriptRoot) 'collector\flow'
New-Item -ItemType Directory -Path $out -Force | Out-Null
$packages=Join-Path $PSScriptRoot 'packages'
$refs=Join-Path $packages 'Microsoft.NETFramework.ReferenceAssemblies.net48.1.0.3\build\.NETFramework\v4.8'
$frameworks=@('net48','net472','net471','net47','net462','net461','net46','net452','net451','net45','net40','netstandard2.0','netstandard1.3','netstandard1.0')
foreach($package in Get-ChildItem -LiteralPath $packages -Directory){
 foreach($framework in $frameworks){
  $lib=Join-Path $package.FullName ('lib\'+$framework)
  if(Test-Path -LiteralPath $lib){Get-ChildItem -LiteralPath $lib -Filter '*.dll' | Copy-Item -Destination $out -Force;break}
 }
 $license=Get-ChildItem -LiteralPath $package.FullName -File | Where-Object {$_.Name -match 'LICENSE|NOTICE'} | Select-Object -First 1
 if($license){Copy-Item -LiteralPath $license.FullName -Destination (Join-Path $out ($package.Name+'-LICENSE.txt')) -Force}
}
$trace=Join-Path $packages 'Microsoft.Diagnostics.Tracing.TraceEvent.3.1.21'
foreach($native in Get-ChildItem -LiteralPath $trace -Recurse -Filter 'TraceEventNative.dll'){
 if($native.FullName -match 'amd64|win-x64') {New-Item -ItemType Directory -Path (Join-Path $out 'amd64') -Force | Out-Null;Copy-Item -LiteralPath $native.FullName -Destination (Join-Path $out 'amd64\TraceEventNative.dll') -Force}
}
New-Item -ItemType Directory -Path (Join-Path $out 'amd64') -Force | Out-Null
Copy-Item -Path (Join-Path $trace 'build\native\amd64\*.dll') -Destination (Join-Path $out 'amd64') -Force
$argsList=@('/nologo','/target:exe','/platform:x64','/optimize+','/nostdlib+',('/out:"'+(Join-Path $out 'NetChecker.Flow.exe')+'"'))
foreach($dll in Get-ChildItem -LiteralPath $refs -Filter '*.dll'){try{[Reflection.AssemblyName]::GetAssemblyName($dll.FullName) | Out-Null}catch{continue};$argsList+=('/reference:"'+$dll.FullName+'"')}
$argsList+=('/reference:"'+(Join-Path $refs 'Facades\netstandard.dll')+'"')
foreach($dll in Get-ChildItem -LiteralPath $out -Filter '*.dll'){$argsList+=('/reference:"'+$dll.FullName+'"')}
$argsList+=('"'+(Join-Path $PSScriptRoot 'Program.cs')+'"')
$rsp=Join-Path $PSScriptRoot 'build.rsp';$argsList | Set-Content -LiteralPath $rsp -Encoding UTF8
& (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe') /noconfig ('@'+$rsp)
if($LASTEXITCODE -ne 0){throw 'Flow build failed'}
& (Join-Path $out 'NetChecker.Flow.exe') --self-test
if($LASTEXITCODE -ne 0){throw 'Flow self test failed'}
Compress-Archive -Path (Join-Path $out '*') -DestinationPath (Join-Path (Split-Path -Parent $out) 'flow.zip') -Force
