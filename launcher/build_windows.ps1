# Build with the Windows .NET Framework compiler; no download/build cache required.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Windows .NET Framework 4.x compiler unavailable. Install the supported .NET Framework developer tools.' }
$icon = Join-Path $projectRoot 'app/static/images/branding/favicon.ico'
$source = Join-Path $PSScriptRoot 'SpectreLauncher.cs'
$destination = Join-Path $projectRoot 'SPECTRE.exe'
& $compiler /nologo /target:winexe /optimize+ /platform:anycpu /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll "/win32icon:$icon" "/out:$destination" $source
if ($LASTEXITCODE -ne 0) { throw 'Launcher build failed.' }
Write-Output "Built $destination"
