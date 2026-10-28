param(
    [string] $RootPath = (Split-Path -Parent $PSScriptRoot),
    [ValidateSet('osx-arm64', 'osx-x64')]
    [string[]] $RuntimeIdentifier = @('osx-arm64', 'osx-x64')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::OSX
)) {
    throw 'Building the native broker launchers requires macOS and Xcode Command Line Tools.'
}
$RootPath = (Resolve-Path -LiteralPath $RootPath).Path
$projectPath = Join-Path $RootPath 'MacBroker' 'MacBroker.csproj'
$binPath = Join-Path $RootPath 'Module' 'AadAuthenticationFactory' 'bin'
$stagingPath = Join-Path $RootPath 'MacBroker' 'obj' 'module-publish'
& dotnet publish $projectPath --configuration Release --self-contained false `
    --output $stagingPath --nologo
if ($LASTEXITCODE -ne 0) {
    throw "Publishing the macOS broker assembly failed with exit code $LASTEXITCODE."
}
New-Item -ItemType Directory -Path $binPath -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $stagingPath 'AadAuthenticationFactory.MacBroker.dll') -Destination $binPath -Force

foreach ($rid in $RuntimeIdentifier) {
    $outputPath = Join-Path $binPath $rid
    # Replace the previous self-contained output; this directory is build-owned.
    if (Test-Path -LiteralPath $outputPath) {
        Remove-Item -LiteralPath $outputPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    $executable = Join-Path $outputPath 'AadAuthenticationFactory.MacBroker'
    $architecture = if ($rid -eq 'osx-arm64') { 'arm64' } else { 'x86_64' }
    & clang++ '-std=c++17' -Wall -Wextra -Werror -arch $architecture '-mmacosx-version-min=12.0' `
        (Join-Path $RootPath 'MacBroker' 'Host.cpp') -o $executable
    if ($LASTEXITCODE -ne 0) {
        throw "Building the macOS broker launcher for '$rid' failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "The published macOS broker executable is missing at '$executable'."
    }
}
