using namespace System.IO

param(
    [Parameter(Mandatory)]
    [string]$RootPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dependencyProject = [Path]::Combine($RootPath, 'Workflow', 'Dependencies.csproj')
$packagesDir = [Path]::Combine($RootPath, 'packages')
$modulePath = [Path]::Combine($RootPath, 'Module', 'AadAuthenticationFactory')
$sharedPath = [Path]::Combine($modulePath, 'shared')

if (-not (Test-Path -LiteralPath $dependencyProject -PathType Leaf)) {
    throw "Dependency project not found at '$dependencyProject'."
}

& dotnet restore $dependencyProject --packages $packagesDir --nologo
if ($LASTEXITCODE -ne 0) {
    throw "dotnet restore failed with exit code $LASTEXITCODE."
}

$packageReferences = ([xml](Get-Content -LiteralPath $dependencyProject -Raw)).
    Project.ItemGroup.PackageReference
$targetFrameworks = @('net462', 'netstandard2.0')

foreach ($targetFramework in $targetFrameworks) {
    New-Item -ItemType Directory -Path ([Path]::Combine($sharedPath, $targetFramework)) -Force | Out-Null
}

foreach ($packageReference in $packageReferences) {
    $packageId = [string]$packageReference.Include
    $packageVersion = [string]$packageReference.Version
    $packageFolder = [Path]::Combine(
        $packagesDir,
        $packageId.ToLowerInvariant(),
        $packageVersion.ToLowerInvariant()
    )

    if (-not (Test-Path -LiteralPath $packageFolder -PathType Container)) {
        throw "Restored package '$packageId' version '$packageVersion' was not found at '$packageFolder'."
    }

    Write-Host "Processing: $packageId - $packageVersion"
    $copiedAssembly = $false

    foreach ($targetFramework in $targetFrameworks) {
        $assemblyPath = [Path]::Combine($packageFolder, 'lib', $targetFramework, "$packageId.dll")
        if (Test-Path -LiteralPath $assemblyPath -PathType Leaf) {
            Copy-Item -LiteralPath $assemblyPath -Destination ([Path]::Combine($sharedPath, $targetFramework)) -Force
            $copiedAssembly = $true
            Write-Host "   $targetFramework"
        }
    }

    if (-not $copiedAssembly) {
        throw "Package '$packageId' version '$packageVersion' does not contain a supported module assembly."
    }
}

$nativeInteropReference = $packageReferences |
    Where-Object Include -EQ 'Microsoft.Identity.Client.NativeInterop' |
    Select-Object -First 1

if ($null -eq $nativeInteropReference) {
    throw 'Microsoft.Identity.Client.NativeInterop is missing from the dependency project.'
}

$nativeInteropFolder = [Path]::Combine(
    $packagesDir,
    ([string]$nativeInteropReference.Include).ToLowerInvariant(),
    ([string]$nativeInteropReference.Version).ToLowerInvariant()
)
$runtimeSource = [Path]::Combine($nativeInteropFolder, 'runtimes')

if (-not (Test-Path -LiteralPath $runtimeSource -PathType Container)) {
    throw "MSAL native runtime directory was not restored at '$runtimeSource'."
}

Copy-Item -LiteralPath $runtimeSource -Destination $modulePath -Recurse -Force

$requiredNativeAssets = @(
    @('linux-x64', 'libmsalruntime.so'),
    @('osx-arm64', 'msalruntime_arm64.dylib'),
    @('osx-x64', 'msalruntime.dylib'),
    @('win-arm64', 'msalruntime_arm64.dll'),
    @('win-x64', 'msalruntime.dll'),
    @('win-x86', 'msalruntime_x86.dll')
)

foreach ($asset in $requiredNativeAssets) {
    $assetPath = [Path]::Combine($modulePath, 'runtimes', $asset[0], 'native', $asset[1])
    if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) {
        throw "Required MSAL native runtime asset is missing at '$assetPath'."
    }
}

Write-Host 'Module dependencies restored successfully.'
