using namespace System.IO

param(
    [Parameter(Mandatory)]
    [string]$RootPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dependencyProject = [Path]::Combine($RootPath, 'Workflow', 'Core', 'Dependencies.csproj')
$desktopDependencyProject = [Path]::Combine($RootPath, 'Workflow', 'Desktop', 'Dependencies.csproj')
$packagesDir = [Path]::Combine($RootPath, 'packages')
$modulePath = [Path]::Combine($RootPath, 'Module', 'AadAuthenticationFactory')
$sharedPath = [Path]::Combine($modulePath, 'shared')

foreach ($project in @($dependencyProject, $desktopDependencyProject)) {
    if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
        throw "Dependency project not found at '$project'."
    }

    & dotnet restore $project --packages $packagesDir --nologo
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet restore for '$project' failed with exit code $LASTEXITCODE."
    }
}

$packageReferences = ([xml](Get-Content -LiteralPath $dependencyProject -Raw)).
    Project.ItemGroup.PackageReference
$desktopPackageReferences = ([xml](Get-Content -LiteralPath $desktopDependencyProject -Raw)).
    Project.ItemGroup.PackageReference
$desktopPackageIds = @($desktopPackageReferences | ForEach-Object { [string]$_.Include })
$targetFrameworks = @('net462', 'netstandard2.0')
# These packages only ship netstandard2.0 managed assemblies.
$netStandardOnlyPackages = @('Microsoft.Identity.Client.Broker', 'Microsoft.Identity.Client.NativeInterop')

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
        if ($targetFramework -eq 'net462' -and $packageId -in $desktopPackageIds) {
            continue
        }

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

foreach ($packageReference in $desktopPackageReferences) {
    $packageId = [string]$packageReference.Include
    $packageVersion = [string]$packageReference.Version
    $assemblyFramework = 'net462'
    if ($packageId -in $netStandardOnlyPackages) {
        $assemblyFramework = 'netstandard2.0'
    }

    $assemblyPath = [Path]::Combine(
        $packagesDir,
        $packageId.ToLowerInvariant(),
        $packageVersion.ToLowerInvariant(),
        'lib',
        $assemblyFramework,
        "$packageId.dll"
    )
    if (-not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) {
        throw "Desktop package '$packageId' version '$packageVersion' assembly was not found at '$assemblyPath'."
    }

    Copy-Item -LiteralPath $assemblyPath -Destination ([Path]::Combine($sharedPath, 'net462')) -Force
    Write-Host "Processing Desktop: $packageId - $packageVersion ($assemblyFramework)"
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
