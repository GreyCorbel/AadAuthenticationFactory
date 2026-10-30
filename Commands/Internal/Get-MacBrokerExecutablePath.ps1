function Get-MacBrokerExecutablePath {
    param([Parameter(Mandatory)] [string] $ModuleRoot)

    $platform = Get-MsalBrokerPlatformConfiguration
    if ($platform.OperatingSystem -ne 'macOS') {
        throw [PlatformNotSupportedException]::new('The Mac broker helper can only run on macOS.')
    }
    $path = [Path]::Combine(
        $ModuleRoot, 'bin', $platform.RuntimeIdentifier, 'AadAuthenticationFactory.MacBroker'
    )
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw [System.IO.FileNotFoundException]::new(
            "The macOS broker helper is missing at '$path'. Build it with Workflow/BuildMacBroker.ps1 or reinstall the complete module.",
            $path
        )
    }
    foreach ($requiredPath in @(
        [Path]::Combine($ModuleRoot, 'bin', 'AadAuthenticationFactory.MacBroker.dll'),
        [Path]::Combine($PSHOME, 'libcoreclr.dylib')
    )) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw [System.IO.FileNotFoundException]::new(
                "The macOS broker requires the helper assembly and the calling PowerShell's .NET runtime. Missing file: '$requiredPath'.",
                $requiredPath
            )
        }
    }

    # PowerShell Gallery extraction does not reliably preserve Unix executable bits.
    & /bin/test -x $path
    if ($LASTEXITCODE -ne 0) {
        & /bin/chmod u+x $path
        if ($LASTEXITCODE -ne 0) {
            throw [System.IO.IOException]::new("Unable to set the executable permission on '$path'.")
        }
    }
    return $path
}
