function Resolve-MsalSharedDirForCore {
    param([Parameter(Mandatory)][string]$ModuleRoot)

    # Prefer netstandard2.0 for PS7.3+ compatibility
    $ns2 = Join-Path $ModuleRoot 'Shared\netstandard2.0'
    $ns2Msal = Join-Path $ns2 'Microsoft.Identity.Client.dll'

    if (Test-Path $ns2Msal) {
        return $ns2
    }

    # Optional: if you run on .NET 8+ you may choose net8.0
    $net8 = Join-Path $ModuleRoot 'Shared\net8.0'
    $net8Msal = Join-Path $net8 'Microsoft.Identity.Client.dll'
    if (Test-Path $net8Msal) {
        Write-Warning "Shared\netstandard2.0\Microsoft.Identity.Client.dll not found. Falling back to Shared\net8.0. This may not work on PS7.3 if host runtime is not .NET 8."
        return $net8
    }

    throw "No compatible MSAL found. Expected at least $ns2Msal (recommended) or $net8Msal."
}
