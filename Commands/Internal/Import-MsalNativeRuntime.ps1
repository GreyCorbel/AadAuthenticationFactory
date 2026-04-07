function Import-MsalNativeRuntime {
    param(
        [Parameter(Mandatory)] [string] $ModuleRoot
    )

    $rid = Get-MsalRuntimeRidFolder
    if ([string]::IsNullOrEmpty($rid)) { return }

    # IMPORTANT: your folder is lowercase "runtimes"
    $nativeDir = [Path]::Join($ModuleRoot, 'runtimes', $rid, 'native')
    if (-not (Test-Path $nativeDir)) { return }

    $candidate = Get-ChildItem -Path $nativeDir -File |
        Where-Object {
            $_.Name -match '^msalruntime' -and $_.Extension -in @('.dll','.so','.dylib')
        } |
        Select-Object -First 1

    if (-not $candidate) {
        Write-Verbose "MSAL native runtime not found in $nativeDir"
        return
    }

    if ($PSEdition -eq 'Core') {
        [System.Runtime.InteropServices.NativeLibrary]::Load($candidate.FullName) | Out-Null
    }
    else {
        # Windows PowerShell 5.1 is Windows-only; LoadLibrary is fine
        if ($null -eq ('Kernel32' -as [type])) {
            $helperPath = [Path]::Join($ModuleRoot, 'Helpers', 'Kernel32.cs')
            $helperDefinition = Get-Content $helperPath -Raw
            Add-Type -TypeDefinition $helperDefinition -ReferencedAssemblies @('System.Runtime.InteropServices') -WarningAction SilentlyContinue -IgnoreWarnings
        }
        [Kernel32]::LoadLibrary($candidate.FullName) | Out-Null
    }

    Write-Verbose "Loaded MSAL native runtime: $($candidate.FullName)"
}