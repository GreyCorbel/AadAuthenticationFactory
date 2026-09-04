function Import-MsalNativeRuntime {
    param(
        [Parameter(Mandatory)] [string] $ModuleRoot
    )

    $platform = Get-MsalBrokerPlatformConfiguration
    $nativePath = [Path]::Combine(
        $ModuleRoot,
        'runtimes',
        $platform.RuntimeIdentifier,
        'native',
        $platform.NativeLibraryFileName
    )

    if (-not (Test-Path -LiteralPath $nativePath -PathType Leaf)) {
        throw [System.IO.FileNotFoundException]::new(
            "MSAL broker native runtime is missing for OS '$($platform.OperatingSystem)', architecture '$($platform.Architecture)', RID '$($platform.RuntimeIdentifier)'. Expected file: '$nativePath'.",
            $nativePath
        )
    }

    if ($script:MsalNativeRuntimePath -eq $nativePath -and $script:MsalNativeRuntimeHandle -ne [IntPtr]::Zero) {
        return $platform
    }

    try {
        if ($PSEdition -eq 'Core') {
            $nativeHandle = [System.Runtime.InteropServices.NativeLibrary]::Load($nativePath)
        }
        else {
            if ($null -eq ('Kernel32' -as [type])) {
                $helperPath = [Path]::Combine($ModuleRoot, 'Helpers', 'Kernel32.cs')
                $helperDefinition = Get-Content $helperPath -Raw
                Add-Type -TypeDefinition $helperDefinition -ReferencedAssemblies @('System.Runtime.InteropServices') -WarningAction SilentlyContinue -IgnoreWarnings
            }

            $nativeHandle = [Kernel32]::LoadLibrary($nativePath)
            if ($nativeHandle -eq [IntPtr]::Zero) {
                $errorCode = [Kernel32]::GetLastError()
                throw [System.ComponentModel.Win32Exception]::new([int]$errorCode)
            }
        }
    }
    catch {
        $message = "Failed to load MSAL broker native runtime for OS '$($platform.OperatingSystem)', architecture '$($platform.Architecture)', RID '$($platform.RuntimeIdentifier)' from '$nativePath'. $($_.Exception.Message)"
        throw [System.DllNotFoundException]::new($message, $_.Exception)
    }

    $script:MsalNativeRuntimePath = $nativePath
    $script:MsalNativeRuntimeHandle = $nativeHandle
    Write-Information "Loaded MSAL native runtime: $nativePath"

    return $platform
}