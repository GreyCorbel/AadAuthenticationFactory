function Get-MsalBrokerPlatformConfiguration {
    $runtimeInfoType = 'System.Runtime.InteropServices.RuntimeInformation' -as [type]
    $hasRuntimeInfo = $null -ne $runtimeInfoType -and $null -ne $runtimeInfoType.GetProperty('ProcessArchitecture')

    if ($hasRuntimeInfo) {
        $architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        $isWindowsOS = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
        $isLinuxOS = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)
        $isMacOS = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX)
        $osDescription = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    }
    else {
        # Windows PowerShell on older .NET Framework: always Windows
        $isWindowsOS = $true
        $isLinuxOS = $false
        $isMacOS = $false
        $osDescription = [Environment]::OSVersion.VersionString
        $architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
            'AMD64' { 'X64' }
            'ARM64' { 'Arm64' }
            'x86'   { 'X86' }
            default { $env:PROCESSOR_ARCHITECTURE }
        }
    }

    if ($isWindowsOS) {
        $runtime = switch ($architecture) {
            'X64'   { @{ Rid = 'win-x64'; NativeLibrary = 'msalruntime.dll' } }
            'X86'   { @{ Rid = 'win-x86'; NativeLibrary = 'msalruntime_x86.dll' } }
            'Arm64' { @{ Rid = 'win-arm64'; NativeLibrary = 'msalruntime_arm64.dll' } }
            default { 
                if([Environment]::Is64BitOperatingSystem) {
                    @{ Rid = 'win-x64'; NativeLibrary = 'msalruntime.dll' }
                } else {
                    $null 
                }
            }
        }

        if ($null -eq $runtime) {
            throw [PlatformNotSupportedException]::new(
                "MSAL broker authentication is not supported on Windows architecture '$architecture'. Supported architectures: X64, X86, Arm64."
            )
        }

        return [pscustomobject]@{
            OperatingSystem = 'Windows'
            Architecture = $architecture
            RuntimeIdentifier = $runtime.Rid
            NativeLibraryFileName = $runtime.NativeLibrary
            BrokerOperatingSystem = [Microsoft.Identity.Client.BrokerOptions+OperatingSystems]::Windows
            RedirectUri = $null
            UseDefaultRedirectUri = $true
            UseParentWindow = $true
            ListOperatingSystemAccounts = $true
        }
    }

    if ($isLinuxOS) {
        if ($architecture -ne 'X64') {
            throw [PlatformNotSupportedException]::new(
                "MSAL broker authentication is not supported on Linux architecture '$architecture' because the bundled native runtime only supports X64."
            )
        }

        return [pscustomobject]@{
            OperatingSystem = 'Linux'
            Architecture = $architecture
            RuntimeIdentifier = 'linux-x64'
            NativeLibraryFileName = 'libmsalruntime.so'
            BrokerOperatingSystem = [Microsoft.Identity.Client.BrokerOptions+OperatingSystems]::Linux
            RedirectUri = $null
            UseDefaultRedirectUri = $true
            UseParentWindow = $false
            ListOperatingSystemAccounts = $true
        }
    }

    if ($isMacOS) {
        $runtime = switch ($architecture) {
            'X64'   { @{ Rid = 'osx-x64'; NativeLibrary = 'msalruntime.dylib' } }
            'Arm64' { @{ Rid = 'osx-arm64'; NativeLibrary = 'msalruntime_arm64.dylib' } }
            default { $null }
        }

        if ($null -eq $runtime) {
            throw [PlatformNotSupportedException]::new(
                "MSAL broker authentication is not supported on macOS architecture '$architecture'. Supported architectures: X64, Arm64."
            )
        }

        return [pscustomobject]@{
            OperatingSystem = 'macOS'
            Architecture = $architecture
            RuntimeIdentifier = $runtime.Rid
            NativeLibraryFileName = $runtime.NativeLibrary
            BrokerOperatingSystem = [Microsoft.Identity.Client.BrokerOptions+OperatingSystems]::OSX
            RedirectUri = 'msauth.com.msauth.unsignedapp://auth'
            UseDefaultRedirectUri = $false
            UseParentWindow = $false
            ListOperatingSystemAccounts = $false
        }
    }

    throw [PlatformNotSupportedException]::new(
        "MSAL broker authentication is not supported on operating system '$osDescription'."
    )
}
