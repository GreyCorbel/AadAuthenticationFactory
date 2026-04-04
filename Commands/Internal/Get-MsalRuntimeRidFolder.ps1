function Get-MsalRuntimeRidFolder {
    # returns one of: win-x64, win-x86, win-arm64, linux-x64, linux-arm64, osx-x64, osx-arm64
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture

    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
        switch ($arch) {
            'X64'   { return 'win-x64' }
            'X86'   { return 'win-x86' }
            'Arm64' { return 'win-arm64' }
            default { return 'win-x64' }
        }
    }
    elseif ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)) {
        switch ($arch) {
            'X64'   { return 'linux-x64' }
            'Arm64' { return 'linux-arm64' }
            default { return 'linux-x64' }
        }
    }
    elseif ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX)) {
        switch ($arch) {
            'X64'   { return 'osx-x64' }
            'Arm64' { return 'osx-arm64' }
            default { return 'osx-x64' }
        }
    }

    return $null
}