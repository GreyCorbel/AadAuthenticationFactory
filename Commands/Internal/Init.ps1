function Init
{
    param()

    process
    {
        $referencedAssemblies = @('System.Net.Http')
        #load is platform specific
        switch($PSEdition)
        {
            'Core'
            {
                $referencedAssemblies+="System.Net.Primitives"
                $referencedAssemblies+="System.Net.WebProxy"
                $referencedAssemblies+="System.Console"
                
                try {
                    $existingType = [Microsoft.Identity.Client.PublicClientApplication]
                    #compiling http factory against version of preloaded package
                    $referencedAssemblies+=$existingType.Assembly.Location
                }
                catch
                {
                    Add-Type -Path ([Path]::Combine([string[]]($PSScriptRoot,'Shared','netcoreapp3.1','Microsoft.Identity.Client.Desktop.dll')))
                    Add-Type -Path ([Path]::Combine([string[]]($PSScriptRoot,'Shared','net8.0','Microsoft.IdentityModel.Abstractions.dll')))
                    Add-Type -Path ([Path]::Combine([string[]]($PSScriptRoot,'Shared','net8.0','Microsoft.Identity.Client.dll')))
                    #compiling http factory against our version of MSAL library
                    $referencedAssemblies+=[Path]::Combine([string[]]($PSScriptRoot,'Shared','net8.0','Microsoft.Identity.Client.dll'))

                }
                #load WAM broker
                if($null -eq ('Microsoft.Identity.Client.Broker.BrokerExtension' -as [type]))
                {
                    #load assembly resolver helper if not loaded previously
                    <# $helper = 'MsalNativeResolver'
                    if($null -eq ($helper -as [type]))
                    {
                        Write-Verbose "Loading helper $helper"
                        $helperDefinition = Get-Content "$PSScriptRoot\Helpers\$helper.cs" -Raw
                        Add-Type -TypeDefinition $helperDefinition -ReferencedAssemblies $referencedAssemblies -WarningAction SilentlyContinue -IgnoreWarnings
                    } #>

                    $managedPath = [Path]::Combine([string[]]($PSScriptRoot,'Shared','netstandard2.0','Microsoft.Identity.Client.NativeInterop.dll'))
                    $assembly = [System.Reflection.Assembly]::LoadFrom($managedPath)
                    Add-Type -Path ([Path]::Combine([string[]]($PSScriptRoot,'Shared','netstandard2.0','Microsoft.Identity.Client.Broker.dll')))
                    
                    if([RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))
                    {
                        switch($env:PROCESSOR_ARCHITECTURE)
                        {
                            'AMD64' {$runtimePath = [Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-x64','native', 'msalruntime.dll')); break;}
                            'ARM64' {$runtimePath = [Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-arm64','native','msalruntime_arm64.dll')); break;}
                            'X86' {$runtimePath = [Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-x86','native','msalruntime_x86.dll')); break;}
                        }
                        if(-not [string]::IsNullOrEmpty($runtimePath))
                        {
                            #[MsalNativeResolver]::RegisterFor($assembly, $runtimePath)
                            [System.Runtime.InteropServices.NativeLibrary]::Load($runtimePath)
                        }
                    }
                }
                break;
            }
            'Desktop'
            {
                try {
                    $existingType = [Microsoft.Identity.Client.PublicClientApplication]
                    #compiling http factory against version of preloaded package
                    $referencedAssemblies+=$existingType.Assembly.Location
                }
                catch
                {
                    Add-Type -Path ([Path]::Combine([string[]]($PSScriptRoot,'Shared','net462','Microsoft.Identity.Client.Desktop.dll')))
                    Add-Type -Path ([Path]::Combine([string[]]($PSScriptRoot,'Shared','net462','Microsoft.IdentityModel.Abstractions.dll')))
                    Add-Type -Path ([Path]::Combine([string[]]($PSScriptRoot,'Shared','net462','Microsoft.Identity.Client.dll')))
                    $referencedAssemblies+=[Path]::Combine([string[]]($PSScriptRoot,'Shared','net462','Microsoft.Identity.Client.dll'))
                }
                #on Windows, load WAM broker
                if($null -eq ('Microsoft.Identity.Client.Broker.BrokerExtension' -as [type]))
                {
                    if($null -eq ('Kernel32' -as [type]))
                    {
                        Write-Verbose "Loading helper Kernel32"
                        $helperDefinition = Get-Content "$PSScriptRoot\Helpers\Kernel32.cs" -Raw
                        Add-Type -TypeDefinition $helperDefinition -ReferencedAssemblies $referencedAssemblies -WarningAction SilentlyContinue -IgnoreWarnings
                    }
                    if([RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))
                    {
                        Add-Type -Path ([Path]::Combine([string[]]($PSScriptRoot,'Shared','net461','Microsoft.Identity.Client.NativeInterop.dll')))
                        Add-Type -Path ([Path]::Combine([string[]]($PSScriptRoot,'Shared','netstandard2.0','Microsoft.Identity.Client.Broker.dll')))
                        #need to add path to native runtime supporting the broker
                        switch($env:PROCESSOR_ARCHITECTURE)
                        {
                            'AMD64' {$runtimePath = [Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-x64','native','msalruntime.dll')); break;}
                            'ARM64' {$runtimePath = [Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-arm64','native','msalruntime_arm64.dll')); break;}
                            'X86' {$runtimePath = [Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-x86','native','msalruntime_x86.dll')); break;}
                        }
                        if(-not [string]::IsNullOrEmpty($runtimePath))
                        {
                            #$env:Path = "$runtimePath;$($env:Path)"
                            [Kernel32]::LoadLibrary($runtimePath) | Out-Null
                        }
                    }
                }

                #on desktop, this one is not pre-loaded
                Add-Type -Assembly System.Net.Http
        
                #for desktop, we do not use separate app domain (will add if needed)
                break;
            }
        }
        #shall we enforse specific version of TLS?
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        #cache for auth factories. Cache key is factory name
        if($null -eq $script:AadAuthenticationFactories -or -not $script:AadAuthenticationFactories -is [hashtable])
        {
            $script:AadAuthenticationFactories = @{}
        }
        $helpers = 'GcMsalHttpClientFactory', 'DeviceCodeHandler','ParentWindowHelper'
        foreach($helper in $helpers)
        {
            if($null -eq ($helper -as [type]))
            {
                Write-Verbose "Loading helper $helper"
                $helperDefinition = Get-Content "$PSScriptRoot\Helpers\$helper.cs" -Raw
                Add-Type -TypeDefinition $helperDefinition -ReferencedAssemblies $referencedAssemblies -WarningAction SilentlyContinue -IgnoreWarnings
            }
        }

    }
}
