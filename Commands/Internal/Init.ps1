function Init
{
    param()

    process
    {
        $referencedAssemblies = @('System.Net.Http')
        #load platform specific
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
                    Add-Type -Path ([System.IO.Path]::Combine([string[]]($PSScriptRoot,'Shared','net6.0','Microsoft.IdentityModel.Abstractions.dll')))
                    Add-Type -Path ([System.IO.Path]::Combine([string[]]($PSScriptRoot,'Shared','net6.0','Microsoft.Identity.Client.dll')))
                    #compiling http factory against our version
                    $referencedAssemblies+=[System.IO.Path]::Combine([string[]]($PSScriptRoot,'Shared','net6.0','Microsoft.Identity.Client.dll'))

                }
                #on Windows, load WAM broker
                if($null -eq ('Microsoft.Identity.Client.Broker.BrokerExtension' -as [type]))
                {
                    Add-Type -Path ([System.IO.Path]::Combine([string[]]($PSScriptRoot,'Shared','netstandard2.0','Microsoft.Identity.Client.Broker.dll')))
                    if([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))
                    {
                        switch($env:PROCESSOR_ARCHITECTURE)
                        {
                            'AMD64' {$runtimePath = [System.IO.Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-x64','native')); break;}
                            'ARM64' {$runtimePath = [System.IO.Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-arm64','native')); break;}
                            'X86' {$runtimePath = [System.IO.Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-x86','native')); break;}
                        }
                        if(-not [string]::IsNullOrEmpty($runtimePath))
                        {
                            $env:Path = "$($env:Path);$runtimePath"
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
                    Add-Type -Path ([System.IO.Path]::Combine([string[]]($PSScriptRoot,'Shared','net461','Microsoft.IdentityModel.Abstractions.dll')))
                    Add-Type -Path ([System.IO.Path]::Combine([string[]]($PSScriptRoot,'Shared','net461','Microsoft.Identity.Client.dll')))
                    $referencedAssemblies+=[System.IO.Path]::Combine([string[]]($PSScriptRoot,'Shared','net461','Microsoft.Identity.Client.dll'))
                }
                #on Windows, load WAM broker
                if($null -eq ('Microsoft.Identity.Client.Broker.BrokerExtension' -as [type]))
                {
                    if([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))
                    {
                        Add-Type -Path ([System.IO.Path]::Combine([string[]]($PSScriptRoot,'Shared','net461','Microsoft.Identity.Client.Broker.dll')))
                        #need to add path to native runtime supporting the broker
                        switch($env:PROCESSOR_ARCHITECTURE)
                        {
                            'AMD64' {$runtimePath = [System.IO.Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-x64','native')); break;}
                            'ARM64' {$runtimePath = [System.IO.Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-arm64','native')); break;}
                            'X86' {$runtimePath = [System.IO.Path]::Combine([string[]]($PSScriptRoot,'Runtimes','win-x86','native')); break;}
                        }
                        if(-not [string]::IsNullOrEmpty($runtimePath))
                        {
                            $env:Path = "$($env:Path);$runtimePath"
                        }
                    }
                }

                #on desktop, this one is not pre-loaded
                Add-Type -Assembly System.Net.Http
        
                #for desktop, we do not use separate app domain (will add if needed)
                break;
            }
        }

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        #Add JIT compiled helpers. Load only if not loaded previously
        $helpers = 'GcMsalHttpClientFactory', 'DeviceCodeHandler','ParentWindowHelper'
        foreach($helper in $helpers)
        {
            if($null -eq ($helper -as [type]))
            {
                $helperDefinition = Get-Content "$PSScriptRoot\Helpers\$helper.cs" -Raw
                Add-Type -TypeDefinition $helperDefinition -ReferencedAssemblies $referencedAssemblies -WarningAction SilentlyContinue -IgnoreWarnings
            }
        }

        if($null -eq $script:AadAuthenticationFactories -or -not $script:AadAuthenticationFactories -is [hashtable])
        {
            $script:AadAuthenticationFactories = @{}
        }
    }
}
