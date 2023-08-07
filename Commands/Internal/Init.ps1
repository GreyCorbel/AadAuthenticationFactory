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
                $referencedAssemblies+="$PSHome\System.Net.Primitives.dll"
                $referencedAssemblies+="System.Net.WebProxy"
                $referencedAssemblies+="System.Console"
                
                try {
                    $existingType = [Microsoft.Identity.Client.PublicClientApplication]
                    #compiling http factory against version of preloaded package
                    $referencedAssemblies+=$existingType.Assembly.Location
                }
                catch
                {
                    Add-Type -Path "$PSScriptRoot\Shared\net6.0\Microsoft.IdentityModel.Abstractions.dll"
                    Add-Type -Path "$PSScriptRoot\Shared\net6.0\Microsoft.Identity.Client.dll"
                    #compiling http factory against our version
                    $referencedAssemblies+="$PSScriptRoot\Shared\net6.0\Microsoft.Identity.Client.dll"

                }
                try {
                    $existingType = [Microsoft.Identity.Client.Broker.BrokerExtension]
                }
                catch
                {
                    Add-Type -Path "$PSScriptRoot\Shared\netstandard2.0\Microsoft.Identity.Client.Broker.dll"
                    switch($env:PROCESSOR_ARCHITECTURE)
                    {
                        'AMD64' {$runtimePath = "$PSScriptRoot\Runtimes\win-x64\native"; break;}
                        'ARM64' {$runtimePath = "$PSScriptRoot\Runtimes\win-arm64\native"; break;}
                        'X86' {$runtimePath = "$PSScriptRoot\Runtimes\win-x86\native"; break;}
                    }
                    if(-not [string]::IsNullOrEmpty($runtimePath))
                    {
                        $env:Path = "$($env:Path);$runtimePath"
                    }
                }

                break;
            }
            'Desktop'
            {
                $referencedAssemblies+="$PSScriptRoot\Shared\net461\Microsoft.Identity.Client.dll"
                #only load when not present
                try {
                    [Microsoft.Identity.Client.PublicClientApplication] | Out-Null
                }
                catch
                {
                    Add-Type -Path "$PSScriptRoot\Shared\net461\Microsoft.IdentityModel.Abstractions.dll"
                    Add-Type -Path "$PSScriptRoot\Shared\net461\Microsoft.Identity.Client.dll"
                }
                try {
                    $existingType = [Microsoft.Identity.Client.Broker.BrokerExtension]
                }
                catch
                {
                    Add-Type -Path "$PSScriptRoot\Shared\net461\Microsoft.Identity.Client.Broker.dll"
                    #need to add path to native runtime supporting the broker
                    switch($env:PROCESSOR_ARCHITECTURE)
                    {
                        'AMD64' {$runtimePath = "$PSScriptRoot\Runtimes\win-x64\native"; break;}
                        'ARM64' {$runtimePath = "$PSScriptRoot\Runtimes\win-arm64\native"; break;}
                        'X86' {$runtimePath = "$PSScriptRoot\Runtimes\win-x86\native"; break;}
                    }
                    if(-not [string]::IsNullOrEmpty($runtimePath))
                    {
                        $env:Path = "$($env:Path);$runtimePath"
                    }
                }

                #on desktop, this one is not pre-loaded
                Add-Type -Assembly System.Net.Http
        
                #for desktop, we do not use separate app domain (will add if needed)
                break;
            }
        }

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        #check if we need to load or already loaded
        if($null -eq ('GcMsalHttpClientFactory' -as [type])) {
            $httpFactoryDefinition = Get-Content "$PSScriptRoot\Helpers\GcMsalHttpClientFactory.cs" -Raw
            Add-Type -TypeDefinition $httpFactoryDefinition -ReferencedAssemblies $referencedAssemblies -WarningAction SilentlyContinue -IgnoreWarnings
        }
        if($null -eq ('DeviceCodeHandler' -as [type])) {
            #check if we need to load or already loaded
            $deviceCodeHandlerDefinition = Get-Content "$PSScriptRoot\Helpers\DeviceCodeHandler.cs" -Raw
            Add-Type -TypeDefinition $deviceCodeHandlerDefinition -ReferencedAssemblies $referencedAssemblies -WarningAction SilentlyContinue -IgnoreWarnings
        }
        if($null -eq ('ParentWindowHelper' -as [type])) {
            #check if we need to load or already loaded
            $parentWindowHelperDefinition = Get-Content "$PSScriptRoot\Helpers\ParentWindowHelper.cs" -Raw
            Add-Type -TypeDefinition $parentWindowHelperDefinition -ReferencedAssemblies $referencedAssemblies -WarningAction SilentlyContinue -IgnoreWarnings
        }
    }
}
