Set-StrictMode -Version Latest

BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../Module/AadAuthenticationFactory/AadAuthenticationFactory.psd1') -ErrorAction Stop
}

Describe 'Mac broker process transport' -Skip:(
    -not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::OSX
    )
) {
    InModuleScope AadAuthenticationFactory {
        BeforeEach {
            $architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()
            $script:transportFactory = [pscustomobject]@{
                AppConfig = [pscustomobject]@{ ClientId = 'not-a-client-id' }
                MacBrokerConfiguration = [pscustomobject]@{
                    ExecutablePath = Join-Path (Get-Module AadAuthenticationFactory).ModuleBase "bin/osx-$architecture/AadAuthenticationFactory.MacBroker"
                    Authority = 'https://login.microsoftonline.com/organizations'
                    MultiCloud = $false
                    ClaimsSupport = $false
                    ExperimentalFeatures = $false
                }
            }
            $script:transportCancellation = [System.Threading.CancellationTokenSource]::new()
        }

        AfterEach {
            $script:transportCancellation.Dispose()
        }

        It 'rejects an explicit proxy instead of silently ignoring it' {
            { New-AadAuthenticationFactory -AuthMode Broker -TenantId organizations `
                -Proxy ([System.Net.WebProxy]::new('http://localhost:8888')) -Name UnsupportedMacProxy } |
                Should -Throw '*does not support B2C policies or an explicit -Proxy*'
        }

        It 'rejects B2C broker factories explicitly' {
            { New-AadAuthenticationFactory -AuthMode Broker -TenantId contoso.onmicrosoft.com `
                -B2CPolicy B2C_1_signin -Name UnsupportedMacB2C } |
                Should -Throw '*does not support B2C policies or an explicit -Proxy*'
        }

        It 'surfaces structured helper errors as MSAL exceptions' {
            { Invoke-MacBroker -Factory $script:transportFactory -Operation accounts `
                -CancellationTokenSource $script:transportCancellation } |
                Should -Throw '*client ID and absolute HTTPS authority are required*'
        }

        It 'does not start a process for an already cancelled request' {
            $script:transportFactory.MacBrokerConfiguration.ExecutablePath = '/does/not/exist'
            $script:transportCancellation.Cancel()
            { Invoke-MacBroker -Factory $script:transportFactory -Operation accounts `
                -CancellationTokenSource $script:transportCancellation } | Should -Throw '*canceled*'
        }

        It 'terminates an unresponsive helper when cancelled' {
            $stub = Join-Path $TestDrive 'waiting-helper'
            Set-Content -LiteralPath $stub -Value "#!/bin/sh`nexec /bin/sleep 30" -NoNewline
            & /bin/chmod u+x $stub
            $script:transportFactory.MacBrokerConfiguration.ExecutablePath = $stub
            $script:transportCancellation.CancelAfter(300)
            $elapsed = [System.Diagnostics.Stopwatch]::StartNew()
            { Invoke-MacBroker -Factory $script:transportFactory -Operation accounts `
                -CancellationTokenSource $script:transportCancellation } | Should -Throw '*canceled*'
            $elapsed.Stop()
            $elapsed.Elapsed.TotalSeconds | Should -BeLessThan 5
        }
    }
}
