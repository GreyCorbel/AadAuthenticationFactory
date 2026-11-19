Set-StrictMode -Version Latest

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $moduleManifestPath = [System.IO.Path]::Combine(
        $repoRoot,
        'Module',
        'AadAuthenticationFactory',
        'AadAuthenticationFactory.psd1'
    )

    if (-not (Test-Path $moduleManifestPath)) {
        throw "Module manifest not found at $moduleManifestPath"
    }

    Import-Module $moduleManifestPath -ErrorAction Stop

    function ConvertTo-Base64Url {
        param(
            [Parameter(Mandatory)]
            [byte[]]$Bytes
        )

        [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }

    $script:requiredCommands = @(
        'Get-AadAccount',
        'Get-AadAuthenticationFactory',
        'Get-AadDefaultClientId',
        'Get-AadToken',
        'New-AadAuthenticationFactory',
        'Test-AadToken'
    )

}

Describe 'AadAuthenticationFactory module surface' {
    It 'exports all expected public commands' {
        foreach ($commandName in $script:requiredCommands) {
            Get-Command -Name $commandName -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }

    It 'returns a GUID default client id' {
        $defaultClientId = Get-AadDefaultClientId
        $parsedGuid = [Guid]::Empty

        $defaultClientId | Should -Not -BeNullOrEmpty
        [Guid]::TryParse($defaultClientId, [ref]$parsedGuid) | Should -BeTrue
    }
}

Describe 'Edition-specific identity packages' {
    It 'bundles each edition identity assembly from its pinned package' {
        $identityPackages = @(
            'Microsoft.Identity.Client',
            'Microsoft.Identity.Client.Broker',
            'Microsoft.IdentityModel.Abstractions',
            'Microsoft.Identity.Client.NativeInterop'
        )
        foreach ($edition in @('Core', 'Desktop')) {
            $projectPath = Join-Path $repoRoot 'Workflow/Core/Dependencies.csproj'
            $destinationFramework = 'netstandard2.0'
            if ($edition -eq 'Desktop') {
                $projectPath = Join-Path $repoRoot 'Workflow/Desktop/Dependencies.csproj'
                $destinationFramework = 'net462'
            }

            $references = ([xml](Get-Content -LiteralPath $projectPath -Raw)).Project.ItemGroup.PackageReference
            foreach ($reference in $references) {
                $packageId = [string]$reference.Include
                if ($packageId -notin $identityPackages) {
                    continue
                }

                $sourceFramework = $destinationFramework
                if ($packageId -in @('Microsoft.Identity.Client.Broker', 'Microsoft.Identity.Client.NativeInterop')) {
                    $sourceFramework = 'netstandard2.0'
                }
                $source = Join-Path $repoRoot (
                    'packages/{0}/{1}/lib/{2}/{3}.dll' -f
                    $packageId.ToLowerInvariant(), $reference.Version, $sourceFramework, $packageId
                )
                $destination = Join-Path (Split-Path $moduleManifestPath) "shared/$destinationFramework/$packageId.dll"

                $destination | Should -Exist
                (Get-FileHash -LiteralPath $destination).Hash |
                    Should -Be (Get-FileHash -LiteralPath $source).Hash
            }
        }
    }

    It 'loads the identity assemblies from the current edition directory' {
        $framework = 'netstandard2.0'
        $typeNames = @(
            'Microsoft.Identity.Client.PublicClientApplication',
            'Microsoft.Identity.Client.Broker.BrokerExtension'
        )
        if ($PSEdition -eq 'Desktop') {
            $framework = 'net462'
            $typeNames += @(
                'Microsoft.IdentityModel.Abstractions.IIdentityLogger',
                'Microsoft.Identity.Client.NativeInterop.Core'
            )
        }

        foreach ($typeName in $typeNames) {
            $assembly = ($typeName -as [type]).Assembly
            $expectedPath = Join-Path (Split-Path $moduleManifestPath) "shared/$framework/$($assembly.GetName().Name).dll"
            $assembly.Location | Should -Be $expectedPath
        }
    }
}

Describe 'Factory lifecycle' {
    It 'creates and retrieves a named factory' {
        $factoryName = "PesterFactory_$([Guid]::NewGuid().ToString('N'))"

        $createdFactory = New-AadAuthenticationFactory `
            -TenantId 'organizations' `
            -AuthMode DeviceCode `
            -DefaultScopes @('https://management.azure.com/.default') `
            -Name $factoryName

        $retrievedFactory = Get-AadAuthenticationFactory -Name $factoryName

        $createdFactory | Should -Not -BeNullOrEmpty
        $retrievedFactory | Should -Not -BeNullOrEmpty
        $retrievedFactory | Should -Be $createdFactory
    }

    It 'creates a broker factory using the platform backend' {
        $module = Get-Module -Name AadAuthenticationFactory
        $platform = & $module { Get-MsalBrokerPlatformConfiguration }
        $expectedPath = [System.IO.Path]::Combine(
            $module.ModuleBase,
            'runtimes',
            $platform.RuntimeIdentifier,
            'native',
            $platform.NativeLibraryFileName
        )
        $factoryName = "PesterBrokerFactory_$([Guid]::NewGuid().ToString('N'))"

        $factory = New-AadAuthenticationFactory `
            -TenantId 'organizations' `
            -AuthMode Broker `
            -DefaultScopes @('https://management.azure.com/.default') `
            -Name $factoryName
        $loadedRuntime = & $module {
            [pscustomobject]@{
                Path = $script:MsalNativeRuntimePath
                Handle = $script:MsalNativeRuntimeHandle
            }
        }

        $factory | Should -Not -BeNullOrEmpty
        if ($platform.OperatingSystem -eq 'macOS') {
            $factory.MacBrokerConfiguration.ExecutablePath | Should -Exist
            $factory.MacBrokerConfiguration.Authority | Should -Be 'https://login.microsoftonline.com/organizations'
            $factory.AppConfig.ClientId | Should -Be '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
            return
        }

        $expectedPath | Should -Exist
        $loadedRuntime.Path | Should -Be $expectedPath
        $loadedRuntime.Handle | Should -Not -Be ([IntPtr]::Zero)
    }

    It 'preserves explicit broker client IDs and non-broker defaults' {
        $clientId = '11111111-1111-1111-1111-111111111111'
        $factory = New-AadAuthenticationFactory -AuthMode Broker -TenantId organizations -ClientId $clientId `
            -Name ExplicitBrokerClientTest
        $factory.AppConfig.ClientId | Should -Be $clientId
        $nonBroker = New-AadAuthenticationFactory -AuthMode DeviceCode -TenantId organizations -Name NonBrokerDefaultTest
        $nonBroker.AppConfig.ClientId | Should -Be (Get-AadDefaultClientId)
        $nonBroker.PSObject.Properties['MacBrokerConfiguration'] | Should -BeNullOrEmpty
    }

    It 'resolves native imports when creating broker authentication parameters' {
        $factory = New-AadAuthenticationFactory `
            -TenantId 'organizations' `
            -AuthMode Broker `
            -Name "PesterNativeBrokerFactory_$([Guid]::NewGuid().ToString('N'))"

        $factory | Should -Not -BeNullOrEmpty
        $module = Get-Module -Name AadAuthenticationFactory
        & $module { param($root) Import-MsalNativeRuntime -ModuleRoot $root } $module.ModuleBase | Out-Null
        $parameters = [Microsoft.Identity.Client.NativeInterop.AuthParameters]::new(
            (Get-AadDefaultClientId),
            'https://login.microsoftonline.com/organizations'
        )
        try {
            $parameters.RequestedScopes = 'https://management.azure.com/.default'
            $parameters.RequestedScopes | Should -Be 'https://management.azure.com/.default'
        }
        finally {
            $parameters.Dispose()
        }
    }
}

Describe 'Confidential client integration' -Tag 'integration' {
    BeforeAll {
        $script:integrationConfig = [pscustomobject]@{
            TenantId = $env:AAD_TEST_TENANT_ID
            Scope = $env:AAD_TEST_SCOPE
            ClientId = $env:AAD_TEST_CLIENT_ID
            ClientSecret = $env:AAD_TEST_CLIENT_SECRET
            ExpectedAudience = $env:AAD_TEST_EXPECTED_AUD
        }

        $script:canRunConfidentialIntegration =
            -not [string]::IsNullOrWhiteSpace($script:integrationConfig.TenantId) -and
            -not [string]::IsNullOrWhiteSpace($script:integrationConfig.Scope) -and
            -not [string]::IsNullOrWhiteSpace($script:integrationConfig.ClientId) -and
            -not [string]::IsNullOrWhiteSpace($script:integrationConfig.ClientSecret)
    }

    It 'acquires an app token and validates expected payload' {
        if (-not $script:canRunConfidentialIntegration) {
            Set-ItResult -Skipped -Because "Integration environment variables not configured"
            return
        }

        $factory = New-AadAuthenticationFactory `
            -TenantId $script:integrationConfig.TenantId `
            -ClientId $script:integrationConfig.ClientId `
            -ClientSecret $script:integrationConfig.ClientSecret `
            -DefaultScopes @($script:integrationConfig.Scope)

        $tokenResult = Get-AadToken -Factory $factory -ErrorAction Stop
        $payload = Test-AadToken -Token $tokenResult -PayloadOnly

        $tokenResult | Should -Not -BeNullOrEmpty
        $tokenResult.AccessToken | Should -Not -BeNullOrEmpty
        $payload | Should -Not -BeNullOrEmpty

        if (-not [string]::IsNullOrWhiteSpace($script:integrationConfig.ExpectedAudience)) {
            $payload.aud | Should -Be $script:integrationConfig.ExpectedAudience
        }
        else {
            $payload.aud | Should -Not -BeNullOrEmpty
        }
    }

    Describe 'Federated credential integration' -Tag 'integration' {
        BeforeAll {
            $script:federatedConfig = [pscustomobject]@{
                TenantId = $env:AAD_TEST_TENANT_ID
                Scope = $env:AAD_TEST_SCOPE
                ClientId = $env:AAD_TEST_CLIENT_ID
                ExpectedAudience = $env:AAD_TEST_EXPECTED_AUD
                OidcAudience = $env:AAD_TEST_OIDC_AUDIENCE
                OidcSubject = $env:AAD_TEST_OIDC_SUBJECT
            }

            $script:canRunFederatedIntegration =
                -not [string]::IsNullOrWhiteSpace($script:federatedConfig.TenantId) -and
                -not [string]::IsNullOrWhiteSpace($script:federatedConfig.Scope) -and
                -not [string]::IsNullOrWhiteSpace($script:federatedConfig.ClientId) -and
                -not [string]::IsNullOrWhiteSpace($script:federatedConfig.ExpectedAudience) -and
                -not [string]::IsNullOrWhiteSpace($script:federatedConfig.OidcAudience) -and
                -not [string]::IsNullOrWhiteSpace($script:federatedConfig.OidcSubject) -and
                -not [string]::IsNullOrWhiteSpace($env:ACTIONS_ID_TOKEN_REQUEST_URL) -and
                -not [string]::IsNullOrWhiteSpace($env:ACTIONS_ID_TOKEN_REQUEST_TOKEN)
        }

        It 'exchanges a GitHub OIDC credential for an Entra access token' {
            if (-not $script:canRunFederatedIntegration) {
                Set-ItResult -Skipped -Because 'Federated integration environment variables not configured'
                return
            }

            $separator = if ($env:ACTIONS_ID_TOKEN_REQUEST_URL.Contains('?')) { '&' } else { '?' }
            $encodedAudience = [Uri]::EscapeDataString($script:federatedConfig.OidcAudience)
            $requestUri = "$($env:ACTIONS_ID_TOKEN_REQUEST_URL)$separator" + "audience=$encodedAudience"
            $response = Invoke-RestMethod `
                -Method Get `
                -Uri $requestUri `
                -Headers @{ Authorization = "Bearer $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN" } `
                -ErrorAction Stop
            $githubToken = $response.value
            $githubPayload = Test-AadToken -Token $githubToken -PayloadOnly

            $githubToken | Should -Not -BeNullOrEmpty
            $githubPayload.iss | Should -Be 'https://token.actions.githubusercontent.com'
            $githubPayload.aud | Should -Be $script:federatedConfig.OidcAudience
            $githubPayload.sub | Should -Be $script:federatedConfig.OidcSubject

            $factory = New-AadAuthenticationFactory `
                -TenantId $script:federatedConfig.TenantId `
                -ClientId $script:federatedConfig.ClientId `
                -Assertion $githubToken `
                -DefaultScopes @($script:federatedConfig.Scope)

            $tokenResult = Get-AadToken -Factory $factory -ErrorAction Stop
            $payload = Test-AadToken -Token $tokenResult -PayloadOnly

            $tokenResult | Should -Not -BeNullOrEmpty
            $tokenResult.AccessToken | Should -Not -BeNullOrEmpty
            $payload | Should -Not -BeNullOrEmpty
            $payload.aud | Should -Be $script:federatedConfig.ExpectedAudience
        }
    }
}
