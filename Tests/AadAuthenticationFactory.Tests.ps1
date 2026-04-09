Set-StrictMode -Version Latest

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $moduleManifestPath = Join-Path $repoRoot 'Module\AadAuthenticationFactory\AadAuthenticationFactory.psd1'

    if (-not (Test-Path $moduleManifestPath)) {
        throw "Module manifest not found at $moduleManifestPath"
    }

    Import-Module $moduleManifestPath -Force -ErrorAction Stop

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
}

