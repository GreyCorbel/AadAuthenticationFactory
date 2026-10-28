Set-StrictMode -Version Latest

BeforeDiscovery {
    $manifest = Join-Path $PSScriptRoot '../Module/AadAuthenticationFactory/AadAuthenticationFactory.psd1'
    Import-Module $manifest -ErrorAction Stop
}

Describe 'Mac broker MSAL compatibility' {
    InModuleScope AadAuthenticationFactory {
        BeforeAll {
            $script:wireAccount = [pscustomobject]@{
                Username = 'user@example.com'
                Environment = 'login.microsoftonline.com'
                HomeAccountId = 'object-id.tenant-id'
            }
            $script:wireResult = [pscustomobject]@{
                AccessToken = 'test-access-token'
                IdToken = $null
                UniqueId = 'object-id'
                TenantId = 'tenant-id'
                TokenType = 'Bearer'
                ExpiresOn = [DateTimeOffset]::UtcNow.AddHours(1).ToString('O')
                ExtendedExpiresOn = [DateTimeOffset]::UtcNow.AddHours(2).ToString('O')
                IsExtendedLifeTimeToken = $false
                Scopes = @('https://management.azure.com/.default')
                CorrelationId = [Guid]::NewGuid().ToString()
                Account = $script:wireAccount
                TokenSource = 'Broker'
                SpaAuthCode = $null
                AdditionalResponseParameters = [pscustomobject]@{ example = 'value' }
                Identities = @(
                    [pscustomobject]@{
                        AuthenticationType = 'test'
                        NameClaimType = 'name'
                        RoleClaimType = 'role'
                        Claims = @(
                            [pscustomobject]@{
                                Type = 'name'
                                Value = 'user@example.com'
                                ValueType = 'http://www.w3.org/2001/XMLSchema#string'
                                Issuer = 'test-issuer'
                                OriginalIssuer = 'test-issuer'
                                Properties = [pscustomobject]@{ test = 'value' }
                            }
                        )
                    }
                )
            }
        }

        It 'reconstructs a real AuthenticationResult and account' {
            $result = ConvertFrom-MacBrokerResult -Result $script:wireResult
            $result | Should -BeOfType ([Microsoft.Identity.Client.AuthenticationResult])
            $result.Account | Should -BeOfType ([Microsoft.Identity.Client.IAccount])
            $result.Account.HomeAccountId.Identifier | Should -Be 'object-id.tenant-id'
            $result.Account.Username | Should -Be 'user@example.com'
            $result.CreateAuthorizationHeader() | Should -Be 'Bearer test-access-token'
            $result.AuthenticationResultMetadata.TokenSource.ToString() | Should -Be 'Broker'
            $result.CorrelationId | Should -Be ([Guid]$script:wireResult.CorrelationId)
            $result.ExpiresOn | Should -Be ([DateTimeOffset]$script:wireResult.ExpiresOn)
            $result.AdditionalResponseParameters['example'] | Should -Be 'value'
            $result.ClaimsPrincipal.Identity.Name | Should -Be 'user@example.com'
            $result.ClaimsPrincipal.Identity.IsAuthenticated | Should -BeTrue
            $result.ClaimsPrincipal.FindFirst('name').Properties['test'] | Should -Be 'value'
        }

        It 'preserves a non-Bearer authentication scheme' {
            $wireResult = $script:wireResult.PSObject.Copy()
            $wireResult.TokenType = 'ssh-cert'
            $result = ConvertFrom-MacBrokerResult -Result $wireResult
            $result.TokenType | Should -Be 'ssh-cert'
            $result.CreateAuthorizationHeader() | Should -Be 'ssh-cert test-access-token'
        }

        It 'rejects a non-broker token result' {
            $wireResult = $script:wireResult.PSObject.Copy()
            $wireResult.TokenSource = 'IdentityProvider'
            { ConvertFrom-MacBrokerResult -Result $wireResult } | Should -Throw '*did not return a broker*'
        }

        It 'rejects an account without a stable identifier' {
            { ConvertFrom-MacBrokerAccount -Account ([pscustomobject]@{ HomeAccountId = '' }) } |
                Should -Throw '*without a home account ID*'
        }

        Context 'Command routing' {
            BeforeEach {
                $script:testFactory = New-AadAuthenticationFactory -AuthMode DeviceCode -TenantId organizations `
                    -DefaultScopes @('https://management.azure.com/.default') -Name MacRoutingTest
                $script:testFactory.FlowType = [AuthenticationFlow]::PublicClientWithWam
                $script:testFactory | Add-Member -NotePropertyName MacBrokerConfiguration -NotePropertyValue ([pscustomobject]@{
                    ExecutablePath = 'unused'
                    Authority = 'https://login.microsoftonline.com/organizations'
                    MultiCloud = $false
                    ClaimsSupport = $false
                    ExperimentalFeatures = $false
                })
                Mock Invoke-MacBroker {
                    if ($Operation -eq 'accounts') { ConvertFrom-MacBrokerAccount -Account $script:wireAccount }
                    else { ConvertFrom-MacBrokerResult -Result $script:wireResult }
                }
            }

            It 'routes accounts through the helper and preserves regex filtering' {
                $accounts = @(Get-AadAccount -Factory $script:testFactory -UserName '^user@')
                $accounts.Count | Should -Be 1
                $accounts[0] | Should -BeOfType ([Microsoft.Identity.Client.IAccount])
                @(Get-AadAccount -Factory $script:testFactory -UserName '^other@').Count | Should -Be 0
                Should -Invoke Invoke-MacBroker -Times 2 -ParameterFilter { $Operation -eq 'accounts' }
            }

            It 'returns real token results and forwards force-refresh and account selection' {
                $result = Get-AadToken -Factory $script:testFactory -ForceRefresh
                $result | Should -BeOfType ([Microsoft.Identity.Client.AuthenticationResult])
                Should -Invoke Invoke-MacBroker -Times 1 -ParameterFilter {
                    $Operation -eq 'token' -and $ForceRefresh -and $AllowInteractive -and
                    $HomeAccountId -eq 'object-id.tenant-id' -and $LoginHint -eq 'user@example.com'
                }
            }

            It 'preserves AsHashTable output' {
                $header = Get-AadToken -Factory $script:testFactory -AsHashTable
                $header | Should -BeOfType ([hashtable])
                $header.Authorization | Should -Be 'Bearer test-access-token'
            }

            It 'forwards claims challenges and authority overrides' {
                $challenge = [Microsoft.Identity.Client.WwwAuthenticateParameters]::CreateFromWwwAuthenticateHeaderValue(
                    'Bearer authorization_uri="https://login.microsoftonline.com/tenant", claims="eyJhY2Nlc3NfdG9rZW4iOnt9fQ=="'
                )
                Get-AadToken -Factory $script:testFactory -WwwAuthenticateParameters $challenge | Out-Null
                Should -Invoke Invoke-MacBroker -Times 1 -ParameterFilter {
                    $Operation -eq 'token' -and $Authority -eq $challenge.Authority -and $Claims -eq $challenge.Claims
                }
            }

            It 'propagates helper failures without a browser fallback' {
                Mock Invoke-MacBroker { throw [Microsoft.Identity.Client.MsalClientException]::new('broker_failure', 'Broker failed') } `
                    -ParameterFilter { $Operation -eq 'token' }
                { Get-AadToken -Factory $script:testFactory } | Should -Throw '*Broker failed*'
            }

            It 'does not invoke the helper for non-broker factories' {
                $factory = New-AadAuthenticationFactory -AuthMode DeviceCode -TenantId organizations -Name OtherBackendTest
                Get-AadAccount -Factory $factory | Out-Null
                Should -Invoke Invoke-MacBroker -Times 0
            }
        }
    }
}
