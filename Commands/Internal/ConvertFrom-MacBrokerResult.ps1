function ConvertFrom-MacBrokerAccount {
    param([Parameter(Mandatory)] $Account)

    if ([string]::IsNullOrEmpty($Account.HomeAccountId)) {
        throw [System.IO.InvalidDataException]::new('The macOS broker returned an account without a home account ID.')
    }
    if ($null -eq ('AadAuthenticationFactory.MacBrokerAccount' -as [type])) {
        $helperPath = [Path]::Combine($PSScriptRoot, 'Helpers', 'MacBrokerAccount.cs')
        Add-Type -Path $helperPath -ReferencedAssemblies ([Microsoft.Identity.Client.IAccount].Assembly.Location) -ErrorAction Stop
    }
    [AadAuthenticationFactory.MacBrokerAccount]::new(
        $Account.Username, $Account.Environment, $Account.HomeAccountId
    )
}

function ConvertFrom-MacBrokerResult {
    param([Parameter(Mandatory)] $Result)

    if ($Result.TokenSource -ne 'Broker' -or [string]::IsNullOrEmpty($Result.AccessToken)) {
        throw [System.IO.InvalidDataException]::new('The macOS helper did not return a broker authentication result.')
    }
    $account = if ($null -ne $Result.Account) { ConvertFrom-MacBrokerAccount -Account $Result.Account } else { $null }
    $metadata = [Microsoft.Identity.Client.AuthenticationResultMetadata]::new(
        [Microsoft.Identity.Client.TokenSource]::Broker
    )
    $additionalParameters = [System.Collections.Generic.Dictionary[string, string]]::new()
    if ($null -ne $Result.AdditionalResponseParameters) {
        foreach ($property in $Result.AdditionalResponseParameters.PSObject.Properties) {
            $additionalParameters.Add($property.Name, [string]$property.Value)
        }
    }
    $principal = $null
    if ($null -ne $Result.Identities) {
        $principal = [System.Security.Claims.ClaimsPrincipal]::new()
        foreach ($wireIdentity in $Result.Identities) {
            $identity = [System.Security.Claims.ClaimsIdentity]::new(
                $wireIdentity.AuthenticationType, $wireIdentity.NameClaimType, $wireIdentity.RoleClaimType
            )
            foreach ($wireClaim in $wireIdentity.Claims) {
                $claim = [System.Security.Claims.Claim]::new(
                    $wireClaim.Type, $wireClaim.Value, $wireClaim.ValueType, $wireClaim.Issuer, $wireClaim.OriginalIssuer
                )
                if ($null -ne $wireClaim.Properties) {
                    foreach ($property in $wireClaim.Properties.PSObject.Properties) {
                        $claim.Properties.Add($property.Name, [string]$property.Value)
                    }
                }
                $identity.AddClaim($claim)
            }
            $principal.AddIdentity($identity)
        }
    }
    [Microsoft.Identity.Client.AuthenticationResult]::new(
        $Result.AccessToken,
        [bool]$Result.IsExtendedLifeTimeToken,
        $Result.UniqueId,
        [DateTimeOffset]$Result.ExpiresOn,
        [DateTimeOffset]$Result.ExtendedExpiresOn,
        $Result.TenantId,
        $account,
        $Result.IdToken,
        [string[]]$Result.Scopes,
        [Guid]$Result.CorrelationId,
        $Result.TokenType,
        $metadata,
        $principal,
        $Result.SpaAuthCode,
        $additionalParameters
    )
}
