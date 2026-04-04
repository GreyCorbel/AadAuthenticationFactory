function Get-AadToken
{
    <#
.SYNOPSIS
    Acquires an Entra ID token from an authentication factory.

.DESCRIPTION
    Requests a token by using the flow configured in an AadAuthenticationFactory
    instance. Depending on the factory type, the command can acquire delegated,
    application, on-behalf-of, broker, device code, or managed identity tokens.
    The command can also return an Authorization header hashtable or request a
    Proof-of-Possession token when supported.

.PARAMETER Scopes
    Scopes to request. If omitted, the factory's DefaultScopes value is used.

.PARAMETER UserName
    User name hint used during authentication or to select a cached account.

.PARAMETER UserToken
    Access token representing the calling user for on-behalf-of flows.
    This is supported only with confidential client factories.

.PARAMETER PopHttpMethod
    HTTP method to bind to a Proof-of-Possession token request.
    Used only when PopRequestUri is specified.

.PARAMETER PoPRequestUri
    Resource URI to bind to a Proof-of-Possession token request.

.PARAMETER AsHashTable
    Returns a hashtable containing an Authorization header instead of the raw
    authentication result.

.PARAMETER ForceRefresh
    Forces token acquisition to bypass cached access tokens where supported.

.PARAMETER WwwAuthenticateParameters
    WWW-Authenticate parameters used for step-up authentication or CAE reauth.

.PARAMETER Factory
    Authentication factory instance, or the name of a previously created factory.
    If not specified, the most recently created factory is used.

.OUTPUTS
    Microsoft.Identity.Client.AuthenticationResult or System.Collections.Hashtable

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('https://management.azure.com/.default') -AuthMode Interactive
$token = $factory | Get-AadToken

Description
-----------
Creates a public client factory and acquires a delegated token interactively.

.EXAMPLE
$cosmosDbAccountName = 'myCosmosDbAccount'
$factory = New-AadAuthenticationFactory -DefaultScopes @("https://$cosmosDbAccountName`.documents.azure.com/.default") -UseManagedIdentity
$token = $factory | Get-AadToken

Description
-----------
Creates a managed identity factory and acquires a token for Azure Cosmos DB.

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -AuthMode WIA
$token = $factory | Get-AadToken -Scopes @('https://eventgrid.azure.net/.default')

Description
-----------
Requests a token by specifying scopes at call time instead of on the factory.

.EXAMPLE
New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('api://mycompany.com/myapi/.default') -AuthMode Interactive
$headers = Get-AadToken -AsHashtable
Invoke-RestMethod -Uri 'https://myapi.mycompany.com/items' -Headers $headers

Description
-----------
Returns an Authorization header hashtable that can be used with Invoke-RestMethod.

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('api://middle-tier/.default') -ClientSecret $env:API_SECRET -ClientId '11111111-1111-1111-1111-111111111111'
$token = Get-AadToken -Factory $factory -Scopes @('https://graph.microsoft.com/.default') -UserToken $incomingAccessToken

Description
-----------
Uses a confidential client factory to perform an on-behalf-of token request.

#>
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [Alias("RequiredScopes")]
            #Scopes to be returned in the token.
            #If not specified, returns token with default scopes provided when creating the factory
        [string[]]$Scopes = $null,
        [Parameter()]
            #User name hint for authentication process
        [string]$UserName,
        [Parameter()]
            #Access token for user
            #Used to identify user in on-behalf-of flows
        [string]$UserToken,
            #Request PoP token instead of Bearer token
            #PoP http method for resource to bind PoP token to
            #default is GET
            #Ignored for authentication flows other than 'PublicClientWithWam
        [System.Net.Http.HttpMethod]$PopHttpMethod = [System.Net.Http.HttpMethod]::Get,
            #Request PoP token instead of Bearer token
            #PUri to bind PoP token to
            #Ignored for authentication flows other than 'PublicClientWithWam
        [string]$PoPRequestUri,
            #When specified, hashtable with Authorization header is returned instead of token
            #This is shortcut to use when just need to have token for authorization header to call REST API (e.g. via Invoke-RestMethod)
            #When not specified, returns authentication result with tokens and other metadata
        [switch]$AsHashTable,
            #Asks runtime to avoid token cache and get fresh token from AAD
        [switch]$ForceRefresh,
        [Parameter()]
        [Microsoft.Identity.Client.WwwAuthenticateParameters]
            #WwwAuthenticateParameters to be used for re-authentication
            #This is used when you want to do step-up authentication with AAD and you have the parameters from the WWW-Authenticate header
        $WwwAuthenticateParameters,
        [Parameter(ValueFromPipeline)]
            #AAD authentication factory created via New-AadAuthenticationFactory
        $Factory = $script:AadLastCreatedFactory
    )

    begin
    {
        Write-Verbose "Initializing"
        [System.Threading.CancellationTokenSource]$cts = new-object System.Threading.CancellationTokenSource([timespan]::FromSeconds(180))
    }
    process
    {
        if($null -eq $Factory)
        {
            Write-Error "Please pass valid instance of AAD Authentication Factory"
            return
        }

        if($factory -is [string])
        {
            $factory = Get-AadAuthenticationFactory -Name $factory
        }
        
        if($null -eq $Scopes)
        {
            $scopes = $factory.DefaultScopes
            if($null -eq $Scopes)
            {
                throw (new-object System.ArgumentException("No scopes specified"))
            }
        }

        if([string]::IsNullOrWhiteSpace($UserName))
        {
            $UserName = $factory.DefaultUserName
        }

        if(-not [string]::IsNullOrEmpty($UserToken))
        {
            if($Factory.FlowType -ne [AuthenticationFlow]::ConfidentialClient)
            {
                throw (new-object System.ArgumentException("Unsupported authentication flow for on-behalf-of: $($Factory.FlowType)"))
            }
            $assertion = new-object Microsoft.Identity.Client.UserAssertion($UserToken)
            Write-Verbose "Getting token with assertion $($assertion.AssertionType) $($assertion.Assertion)"
            $task = $Factory.AcquireTokenOnBehalfOf($Scopes, $assertion).ExecuteAsync($cts.Token)
        }
        else
        {
            Write-Verbose "Getting account from cache"
            $account = Get-AadAccount -UserName $UserName -Factory $Factory
            if($account.count -gt 1)
            {
                Write-Verbose "Multiple accounts found in cache. Using first one"
                $account = $account[0]
            }
            switch($Factory.FlowType)
            {
                ([AuthenticationFlow]::PublicClient) {
                    try
                    {
                        Write-Verbose "Getting token for $($account.Username)"
                        $builder = $factory.AcquireTokenSilent($scopes,$account)
                        $builder = $builder.WithForceRefresh($forceRefresh)
                        if($null -ne $WwwAuthenticateParameters)
                        {
                            Write-Verbose "Using WWW-Authenticate parameters for re-authentication"
                            $builder = $builder.WithAuthority($WwwAuthenticateParameters.Authority)
                            $builder = $builder.WithClaims($WwwAuthenticateParameters.Claims)
                        }

                        $task = $builder.ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    catch [Microsoft.Identity.Client.MsalUiRequiredException]
                    {
                        Write-Verbose "Getting token interactively"
                        $task = $factory.AcquireTokenInteractive($Scopes).ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    break;
                }
                ([AuthenticationFlow]::PublicClientWithWia) {
                    if($null -ne $Account)
                    {
                        Write-Verbose "Getting token for $($account.Username)"
                        $task = $factory.AcquireTokenSilent($Scopes, $account).WithForceRefresh($forceRefresh).ExecuteAsync()
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    else
                    {
                        Write-Verbose "Getting token with explicit auth"
                        $task = $factory.AcquireTokenByIntegratedWindowsAuth($Scopes).WithUserName($UserName).ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                        #let the app throw to caller when UI required as the purpose here is to stay silent
                    }
                    break;
                }
                ([AuthenticationFlow]::PublicClientWithWam) {
                    if($null -eq $Account -and [string]::IsNullOrEmpty($userName))
                    {
                        <# Write-Verbose "Getting token for OperatingSystemAccount"
                        $account = [Microsoft.Identity.Client.PublicClientApplication]::OperatingSystemAccount #>
                    }
                    try
                    {
                        Write-Verbose "Getting token silently"
                        $builder = $factory.AcquireTokenSilent($scopes,$account)
                        $builder = $builder.WithForceRefresh($forceRefresh)
                        if(-not [string]::IsNullOrEmpty($PoPRequestUri))
                        {
                            if(-not $factory.IsProofOfPossessionSupportedByClient)
                            {
                                throw (new-object System.ArgumentException("PoP authentication scheme is not supported by client"))
                            }
                            Write-Verbose "Requesting PoP nonce from resource server for Uri: $PoPRequestUri and http method $PopHttpMethod"
                            $PopNonce = Get-PoPNonce -Uri $PoPRequestUri -Method $PopHttpMethod -Factory $Factory
                            if($null -eq $PopNonce)
                            {
                                throw (new-object System.ArgumentException("PoP authentication scheme is not supported by resource server"))
                            }
                            $builder = $builder.WithProofOfPossession($PopNonce, $PopHttpMethod, $PoPRequestUri)
                        }
                        if($null -ne $WwwAuthenticateParameters)
                        {
                            Write-Verbose "Using WWW-Authenticate parameters for re-authentication"
                            $builder = $builder.WithAuthority($WwwAuthenticateParameters.Authority)
                            $builder = $builder.WithClaims($WwwAuthenticateParameters.Claims)
                        }
                        $task = $builder.ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    catch [Microsoft.Identity.Client.MsalUiRequiredException]
                    {
                        $builder = $factory.AcquireTokenInteractive($Scopes)
                        if(-not [string]::IsNullOrEmpty($UserName))
                        {
                            Write-Verbose "Falling back to UI auth with parent window hadle: $windowHandle and login hint: $userName"
                            $builder = $builder.WithLoginHint($userName)
                        }
                        else
                        {
                            Write-Verbose "Falling back to UI auth with parent window hadle: $windowHandle and account: $($account.userName)"
                            $builder = $builder.WithAccount($account)
                        }
                        if(-not [string]::IsNullOrEmpty($popNonce))
                        {
                            Write-Verbose "Requesting PoP token interactively"
                            $builder = $builder.WithProofOfPossession($PopNonce, $PopHttpMethod, $PoPRequestUri)
                        }
                        $task = $builder.ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }    
                    break;
                }
                ([AuthenticationFlow]::PublicClientWithDeviceCode) {
                    try
                    {
                        Write-Verbose "Getting token for $($account.Username)"
                        $builder = $factory.AcquireTokenSilent($scopes,$account)
                        $builder = $builder.WithForceRefresh($forceRefresh)
                        if($null -ne $WwwAuthenticateParameters)
                        {
                            Write-Verbose "Using WWW-Authenticate parameters for re-authentication"
                            $builder = $builder.WithAuthority($WwwAuthenticateParameters.Authority)
                            $builder = $builder.WithClaims($WwwAuthenticateParameters.Claims)
                        }

                        $task = $builder.ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    catch [Microsoft.Identity.Client.MsalUiRequiredException]
                    {
                        Write-Verbose "Getting token with device code"
                        $task = $factory.AcquireTokenWithDeviceCode($Scopes,[DeviceCodeHandler]::Get()).ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    break;
                }
                ([AuthenticationFlow]::ResourceOwnerPassword) {
                    try
                    {
                        $creds = $factory.ResourceOwnerCredential
                        if($forceRefresh)
                        {
                            Write-Verbose "Refreshing token with explicit credentials"
                            $task = $factory.AcquireTokenByUsernamePassword($Scopes, $creds.UserName, $creds.GetNetworkCredential().Password).ExecuteAsync()
                            $rslt = $task | AwaitTask -CancellationTokenSource $cts
                        }
                        else
                        {
                            Write-Verbose "Getting token silently"
                            $task = $factory.AcquireTokenSilent($scopes,$account).ExecuteAsync($cts.Token)
                            $rslt = $task | AwaitTask -CancellationTokenSource $cts
                        }
                    }
                    catch [Microsoft.Identity.Client.MsalUiRequiredException]
                    {
                        Write-Verbose "Getting token with credentials"
                        $task = $factory.AcquireTokenByUsernamePassword($Scopes, $creds.UserName, $creds.GetNetworkCredential().Password).ExecuteAsync()
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    break;
                }
                ([AuthenticationFlow]::ConfidentialClient) {

                    Write-Verbose "Getting token for confidentioal client"
                    $builder = $factory.AcquireTokenForClient($scopes)
                    $builder = $builder.WithForceRefresh($forceRefresh)
                    if(-not [string]::IsNullOrEmpty($PoPRequestUri))
                    {
                        Write-Verbose "Requesting PoP nonce from resource server for Uri: $PoPRequestUri and http method $PopHttpMethod"
                        $PopNonce = Get-PoPNonce -Uri $PoPRequestUri -Method $PopHttpMethod -Factory $Factory
                        if($null -eq $PopNonce)
                        {
                            throw (new-object System.ArgumentException("PoP authentication scheme is not supported by resource server"))
                        }
                        $popConfig = new-object Microsoft.Identity.Client.AppConfig.PoPAuthenticationConfiguration((new-object Uri($PoPRequestUri)))
                        $popConfig.HttpMethod = $PopHttpMethod
                        $popConfig.Nonce = $PopNonce
                        $builder = $builder.WithProofOfPossession($popConfig)
                    }
                    $task = $builder.ExecuteAsync($cts.Token)
                    $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    break
                }
                ([AuthenticationFlow]::ManagedIdentity) {
                    Write-Verbose "Getting token for system-assigned MSI"
                    $task = $Factory.AcquireTokenForManagedIdentity($scopes).WithForceRefresh($forceRefresh).ExecuteAsync()
                    $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    break
                }
                ([AuthenticationFlow]::UserAssignedIdentity) {
                    Write-Verbose "Getting token for user-assigned MSI"
                    $task = $Factory.AcquireTokenForManagedIdentity($scopes).WithForceRefresh($forceRefresh).ExecuteAsync()
                    $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    break
                }
                default {
                    throw (new-object System.ArgumentException("Unsupported authentication flow: $_"))
                }
            }
        }

        if($AsHashTable)
        {
            Write-Verbose 'Converting token to authorization header'
            @{
                'Authorization' = $rslt.CreateAuthorizationHeader()
            }
        }
        else
        {
            $rslt
        }
    }
    end
    {
        if($null -ne $cts)
        {
            Write-Verbose "Disposing resources"
            $cts.Dispose()
        }
    }
}
