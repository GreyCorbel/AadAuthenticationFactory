using namespace System
using namespace System.IO
using namespace System.Runtime.InteropServices
using namespace System.Reflection
using namespace System.Text
#region Public commands
function Get-AadAccount
{
    <#
.SYNOPSIS
    Returns cached Entra ID accounts from an authentication factory.

.DESCRIPTION
    Returns cached account objects for a public client authentication factory.
    When UserName is specified, the command filters cached accounts by using
    PowerShell's -match operator against the account user name.
    Managed identity and other non-public client factories do not return accounts.

.PARAMETER UserName
    Optional user name pattern used to filter cached accounts.

.PARAMETER Factory
    Authentication factory instance, or the name of a previously created factory.
    If not specified, the most recently created factory is used.

.OUTPUTS
    Microsoft.Identity.Client.IAccount

.NOTES
    UserName filtering uses the PowerShell -match operator.

.EXAMPLE
New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('https://management.azure.com/.default') -AuthMode Interactive
Get-AadToken | Test-AadToken -PayloadOnly
Get-AadAccount

Description
-----------
Returns all cached accounts for the most recently created public client factory.

.EXAMPLE
Get-AadAccount -Factory 'Default' -UserName 'john'

Description
-----------
Returns cached accounts from the named factory whose user name matches 'john'.

#>
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline)]
            #User name to get account information for
            #If not specified, all accounts cached in factory are returned
        [string]$UserName,
            #AAD authentication factory created via New-AadAuthenticationFactory
        $Factory = $script:AadLastCreatedFactory
    )

    begin
    {
        [System.Threading.CancellationTokenSource]$cts = new-object System.Threading.CancellationTokenSource([timespan]::FromSeconds(180))
    }
    process
    {
        if($factory -is [string])
        {
            $factory = Get-AadAuthenticationFactory -Name $factory
        }

        if($factory -is [Microsoft.Identity.Client.PublicClientApplication])
        {
            if([string]::IsNullOrEmpty($Factory.B2CPolicy))
            {
                $allAccounts = $Factory.GetAccountsAsync() | AwaitTask -CancellationTokenSource $cts
            }
            else
            {
                $allAccounts = $Factory.GetAccountsAsync($Factory.B2CPolicy) | AwaitTask -CancellationTokenSource $cts
            }

            if(-not [string]::IsNullOrEmpty($UserName))
            {
                $allAccounts | Where-Object{$_.UserName -match $Username}
            }
            else 
            {
                $allAccounts
            }
        }
    }
    end
    {
        if($null -ne $cts)
        {
            $cts.Dispose()
        }
    }
}
function Get-AadAuthenticationFactory
{
    <#
.SYNOPSIS
    Returns one or more authentication factories from the current session.

.DESCRIPTION
    Returns the authentication factory specified by name.
    If Name is not specified, the most recently created factory is returned.
    When All is specified, all factories created in the current session are returned.
    If a requested factory does not exist, the command returns $null.

.PARAMETER Name
    Name of the factory to retrieve. If omitted, the most recently created
    factory is returned.

.PARAMETER All
    Returns every authentication factory created in the current session.

.OUTPUTS
    Authentication factory object, a collection of factories, or $null

.EXAMPLE
Get-AadAuthenticationFactory

Description
-----------
Returns the most recently created authentication factory.

.EXAMPLE
Get-AadAuthenticationFactory -Name 'Vault'

Description
-----------
Returns the factory created with the name 'Vault', or $null if it does not exist.

.EXAMPLE
Get-AadAuthenticationFactory -All

Description
-----------
Returns all authentication factories created in the current PowerShell session.

#>
    [CmdletBinding(DefaultParameterSetName = 'SpecificFactory')]
    param
    ( 
        [Parameter(ValueFromPipeline, ParameterSetName = 'SpecificFactory')]
        [string]
            #name of the factory to retrieve. If not specified, returns last created factory
        $Name,
        [Parameter(ParameterSetName = 'All')]
        [switch]
            #returns all factories created in current session
        $All
    )

    process
    {
        Switch($PSCmdlet.ParameterSetName)
        {
            'All' {
                $script:AadAuthenticationFactories.Values
                break;
            }
            'SpecificFactory' {
                if([string]::IsNullOrEmpty($Name))
                {
                    $script:AadLastCreatedFactory
                }
                else
                {
                    $script:AadAuthenticationFactories[$Name]
                }
                break;
            }
        }
    }
}
function Get-AadDefaultClientId
{
    <#
.SYNOPSIS
    Returns the module's default Entra ID client ID.

.DESCRIPTION
    Returns the default client ID used when New-AadAuthenticationFactory is
    called without an explicit ClientId. The configured default is the Azure
    PowerShell public client application ID.

.OUTPUTS
    System.String

.EXAMPLE
Get-AadDefaultClientId

Description
-----------
Returns the client ID that the module uses by default for public client flows.

    #>
    [CmdletBinding()]
    param
    ( )

    process
    {
        $module = $MyInvocation.MyCommand.Module
        $Module.PrivateData.Configuration.DefaultClientId
    }
}
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
function Get-PoPNonce
{
<#
.SYNOPSIS
    Retrieves a Proof-of-Possession nonce from a resource.

.DESCRIPTION
    Sends an unauthenticated request to a resource and inspects the
    WWW-Authenticate response headers for a PoP challenge. If the resource
    advertises PoP and provides a nonce, that nonce is returned; otherwise the
    command returns $null.

.PARAMETER Uri
    Resource URI to probe for a PoP challenge.

.PARAMETER Method
    HTTP method to use when probing the resource.

.PARAMETER Factory
    Authentication factory whose HTTP client should be used to send the request.
    If not specified, the most recently created factory is used.

.OUTPUTS
    System.String or $null

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('api://myapi/.default') -AuthMode Broker
Get-PoPNonce -Uri 'https://myapi.contoso.com/items' -Method ([System.Net.Http.HttpMethod]::Get) -Factory $factory

Description
-----------
Checks whether the target API challenges clients for a PoP token and returns the nonce if one is provided.

#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
            #URI of the resource to get PoP nonce for            
        [string]$Uri,
        [Parameter(Mandatory=$true)]
            #HTTP method to use for request
        [System.Net.Http.HttpMethod]$Method,
        [Parameter(ValueFromPipeline)]
            #AAD authentication factory created via New-AadAuthenticationFactory
        $Factory = $script:AadLastCreatedFactory
    )
    begin
    {
        [System.Threading.CancellationTokenSource]$cts = new-object System.Threading.CancellationTokenSource([timespan]::FromSeconds(10))
    }

    process
    {
        try {
            $message = New-Object System.Net.Http.HttpRequestMessage
            $message.Method = $Method
            $message.RequestUri = [System.Uri]::new($Uri)
            $client = $factory.HttpClientFactory.GetHttpClient()
            $response = $client.SendAsync($message) | AwaitTask -CancellationTokenSource $cts
            if($response.StatusCode -eq [System.Net.HttpStatusCode]::Unauthorized -and $null -ne $response.Headers.WwwAuthenticate)
            {
                $popHeader = $response.Headers.WwwAuthenticate | Where-Object {$_.scheme -eq 'PoP'}
                if($null -ne $popHeader)
                {
                    $r = [Microsoft.Identity.Client.WwwAuthenticateParameters]::CreateFromAuthenticationHeaders($response.Headers, 'PoP')  
                    $r.Nonce
                }
            }
        }
        finally
        {
            if($null -ne $message)
            {
                $message.Dispose()
            }
        }
    }
    end
    {
        if($null -ne $cts)
        {
            $cts.Dispose()
        }
    }
}
function New-AadAuthenticationFactory
{
    <#
.SYNOPSIS
    Creates an authentication factory for Entra ID token acquisition.

.DESCRIPTION
    Creates a reusable authentication factory configured for public client,
    confidential client, resource owner password, broker, or managed identity
    authentication flows. If ClientId is omitted, the module uses its configured
    default Azure PowerShell client ID.

.PARAMETER DefaultScopes
    Default scopes requested when Get-AadToken is called without -Scopes.

.PARAMETER TenantId
    Tenant identifier or verified domain name. You can also use values such as
    organizations, common, or consumers where supported.

.PARAMETER ClientId
    Application client ID. If omitted, the module's default client ID is used.

.PARAMETER RedirectUri
    Redirect URI to use for public or confidential client authentication.

.PARAMETER ClientSecret
    Client secret used for confidential client authentication.

.PARAMETER ResourceOwnerCredential
    Credentials used for the resource owner password flow.

.PARAMETER X509Certificate
    Certificate used for confidential client authentication.

.PARAMETER Assertion
    Client assertion JWT used for federated confidential client authentication.

.PARAMETER LoginApi
    Base login endpoint. Defaults to the public Azure cloud endpoint.

.PARAMETER B2CPolicy
    Azure AD B2C policy name used to build the B2C authority.

.PARAMETER AuthMode
    Public client authentication mode: Interactive, DeviceCode, WIA, WAM, or Broker.

.PARAMETER DefaultUserName
    Optional login hint used by public client interactive authentication.

.PARAMETER UseManagedIdentity
    Creates a managed identity factory instead of an MSAL public or confidential client.

.PARAMETER Multicloud
    Enables multicloud token acquisition for supported public client scenarios.

.PARAMETER EnableExperimentalFeatures
    Enables MSAL experimental features on the created factory.

.PARAMETER WithClaimsRequestSupport
    Enables claims request support for public client flows.

.PARAMETER Name
    Optional case-insensitive name used to store the factory for later retrieval.

.PARAMETER Proxy
    Web proxy configuration used by the factory's HTTP client.

.OUTPUTS
    AadAuthenticationFactory object

.EXAMPLE
New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('https://my-db.documents.azure.com/.default') -AuthMode Interactive

Description
-----------
Creates a public client factory that can acquire delegated tokens interactively.

.EXAMPLE
$proxy=new-object System.Net.WebProxy('http://myproxy.mycompany.com:8080')
$proxy.BypassProxyOnLocal=$true
$factory = New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('https://eventgrid.azure.net/.default') -AuthMode DeviceCode -Proxy $proxy
$token = $factory | Get-AadToken

Description
-----------
Creates a device code factory that uses a custom outbound proxy.

.EXAMPLE
$creds = Get-Credential
New-AadAuthenticationFactory -Name 'Vault' -TenantId 'contoso.onmicrosoft.com' -ResourceOwnerCredential $creds -DefaultScopes 'https://vault.azure.net/.default'
$vaultToken = Get-AadToken -Factory (Get-AadAuthenticationFactory -Name 'Vault')

Description
-----------
Creates a named resource owner password factory and retrieves a token from it.

.EXAMPLE
New-AadAuthenticationFactory -ClientId '22222222-2222-2222-2222-222222222222' -ClientSecret $env:CLIENT_SECRET -TenantId 'contoso.onmicrosoft.com' -DefaultScopes @('https://graph.microsoft.com/.default')

Description
-----------
Creates a confidential client factory that acquires application tokens by using a client secret.

.EXAMPLE
New-AadAuthenticationFactory -ClientId '33333333-3333-3333-3333-333333333333' -TenantId 'contoso.onmicrosoft.com' -AuthMode Broker -DefaultScopes @('https://management.azure.com/.default')

Description
-----------
Creates a public client factory that uses the OS broker where available.
#>

    param
    (
        [Parameter()]
        [Alias("RequiredScopes")]
        [string[]]
            #Scopes to ask token for
        $DefaultScopes,

        [Parameter(Mandatory,ParameterSetName = 'ConfidentialClientWithAssertion')]
        [Parameter(Mandatory,ParameterSetName = 'ConfidentialClientWithSecret')]
        [Parameter(Mandatory,ParameterSetName = 'ConfidentialClientWithCertificate')]
        [Parameter(Mandatory,ParameterSetName = 'PublicClient')]
        [Parameter(Mandatory,ParameterSetName = 'ResourceOwnerPasssword')]
        [string]
            #Id of tenant where to autenticate the user. Can be tenant id, or any registerd DNS domain
            #You can also use one of AAD placeholders: organizations, common, consumers
        $TenantId,

        [Parameter()]
        [string]
            #ClientId of application that gets token
            #Default: well-known clientId for Azure PowerShell
        $ClientId,

        [Parameter()]
        [Uri]
            #RedirectUri for the client
            #Default: default MSAL redirect Uri
        $RedirectUri,

        [Parameter(ParameterSetName = 'ConfidentialClientWithSecret')]
        [string]
            #Client secret for ClientID
            #Used to get access as application rather than as calling user
        $ClientSecret,

        [Parameter(ParameterSetName = 'ResourceOwnerPasssword')]
        [pscredential]
            #Resource Owner username and password for public client ROPC flow
            #Used to get access as user specified by credential
            #Note: Does not work for federated authentication
        $ResourceOwnerCredential,

        [Parameter(ParameterSetName = 'ConfidentialClientWithCertificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
            #Authentication certificate for ClientID
            #Used to get access as application rather than as calling user
        $X509Certificate,

        [Parameter(ParameterSetName = 'ConfidentialClientWithAssertion')]
        [string]
            #Client assertion - JWT token created by external identity provider
            #Used to authenticate with federated identity
        $Assertion,

        [Parameter(ParameterSetName = 'ConfidentialClientWithAssertion')]
        [Parameter(ParameterSetName = 'ConfidentialClientWithSecret')]
        [Parameter(ParameterSetName = 'ConfidentialClientWithCertificate')]
        [Parameter(ParameterSetName = 'PublicClient')]
        [Parameter(ParameterSetName = 'ResourceOwnerPasssword')]
        [string]
            #AAD auth endpoint
            #Default: endpoint for public cloud
        $LoginApi = 'https://login.microsoftonline.com',
        
        [Parameter(ParameterSetName = 'ConfidentialClientWithAssertion')]
        [Parameter(ParameterSetName = 'ConfidentialClientWithSecret')]
        [Parameter(ParameterSetName = 'ConfidentialClientWithCertificate')]
        [Parameter(ParameterSetName = 'PublicClient')]
        [Parameter(ParameterSetName = 'ResourceOwnerPasssword')]
        [string]
            #Name of the B2C policy to use for login
            #Specifying this parameter means that you want to use B2B login and expects you to provide B2C tenant name in tenant ID
            #Default: endpoint for public cloud
        $B2CPolicy,

        [Parameter(Mandatory, ParameterSetName = 'PublicClient')]
        [ValidateSet('Interactive', 'DeviceCode', 'WIA', 'WAM', 'Broker')]
        [string]
            #How to authenticate client - via web view, via device code flow, or via Windows Integrated Auth
            #Used in public client flows
        $AuthMode,
        
        [Parameter(ParameterSetName = 'PublicClient')]
        [Alias("UserNameHint")]
        [string]
            #Username hint for authentication UI
            #Optional
        $DefaultUserName,

        [Parameter(ParameterSetName = 'MSI')]
        [Switch]
            #Tries to get parameters from environment and token from internal endpoint provided by Azure MSI support
        $UseManagedIdentity,

        [Parameter(ParameterSetName = 'PublicClient')]
        [Switch]
            #Enables support for multi-clud authentication, allowing to ask tokens for national clouds from global cloud
            #Only works with default clientId
        $Multicloud,

        [Switch]
            #Enables experimental features in MSAL
        $EnableExperimentalFeatures,

        [Parameter(ParameterSetName = 'PublicClient')]
        [switch]
            #Enables support for claims request in authentication
            #Only works with public client flows
        $WithClaimsRequestSupport,

        [Parameter()]
        [string]
            #Name of the factory. 
            #May be useful when creating more factories in one script
            #Name is case-insensitive
            #Optional
        $Name,

        [Parameter()]
        [System.Net.WebProxy]
            #Web proxy configuration
            #Optional
        $Proxy = $null
    )

    process
    {
        $module = $MyInvocation.MyCommand.Module
        $moduleName = $module.Name

        $moduleVersion = $module.Version
        if($null -ne $Module.privatedata.psdata.Prerelease) {$moduleVersion = "$moduleVersion`-$($Module.privatedata.psdata.Prerelease)"}

        $useDefaultCredentials = $false

        $defaultClientId = Get-AadDefaultClientId
        if([string]::IsNullOrEmpty($ClientId))
        {
            $ClientId = $defaultClientId
        }

        if([string]::IsNullOrEmpty($B2CPolicy))
        {
            $AuthorityUri = "$LoginApi/$TenantId"
        }
        else {
            $AuthorityUri = "$LoginApi/tfp/$TenantId/$B2CPolicy"
        }
        #setup of common options
        switch($PSCmdlet.ParameterSetName)
        {
            {$_ -in 'ConfidentialClientWithSecret','ConfidentialClientWithCertificate','ConfidentialClientWithAssertion'} {
                $opts = new-object Microsoft.Identity.Client.ConfidentialClientApplicationOptions
                $opts.ClientId = $clientId
                $opts.clientName = $moduleName
                $opts.ClientVersion = $moduleVersion

                if(-not [string]::IsNullOrEmpty($RedirectUri))
                {
                    $opts.RedirectUri = $RedirectUri
                }
                $builder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::CreateWithApplicationOptions($opts)
                if($_ -eq 'ConfidentialClientWithSecret')
                {
                    $builder = $builder.WithClientSecret($ClientSecret)
                }
                elseif($_ -eq 'ConfidentialClientWithAssertion')
                {
                    $builder = $builder.WithClientAssertion($Assertion)
                }
                else
                {
                    $builder = $builder.WithCertificate($X509Certificate)
                }
                
                if([string]::IsNullOrEmpty($B2CPolicy))
                {
                    $builder = $builder.WithAuthority($AuthorityUri)
                }
                else
                {
                    $builder = $builder.WithB2CAuthority($authorityUri)
                }

                $flowType = [AuthenticationFlow]::ConfidentialClient

                break;
            }
            {$_ -in 'PublicClient','ResourceOwnerPasssword'} {
                $opts = new-object Microsoft.Identity.Client.PublicClientApplicationOptions
                $opts.ClientId = $clientId
                $opts.clientName = $moduleName
                $opts.ClientVersion = $moduleVersion


                $builder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::CreateWithApplicationOptions($opts)

                if([string]::IsNullOrEmpty($B2CPolicy))
                {
                    $builder = $builder.WithAuthority($AuthorityUri)
                }
                else
                {
                    $builder = $builder.WithB2CAuthority($authorityUri)
                }
                if(-not [string]::IsNullOrEmpty($RedirectUri))
                {
                    $builder = $builder.WithRedirectUri($RedirectUri)
                }
                else
                {
                    $builder = $builder.WithDefaultRedirectUri()
                }
                if($Multicloud)
                {
                    $builder = $builder.WithMultiCloudSupport($true)
                }
                if($WithClaimsRequestSupport)
                {
                    $capabilities = new-object System.Collections.Generic.List[string]
                    $capabilities.Add("cp1") | Out-Null
                    $builder = $builder.WithClientCapabilities($capabilities)
                }
                if($_ -eq 'ResourceOwnerPasssword')
                {
                    $flowType = [AuthenticationFlow]::ResourceOwnerPassword
                }
                else
                {
                    switch ($AuthMode) {
                        'WIA' { 
                            if([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))
                            {
                                $flowType = [AuthenticationFlow]::PublicClientWithWia
                                $useDefaultCredentials = $true
                            }
                            else
                            {
                                throw New-Object System.PlatformNotSupportedException("WIA is only supported on Windows platform")
                            }
                            break 
                        }
                        'DeviceCode' { 
                            $flowType = [AuthenticationFlow]::PublicClientWithDeviceCode
                            break
                        }
                        {$_ -in 'WAM','Broker'} {
                            
                            $flowType = [AuthenticationFlow]::PublicClientWithWam
                            $os =
                            [Microsoft.Identity.Client.BrokerOptions+OperatingSystems]::Windows -bor
                            [Microsoft.Identity.Client.BrokerOptions+OperatingSystems]::Linux   -bor
                            [Microsoft.Identity.Client.BrokerOptions+OperatingSystems]::OSX

                            $brokerOptions = [Microsoft.Identity.Client.BrokerOptions]::new($os)
                            $brokerOptions.Title = "AadAuthenticationFactory"
                            $brokerOptions.ListOperatingSystemAccounts = $true
                            $builder = [Microsoft.Identity.Client.Broker.BrokerExtension]::WithBroker($builder,$brokerOptions)
                            $builder = $builder.WithParentActivityOrWindow([ParentWindowHelper]::ConsoleWindowHandleProvider)
                            $builder = $builder.WithRedirectUri("http://localhost")
                            break
                        }
                        Default {
                            $flowType = [AuthenticationFlow]::PublicClient
                            break
                        }
                    }
                }
                break;
            }
            'MSI' {
                if($clientId -eq $defaultClientId)
                {
                    $managedIdentityId = [Microsoft.Identity.Client.AppConfig.ManagedIdentityId]::SystemAssigned
                    $flowType = [AuthenticationFlow]::ManagedIdentity
                }
                else
                {
                    $managedIdentityId = [Microsoft.Identity.Client.AppConfig.ManagedIdentityId]::WithUserAssignedClientId($clientId)
                    $flowType = [AuthenticationFlow]::UserAssignedIdentity
                }
                $builder = [Microsoft.Identity.Client.ManagedIdentityApplicationBuilder]::Create($managedIdentityId)
               
                break;
            }
            default {
                throw (new-object System.ArgumentException("Unsupported flow type: $_"))
            }
        }
        #crate factory and add to builder
        $httpFactory = [GcMsalHttpClientFactory]::Create($proxy,$ModuleVersion,$useDefaultCredentials)
        $builder = $builder.WithHttpClientFactory($httpFactory)
        $builder = $builder.WithExperimentalFeatures($EnableExperimentalFeatures)

        #build the app and add processing info
        $factory = $builder.Build() `
        | Add-Member -MemberType NoteProperty -Name Name -Value $Name -PassThru `
        | Add-Member -MemberType NoteProperty -Name FlowType -Value $flowType -PassThru `
        | Add-Member -MemberType NoteProperty -Name DefaultScopes -Value $DefaultScopes -PassThru `
        | Add-Member -MemberType NoteProperty -Name DefaultUserName -Value $DefaultUserName -PassThru `
        | Add-Member -MemberType NoteProperty -Name ResourceOwnerCredential -Value $ResourceOwnerCredential -PassThru `
        | Add-Member -MemberType NoteProperty -Name B2CPolicy -Value $B2CPolicy -PassThru `
        | Add-Member -MemberType NoteProperty -Name TenantId -Value $TenantId -PassThru `
        | Add-Member -MemberType NoteProperty -Name HttpClientFactory -Value $httpFactory -PassThru

        #Give the factory common type name for formatting
        $factory.psobject.typenames.Insert(0,'GreyCorbel.Identity.Authentication.AadAuthenticationFactory')
        $script:AadLastCreatedFactory = $factory
        $script:AadAuthenticationFactories[$factory.Name] = $factory
        $factory
    }
}
function Test-AadToken
{
    <#
.SYNOPSIS
    Parses and validates an Entra ID token.

.DESCRIPTION
    Parses a JWT access token or ID token and validates its signature against the
    issuer's OpenID configuration and signing keys. The Token parameter accepts a
    raw JWT string, an AuthenticationResult returned by Get-AadToken, or a
    hashtable containing an Authorization header.
    Some tokens that contain nonce-related header data may not validate cleanly.
    See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609 for details.

.PARAMETER Token
    Raw JWT string, AuthenticationResult, or Authorization header hashtable.

.PARAMETER OidcConfigUri
    OpenID configuration endpoint to use instead of deriving it from the token.

.PARAMETER PayloadOnly
    Returns only the parsed payload claims instead of the full validation result.

.OUTPUTS
    Token validation result object or the parsed token payload

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('https://eventgrid.azure.net/.default') -AuthMode Interactive
$token = $factory | Get-AadToken
$token.idToken | Test-AadToken | fl

Description
-----------
Acquires a token, extracts the ID token, and validates it.

.EXAMPLE
New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('https://graph.microsoft.com/.default') -AuthMode Interactive
Get-AadToken | Test-AadToken -PayloadOnly

Description
-----------
Acquires an access token, validates it, and returns only the parsed claims.

.EXAMPLE
$headers = Get-AadToken -AsHashtable
Test-AadToken -Token $headers

Description
-----------
Validates a bearer token when it is supplied as an Authorization header hashtable.
#>
[CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [object]
            #IdToken or AccessToken field from token returned by Get-AadToken
            #or complete result of Get-AadToken - in such case, AccessToken is examined
        $Token,
        [Parameter()]
        [string]
            #OpenID configuration URI - if not provided, it's taken from token
        $OidcConfigUri,
        [switch]
            #Causes to retun just parsed payload of token - contains list of claims
        $PayloadOnly
    )

    process
    {
        if($token -is [Microsoft.Identity.Client.AuthenticationResult])
        {
            if($null -ne $token.AccessToken)
            {
                Write-Verbose 'Using AccessToken from provided token'
                $Token = $Token.AccessToken
            }
            else
            {
                if($null -ne $token.IdToken)
                {
                    Write-Verbose 'Using IdToken from provided token'
                    $Token = $Token.IdToken
                }
                else
                {
                    Write-Error 'Invalid format of provided token'
                    return
                }
            }
        }
        else
        {
            if($token -is [System.Collections.Hashtable])
            {
                if($null -ne $token['Authorization'])
                {
                    Write-Verbose 'Using AccessToken from provided hashtable'
                    $token = $token['Authorization'].Replace('Bearer ','')
                }
                else
                {
                    Write-Error 'Provided hashtable does not contain Authorization key'
                }
            }
            else
            {
                Write-Verbose 'Using provided plaintext token'
            }
        }
        $parts = $token.split('.')
        if($parts.Length -ne 3)
        {
            Write-Error 'Invalid format of provided token'
            return
        }
        
        Write-Verbose "Parsing the token"
        $result = [PSCustomObject]@{
            Header = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Base64UrlDecode -Data $parts[0]))) | ConvertFrom-Json
            Payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Base64UrlDecode -Data $parts[1]))) | ConvertFrom-Json
            IsValid = $false
        }

        try {
            if($null -eq $result.Payload.iss)
            {
                Write-Warning "Token does not contain issuer information --> most likely not valid AAD token. Cannot perform token validation against issuer's signature"
                return
            }
            #validate the token

            #validate the result using published keys
            if(-not [string]::IsNullOrEmpty($OidcConfigUri))
            {
                $endpoint = $OidcConfigUri
            }
            else
            {
                if($null -eq $result.Payload.tfp)
                {
                    #AAD token
                    $endpoint = $result.Payload.iss
                    if(-not $endpoint.EndsWith('/'))
                    {
                        $endpoint += '/'
                    }
                    $endpoint = "$endpoint`.well-known/openid-configuration"
                }
                else
                {
                    #AAD B2C token
                    Write-Verbose "It's B2C token"
                    $endpoint = $result.Payload.iss.Replace('/v2.0/','')
                    $endpoint = "$endpoint/$($result.Payload.tfp)/.well-known/openid-configuration"
                }
            }
            Write-Verbose "Getting openid configuration from $endpoint"
            try {
                $config = Invoke-RestMethod -Method Get -Uri $endpoint -ErrorAction Stop -Verbose:$false
            }
            catch {
                Write-Warning "Could not get openid configuration from endpoint $endpoint"
                return
            }
            $keysEndpoint = $config.jwks_uri
    
            Write-Verbose "Getting signing keys from $keysEndpoint"
            try {
                $signingKeys = Invoke-RestMethod -Method Get -Uri $keysEndpoint -ErrorAction Stop -Verbose:$false
            }
            catch {
                Write-Warning "Could not get signing keys from endpoint $keysEndpoint"
                return
            }
            Write-Verbose "Received $($signingKeys.keys.count) signing keys:"
            Write-Verbose ($signingKeys | ConvertTo-Json -Depth 9)
    
            $key = $signingKeys.keys | Where-object{$_.kid -eq $result.Header.kid}
            if($null -eq $key)
            {
                Write-Warning "Could not find signing key with id = $($result.Header.kid) on endpoint $keysEndpoint"
                return
            }
            Write-Verbose "Using key with kid: $($key.kid)"
    
            $rsa = $null
            if($null -ne $key.e -and $null -ne $key.n)
            {
                Write-Verbose "Getting public key from modulus $($key.n) and exponent $($key.e)"
                $exponent = Base64UrlDecode -data $key.e
                $exponent = [convert]::FromBase64String($exponent)
                $modulus = Base64UrlDecode -data $key.n
                $modulus = [convert]::FromBase64String($modulus)
                $rsa = new-object System.Security.Cryptography.RSACryptoServiceProvider
                $params = new-object System.Security.Cryptography.RSAParameters
                $params.Exponent = $exponent
                $params.Modulus = $modulus
                $rsa.ImportParameters($params)
            }
            else {
                if($null -ne $key.x5c)
                {
                    Write-Verbose "Getting public key from x5c: $($key.x5c)"
                    $cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($key.x5c[0]))
                    $rsa = $cert.PublicKey.Key
                }    
            }
    
            if($null -eq $rsa)
            {
                Write-Warning "Could not validate the token as both x5c and n/e information is missing"
                return
            }
    
            Write-Verbose "Creating payload to validate"
            $payload = "$($parts[0]).$($parts[1])"
            $dataToVerify = [System.Text.Encoding]::UTF8.GetBytes($payload)
            $sig = Base64UrlDecode -Data $parts[2]
            $signature = [Convert]::FromBase64String($sig)
    
            switch($result.Header.alg)
            {
                'RS384' {
                    $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA384
                    break;
                }
                'RS512' {
                    $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA512
                    break;
                }
                default {
                    $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
                    break;
                }
            }
            $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            Write-Verbose "Validating payload"
            $result.IsValid = $rsa.VerifyData($dataToVerify,$signature,$hash,$Padding)
            if($null -ne $cert) {$cert.Dispose()}
            if($null -ne $result.Header.nonce)
            {
                Write-Verbose "Header contains nonce, so token may not be properly validated. See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609"
            }
            $result.psobject.typenames.Insert(0,'GreyCorbel.Identity.Authentication.TokenValidationResult')
        }
        finally
        {
            if($PayloadOnly)
            {
                $result.Payload
            }
            else
            {
                $result
            }
        }
    }
}
#endregion Public commands
#region Internal commands
function Add-TypeSafePath {
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path $Path) {
        Add-Type -Path $Path -ErrorAction Stop | Out-Null
        return $true
    }
    return $false
}
enum AuthenticationFlow
{
    #Public client with browser based auth
    PublicClient
    #Public client with console based auth
    PublicClientWithDeviceCode
    #Public client with Windows Integrated auth
    PublicClientWithWia
    #Public client with Windows Authentication Broker
    PublicClientWithWam
    #Confidential client with client secret or certificate
    ConfidentialClient
    #Confidential client with System-assigned Managed identity or Arc-enabled server
    ManagedIdentity
    #Confidential client with User-assigned Managed identity
    UserAssignedIdentity
    #Unattended Resource Owner auth with username and password
    ResourceOwnerPassword
}
function AwaitTask {
    <#
        .SYNOPSIS
            Waits for the task to complete and returns the result.
        .DESCRIPTION
            Waits for the task to complete and returns the result. If the task is canceled, it will throw an exception.
        .PARAMETER task
            The task to wait for.
        .PARAMETER CancellationTokenSource
            The cancellation token source to cancel the authentication process if needed.
    #>
    param (
        [Parameter(ValueFromPipeline, Mandatory)]
        $task,
        [Parameter(Mandatory)]
        [System.Threading.CancellationTokenSource]$CancellationTokenSource
    )

    process {
        try {
            $errorHappened = $false
            while (-not $task.AsyncWaitHandle.WaitOne(200)) { }
            $rslt = $task.GetAwaiter().GetResult()
            $rslt
        }
        catch [System.OperationCanceledException]{
            $errorHappened = $true
            Write-Warning 'Authentication process has timed out'
        }
        catch {
            $errorHappened = $true
            throw $_.Exception
        }
        finally {
            if(-not $errorHappened -and $null -eq $rslt)
            {
                #we do not have result and did not went thru Catch block --> likely Ctrl+Break scenario
                #let`s cancel authentication in the factory
                $CancellationTokenSource.Cancel()
                Write-Verbose 'Authentication canceled by Ctrl+Break'
            }
        }
    }
}
function Base64UrlDecode
{
    param
    (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$Data
    )

    process
    {
        $result = $Data
        $result = $result.Replace('-','+').Replace('_','/')

        switch($result.Length % 4)
        {
            0 {break;}
            2 {$result = "$result=="; break}
            3 {$result = "$result="; break;}
            default {throw "Invalid data format"}
        }

        $result
    }
}
function Get-AssemblyVersionFromPath {
    param([Parameter(Mandatory)][string]$Path)

    try {
        return [AssemblyName]::GetAssemblyName($Path).Version
    } catch {
        return $null
    }
}
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
function Import-MsalNativeRuntime {
    param(
        [Parameter(Mandatory)] [string] $ModuleRoot
    )

    $rid = Get-MsalRuntimeRidFolder
    if ([string]::IsNullOrEmpty($rid)) { return }

    # IMPORTANT: your folder is lowercase "runtimes"
    $nativeDir = [Path]::Combine($ModuleRoot, 'runtimes', $rid, 'native')
    if (-not (Test-Path $nativeDir)) { return }

    $candidate = Get-ChildItem -Path $nativeDir -File |
        Where-Object {
            $_.Name -match '^msalruntime' -and $_.Extension -in @('.dll','.so','.dylib')
        } |
        Select-Object -First 1

    if (-not $candidate) {
        Write-Verbose "MSAL native runtime not found in $nativeDir"
        return
    }

    if ($PSEdition -eq 'Core') {
        [System.Runtime.InteropServices.NativeLibrary]::Load($candidate.FullName) | Out-Null
    }
    else {
        # Windows PowerShell 5.1 is Windows-only; LoadLibrary is fine
        if ($null -eq ('Kernel32' -as [type])) {
            $helperPath = [Path]::Combine($ModuleRoot, 'Helpers', 'Kernel32.cs')
            $helperDefinition = Get-Content $helperPath -Raw
            Add-Type -TypeDefinition $helperDefinition -ReferencedAssemblies @('System.Runtime.InteropServices') -WarningAction SilentlyContinue -IgnoreWarnings
        }
        [Kernel32]::LoadLibrary($candidate.FullName) | Out-Null
    }

    Write-Information "Loaded MSAL native runtime: $($candidate.FullName)"
}
function Init {
    param()

    process {
        $moduleRoot = $PSScriptRoot

        # Base referenced assemblies used for compiling helper .cs files
        $referencedAssemblies = @('System.Net.Http')

        # Some hosts require TLS 1.2; keep your existing behavior
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        } catch {
            # On newer .NET this may be ignored; safe to swallow
        }

        # Initialize cache for factories
        if ($null -eq $script:AadAuthenticationFactories -or -not ($script:AadAuthenticationFactories -is [hashtable])) {
            $script:AadAuthenticationFactories = @{}
        }

        # Determine whether MSAL is already loaded
        $msalAlreadyLoaded = $false
        $msalAssemblyPath  = $null
        $msalLoadedVersion = $null

        try {
            $existingType = [Microsoft.Identity.Client.PublicClientApplication]
            $msalAlreadyLoaded = $true
            $msalAssemblyPath  = $existingType.Assembly.Location
            $msalLoadedVersion = $existingType.Assembly.GetName().Version
            Write-Information "MSAL already loaded from: $msalAssemblyPath (v$msalLoadedVersion)"

            # --- Warnings ---
            # 1) Always warn that MSAL is already loaded (but keep it informative)
            Write-Information "MSAL already loaded in session: $msalAssemblyPath (v$msalLoadedVersion). AadAuthenticationFactory will reuse it."

            # 2) Warn if versions differ (this is the dangerous case)
            if ($moduleMsalVersion -and ($moduleMsalVersion -ne $msalLoadedVersion)) {
                Write-Warning "AadAuthenticationFactory ships MSAL v{0} at '{1}', but the session already loaded MSAL v{2} from '{3}'. PowerShell loads assemblies into a shared context, so version conflicts are common. If authentication fails, start a new session and import AadAuthenticationFactory first (before Az/Graph/EXO modules)." -f $moduleMsalVersion, $moduleMsalPath, $msalLoadedVersion, $msalAssemblyPath
            }

            # 3) If versions match but paths differ, warn at Verbose (or Warning if you prefer)
            elseif ($moduleMsalVersion -and ($moduleMsalPath -and ($moduleMsalPath -ne $msalAssemblyPath))) {
                Write-Information ("MSAL version matches (v{0}) but was loaded from a different path. `nModule path: '{1}'. ``nLoaded path: '{2}'." -f $msalLoadedVersion, $moduleMsalPath, $msalAssemblyPath)
            }
        } catch {
            # Not loaded yet
        }

        # --------------------------------------------------------
        # Select module-shipped MSAL directories
        # --------------------------------------------------------
        $sharedDir = $null
        $sharedMsalPath = $null

        if ($PSEdition -eq 'Core') {
            # PS7.3+: prefer netstandard2.0
            $sharedDir = Resolve-MsalSharedDirForCore -ModuleRoot $moduleRoot
            
            $brokerDir = [Path]::Combine($moduleRoot, 'shared', 'netstandard2.0')
            # Extra references commonly needed in PS Core for compiling helpers
            $referencedAssemblies += 'System.Net.Primitives'
            $referencedAssemblies += 'System.Net.WebProxy'
            $referencedAssemblies += 'System.Console'
            $referencedAssemblies += 'netstandard'
        }
        else {
            # Windows PowerShell 5.1: use net462
            $sharedDir = [Path]::Combine($moduleRoot, 'shared', 'net462')
            $brokerDir = [Path]::Combine($moduleRoot, 'shared', 'net462')
        }

        $sharedMsalPath = [Path]::Combine($sharedDir, 'Microsoft.Identity.Client.dll')
        $sharedMsalVersion = if (Test-Path $sharedMsalPath) { Get-AssemblyVersionFromPath -Path $sharedMsalPath } else { $null }

        # Broker bits are typically netstandard2.0
        $brokerDll = [Path]::Combine($brokerDir, 'Microsoft.Identity.Client.Broker.dll')
        $brokerVersion = if (Test-Path $brokerDll) { Get-AssemblyVersionFromPath -Path $brokerDll } else { $null }

        # --------------------------------------------------------
        # Load MSAL managed assemblies if not already loaded
        # --------------------------------------------------------
        if (-not $msalAlreadyLoaded) {
            if (-not (Test-Path $sharedMsalPath)) {
                throw "MSAL not found at $sharedMsalPath. Populate Shared folder appropriately."
            }

            Add-Type -Path $sharedMsalPath -ErrorAction Stop | Out-Null

            $msalAssemblyPath  = $sharedMsalPath
            $msalLoadedVersion = ([Assembly]::LoadFrom($sharedMsalPath)).GetName().Version
            Write-Information "Loaded MSAL from module: $msalAssemblyPath (v$msalLoadedVersion)"
        }
        else {
            # MSAL was already loaded; use it for helper compilation reference
            # Also, if your shipped broker version doesn't match MSAL, we may skip loading broker
            if ($sharedMsalVersion -and $msalLoadedVersion -and ($sharedMsalVersion -ne $msalLoadedVersion)) {
                Write-Information "Module-shipped MSAL version is $sharedMsalVersion but session already has $msalLoadedVersion. Will not attempt to load another MSAL copy."
            }
        }

        # Ensure helper compilation references MSAL assembly currently in use
        if ($msalAssemblyPath) {
            $referencedAssemblies += $msalAssemblyPath
        }

        # Desktop: ensure System.Net.Http is available
        if ($PSEdition -eq 'Desktop') {
            Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue | Out-Null
        }

        # --------------------------------------------------------
        # Load Broker (if not loaded) + native runtime (cross-platform)
        # --------------------------------------------------------
        $brokerTypePresent = ($null -ne ('Microsoft.Identity.Client.Broker.BrokerExtension' -as [type]))
        if (-not $brokerTypePresent) {

            # If MSAL already loaded from elsewhere, ensure broker version matches MSAL version before loading
            if ($msalLoadedVersion -and $brokerVersion -and ($msalLoadedVersion -ne $brokerVersion)) {
                Write-Warning ("MSAL version in session is {0} but module broker is {1}. Skipping broker load to avoid version conflicts. Broker-based auth may be unavailable; browser/device-code fallback still works." -f $msalLoadedVersion, $brokerVersion)
            }
            else {
                # Load broker extension assembly
                if (-not (Test-Path $brokerDll)) {
                    Write-Warning "Broker DLL not found at $brokerDll. Broker-based auth will be unavailable."
                }
                else {
                    Add-Type -Path $brokerDll -ErrorAction Stop | Out-Null

                    # Load native runtime for broker (Windows/Linux/macOS)
                    Import-MsalNativeRuntime -ModuleRoot $moduleRoot
                }
            }
        }

        # --------------------------------------------------------
        # Compile helper .cs files (your existing pattern)
        # --------------------------------------------------------
        $helpers = @('GcMsalHttpClientFactory', 'DeviceCodeHandler', 'ParentWindowHelper')

        foreach ($helper in $helpers) {
            if ($null -eq ($helper -as [type])) {
                
                $helperPath = [Path]::Combine($moduleRoot, 'Helpers', "$helper.cs")
                if (-not (Test-Path $helperPath)) {
                    Write-Warning "Helper $helper not found at $helperPath - skipping."
                    continue
                }

                Write-Information "Compiling helper $helper"
                $helperDefinition = Get-Content $helperPath -Raw

                Add-Type -TypeDefinition $helperDefinition `
                    -ReferencedAssemblies $referencedAssemblies `
                    -WarningAction SilentlyContinue -IgnoreWarnings | Out-Null
            }
        }

        Write-Information "Init completed. MSAL v$msalLoadedVersion; Broker loaded: $(-not (-not ('Microsoft.Identity.Client.Broker.BrokerExtension' -as [type])))"
    }
}
function Resolve-MsalSharedDirForCore {
    param([Parameter(Mandatory)][string]$ModuleRoot)

    # Prefer netstandard2.0 for PS7.3+ compatibility
    $ns2 = [Path]::Combine($ModuleRoot, 'shared', 'netstandard2.0')
    $ns2Msal = [Path]::Combine($ns2, 'Microsoft.Identity.Client.dll')

    if (Test-Path $ns2Msal) {
        return $ns2
    }

    # Optional: if you run on .NET 8+ you may choose net8.0
    $net8 = [Path]::Combine($ModuleRoot, 'shared', 'net8.0')
    $net8Msal = [Path]::Combine($net8, 'Microsoft.Identity.Client.dll')
    if (Test-Path $net8Msal) {
        Write-Warning "Shared\netstandard2.0\Microsoft.Identity.Client.dll not found. Falling back to Shared\net8.0. This may not work on PS7.3 if host runtime is not .NET 8."
        return $net8
    }

    throw "No compatible MSAL found. Expected at least $ns2Msal (recommended) or $net8Msal."
}
#endregion Internal commands
#region Module initialization
Init
#endregion Module initialization
