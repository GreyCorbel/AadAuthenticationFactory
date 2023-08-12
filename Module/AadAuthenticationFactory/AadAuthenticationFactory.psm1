#region Public commands
function Get-AadAccount
{
    <#
.SYNOPSIS
    Returns account(s) from AAD authentication factory cache

.DESCRIPTION
    For supported factory types, command returns either account(s) that match provided user account, or all accounts available in the cche.
    For unsupported factories (those working with Managed Identities) does not return anything

.OUTPUTS
    One or more accounts found in factory cache

.NOTES
    Command uses -match operator to match value of UserName parameter with usernames of accounts in factory's cache

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId mydomain.com  -RequiredScopes @('https://eventgrid.azure.net/.default') -AuthMode Interactive
Get-AadAccount -Factory $factory -All

Description
-----------
Returns all accounts from factory cache

.EXAMPLE
New-AadAuthenticationFactory -TenantId mydomain.com  -RequiredScopes @('https://eventgrid.azure.net/.default') -AuthMode Interactive
Get-AadAccount -UserName John

Description
-----------
Returns all accounts from factory cache that match pattern 'John'.

#>
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline, ParameterSetName = 'SpecificAcount')]
            #User name to get account information for
            #If not specified, all accounts cached in factory are returned
        [string]$UserName,
        [Parameter(ParameterSetName = 'All')]
            #tells the command to return all accounts available
        [switch]$All,
            #AAD authentication factory created via New-AadAuthenticationFactory
        $Factory = $script:AadLastCreatedFactory
    )

    begin
    {
        [System.Threading.CancellationTokenSource]$cts = new-object System.Threading.CancellationTokenSource([timespan]::FromSeconds(180))
    }
    process
    {
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

            switch($PSCmdlet.ParameterSetName)
            {
                'All' {
                    $allAccounts
                    break;
                }
                'SpecificAcount' {
                    if(-not [string]::IsNullOrEmpty($UserName))
                    {
                        $allAccounts | Where-Object{$_.UserName -match $Username}
                    }
                    else {
                        if($allAccounts.Count -gt 0)
                        {
                            $allAccounts[0]
                        }
                    }
                    break;
                }
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
function Get-AadToken
{
    <#
.SYNOPSIS
    Retrieves AAD token according to configuration of authentication factory

.DESCRIPTION
    Retrieves AAD token according to configuration of authentication factory

.OUTPUTS
    Authentication result from AAD with tokens and other information, or hashtable with Authorization header

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId mydomain.com  -RequiredScopes @('https://eventgrid.azure.net/.default') -AuthMode Interactive
$token = $factory | Get-AadToken

Description
-----------
Command creates authentication factory and retrieves AAD token from it, authenticating user via web view or browser

.EXAMPLE
$cosmosDbAccountName = 'myCosmosDBAcct
$factory = New-AadAuthenticationFactory -DefaultScopes @("https://$cosmosDbAccountName`.documents.azure.com/.default") -UseManagedIdentity
$token = $factory | Get-AadToken

Description
-----------
Command creates authentication factory and retrieves AAD token for access data plane of cosmos DB aaccount.
For details on CosmosDB RBAC access, see https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-setup-rbac

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId mydomain.com -AuthMode WIA
$token = $factory | Get-AadToken -Scopes @('https://eventgrid.azure.net/.default')

Description
-----------
Command creates authentication factory without default scopes and retrieves AAD token for access to event grid, specifying scopes when asking for token

.EXAMPLE
New-AadAuthenticationFactory -TenantId mydomain.com  -RequiredScopes @('api://mycompany.com/myapi/.default') -AuthMode WIA
$headers = Get-AadToken -AsHashtable
Invoke-RestMethod -Uri "https://myapi.mycomany.com/items" -Headers $headers 

Description
-----------
Command shows how to get token as hashtable containing properly formatted Authorization header and use it to authenticate call method on REST API

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
            #When specified, hashtable with Authorization header is returned instead of token
            #This is shortcut to use when just need to have token for authorization header to call REST API (e.g. via Invoke-RestMethod)
            #When not specified, returns authentication result with tokens and other metadata
        [switch]$AsHashTable,
            #Asks runtime to avoid token cache and get fresh token from AAD
            [switch]$forceRefresh,
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
            switch($Factory.FlowType)
            {
                ([AuthenticationFlow]::PublicClient) {
                    try
                    {
                        Write-Verbose "Getting token for $($account.Username)"
                        $task = $factory.AcquireTokenSilent($scopes,$account).WithForceRefresh($forceRefresh).ExecuteAsync($cts.Token)
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
                        Write-Verbose "Getting token for OperatingSystemAccount"
                        $account = [Microsoft.Identity.Client.PublicClientApplication]::OperatingSystemAccount
                    }
                    try
                    {
                        Write-Verbose "Getting token silently"
                        $task = $factory.AcquireTokenSilent($scopes,$account).WithForceRefresh($forceRefresh).ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    catch [Microsoft.Identity.Client.MsalUiRequiredException]
                    {
                        $windowHandle = [ParentWindowHelper]::GetConsoleOrTerminalWindow()
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
                        $task = $builder.WithParentActivityOrWindow($windowHandle).ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    break;
                }
                ([AuthenticationFlow]::PublicClientWithDeviceCode) {
                    try
                    {
                        Write-Verbose "Getting token for $($account.Username)"
                        $task = $factory.AcquireTokenSilent($scopes,$account).WithForceRefresh($forceRefresh).ExecuteAsync($cts.Token)
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
                            $task = $factory.AcquireTokenByUsernamePassword($Scopes, $UserName, $creds.GetNetworkCredential().Password).WithPrompt('ForceLogin').ExecuteAsync()
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
                        $task = $factory.AcquireTokenByUsernamePassword($Scopes, $UserName, $creds.GetNetworkCredential().Password).WithPrompt('ForceLogin').ExecuteAsync()
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    break;
                }
                ([AuthenticationFlow]::ConfidentialClient) {

                    Write-Verbose "Getting token for confidentioal client"
                    $task = $factory.AcquireTokenForClient($scopes).WithForceRefresh($forceRefresh).ExecuteAsync($cts.Token)
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
function New-AadAuthenticationFactory
{
    <#
.SYNOPSIS
    Creates authentication factory with provided parameters for Public or Confidential client flows

.DESCRIPTION
    Creates authentication factory with provided parameters for Public or Confidential client flows
    Authentication uses by default well-know clientId of Azure Powershell, but can accept clientId of app registered in your own tenant.

.OUTPUTS
    AadAuthenticationFactory object

.EXAMPLE
New-AadAuthenticationFactory -TenantId mydomain.com -RequiredScopes @('https://my-db.documents.azure.com/.default') -AuthMode Interactive

Description
-----------
This command returns AAD authentication factory for Public client auth flow with well-known clientId for Azure PowerShell and interactive authentication for getting tokens for CosmosDB account

.EXAMPLE
$proxy=new-object System.Net.WebProxy('http://myproxy.mycompany.com:8080')
$proxy.BypassProxyOnLocal=$true
$factory = New-AadAuthenticationFactory -TenantId mydomain.com  -RequiredScopes @('https://eventgrid.azure.net/.default') -AuthMode deviceCode -Proxy $proxy
$token = $factory | Get-AadToken

Description
-----------
Command works in on prem environment where access to internet is available via proxy. Command authenticates user with device code flow.

.EXAMPLE
$creds = Get-Credential
New-AadAuthenticationFactory -TenantId 'mytenant.com' -ResourceOwnerCredential $creds -RequiredScopes 'https://vault.azure.net/.default'
$vaultToken = Get-AadToken

Description
-----------
Command collects credentials of cloud-only account and authenticates with Resource Owner Password flow to get access token for Azure KeyVault.
Get-AadToken command uses implicit factory cached from last call of New-AadAuthenticationFactory
#>

    param
    (
        [Parameter()]
        [Alias("RequiredScopes")]
        [string[]]
            #Scopes to ask token for
        $DefaultScopes,

        [Parameter(Mandatory,ParameterSetName = 'ConfidentialClientWithSecret')]
        [Parameter(Mandatory,ParameterSetName = 'ConfidentialClientWithCertificate')]
        [Parameter(Mandatory,ParameterSetName = 'PublicClient')]
        [Parameter(Mandatory,ParameterSetName = 'ResourceOwnerPasssword')]
        [string]
            #Id of tenant where to autenticate the user. Can be tenant id, or any registerd DNS domain
            #You can also use AAD placeholder: organizations, common, consumers
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

        [Parameter(ParameterSetName = 'ConfidentialClientWithSecret')]
        [Parameter(ParameterSetName = 'ConfidentialClientWithCertificate')]
        [Parameter(ParameterSetName = 'PublicClient')]
        [Parameter(ParameterSetName = 'ResourceOwnerPasssword')]
        [string]
            #AAD auth endpoint
            #Default: endpoint for public cloud
        $LoginApi = 'https://login.microsoftonline.com',
        
        [Parameter(ParameterSetName = 'ConfidentialClientWithSecret')]
        [Parameter(ParameterSetName = 'ConfidentialClientWithCertificate')]
        [Parameter(ParameterSetName = 'PublicClient')]
        [Parameter(ParameterSetName = 'ResourceOwnerPasssword')]
        [string]
            #Name of the B2C policy to use for login
            #Specifying this parameter means that you want to use B2B logig and expects you to provide B2C tenant name in tenant ID
            #Default: endpoint for public cloud
        $B2CPolicy,

        [Parameter(Mandatory, ParameterSetName = 'PublicClient')]
        [ValidateSet('Interactive', 'DeviceCode', 'WIA', 'WAM')]
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
            #tries to get parameters from environment and token from internal endpoint provided by Azure MSI support
        $UseManagedIdentity,

        [Parameter()]
        [System.Net.WebProxy]
            #Web proxy configuration
            #Optional
        $proxy = $null
    )

    process
    {
        $ModuleManifest = Import-PowershellDataFile $PSCommandPath.Replace('.psm1', '.psd1')
        $moduleName = [system.io.path]::GetFileNameWithoutExtension($PSCommandPath)
        $moduleVersion = $moduleManifest.ModuleVersion
        if($null -ne $ModuleManifest.privatedata.psdata.Prerelease) {$moduleVersion = "$moduleVersion`-$($ModuleManifest.privatedata.psdata.Prerelease)"}

        $useDefaultCredentials = $false
        if([string]::IsNullOrWhiteSpace($clientId)) {$clientId = $ModuleManifest.PrivateData.Configuration.DefaultClientId}

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
            {$_ -in 'ConfidentialClientWithSecret','ConfidentialClientWithCertificate'} {
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
                        'WAM' {
                            if([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows))
                            {
                                $flowType = [AuthenticationFlow]::PublicClientWithWam
                                $opts = new-object Microsoft.Identity.Client.BrokerOptions('Windows')
                                $builder = [Microsoft.Identity.Client.Broker.BrokerExtension]::WithBroker($builder,$opts)
                            }
                            else
                            {
                                throw New-Object System.PlatformNotSupportedException("WAM is only supported on Windows platform")
                            }
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
                if($clientId -eq $ModuleManifest.PrivateData.Configuration.DefaultClientId)
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
        $httpFactory = [GcMsalHttpClientFactory]::Create($proxy,$moduleManifest.ModuleVersion,$useDefaultCredentials)
        $builder = $builder.WithHttpClientFactory($httpFactory)

        #build the app and add processing info
        $script:AadLastCreatedFactory = $builder.Build() `
        | Add-Member -MemberType NoteProperty -Name FlowType -Value $flowType -PassThru `
        | Add-Member -MemberType NoteProperty -Name DefaultScopes -Value $DefaultScopes -PassThru `
        | Add-Member -MemberType NoteProperty -Name DefaultUserName -Value $DefaultUserName -PassThru `
        | Add-Member -MemberType NoteProperty -Name ResourceOwnerCredential -Value $ResourceOwnerCredential -PassThru `
        | Add-Member -MemberType NoteProperty -Name B2CPolicy -Value $B2CPolicy -PassThru

        #Give the factory common type name for formatting
        $script:AadLastCreatedFactory.psobject.typenames.Insert(0,'GreyCorbel.Identity.Authentication.AadAuthenticationFactory')
        $script:AadLastCreatedFactory 
    }
}
function Test-AadToken
{
    <#
.SYNOPSIS
    Parses and validates AAD-issued token

.DESCRIPTION
    Parses provided IdToken or AccessToken and checks for its validity.
    Note that some tokens may not be properly validated - this is in case then 'nonce' field present and set in the haeder. AAD issues such tokens for Graph API and nonce is taken into consideration when validating the token.
    See discussion at https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609 for more details.

.OUTPUTS
    Parsed token and information about its validity

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId mydomain.com  -RequiredScopes @('https://eventgrid.azure.net/.default') -AuthMode Interactive
$token = $factory | Get-AadToken
$token.idToken | Test-AadToken | fl

Description
-----------
Command creates authentication factory, asks it to issue token for EventGrid and parses IdToken and validates it

.EXAMPLE
New-AadAuthenticationFactory -TenantId mydomain.com  -DefaultScopes @('https://graph.microsoft.com/.default') -AuthMode Interactive
Get-AadToken | Test-AadToken -PayloadOnly

Description
-----------
Command creates authentication factory, asks it to issue token for MS Graph and parses AccessToken (this is token to use when passing complete response from Get-AadToken), validates it and shows claims contained
#>
[CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [object]
        #IdToken or AccessToken field from token returned by Get-AadToken
        #or complete result of Get-AadToken - in such case, AccessToken is examined
        $Token,
        [switch]
        $PayloadOnly
    )

    process
    {
        if($token -is [Microsoft.Identity.Client.AuthenticationResult])
        {
            $Token = $Token.AccessToken
        }
        if($token -is [System.Collections.Hashtable])
        {
            $token = $token['Authorization'].Replace('Bearer ','')
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

        #validate the result using published keys
        if($null -eq $result.Payload.tfp)
        {
            #AAD token
            Write-Verbose "It's standard AAD token"
            $endpoint = $result.Payload.iss.Replace('/v2.0','')
            $keysEndpoint = "$($endpoint)/discovery/v2.0/keys"
        }
        else
        {
            #AAD B2C token
            Write-Verbose "It's B2C token"
            $endpoint = $result.Payload.iss.Replace('/v2.0/','')
            $keysEndpoint = "$endpoint/$($result.Payload.tfp)/discovery/v2.0/keys"
        }

        Write-Verbose "Getting signing keys from $keysEndpoint"
        $signingKeys = Invoke-RestMethod -Method Get -Uri $keysEndpoint
        Write-Verbose "Received $($signingKeys.keys.count) signing keys:"
        Write-Verbose ($signingKeys | ConvertTo-Json -Depth 9)

        $key = $signingKeys.keys | Where-object{$_.kid -eq $result.Header.kid}
        if($null -eq $key)
        {
            Write-Warning "Could not find signing key with id = $($result.Header.kid) on endpoint $keysEndpoint"
            return $result
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
            return $result
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
#endregion Public commands
#region Internal commands
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
                $referencedAssemblies+=[System.IO.Path]::Combine($PSHome,'System.Net.Primitives.dll')
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
                        Add-Type -Path [System.IO.Path]::Combine([string[]]($PSScriptRoot,'Shared','net461','Microsoft.Identity.Client.Broker.dll'))
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
#endregion Internal commands
#region Module initialization
Init
#endregion Module initialization
