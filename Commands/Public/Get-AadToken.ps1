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
                $account = $account[0]
            }
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
                        $builder = $factory.AcquireTokenSilent($scopes,$account)
                        $builder = $builder.WithForceRefresh($forceRefresh)
                        if(-not [string]::IsNullOrEmpty($PoPRequestUri))
                        {
                            Write-Verbose "Requesting PoP nonce from resource server for Uri: $PoPRequestUri and http method $PopHttpMethod"
                            $PopNonce = Get-PoPNonce -Uri $PoPRequestUri -Method $PopHttpMethod -Factory $Factory
                            if($null -eq $PopNonce)
                            {
                                throw (new-object System.ArgumentException("Resource does not support PoP authentication scheme"))
                            }
                            $builder = $builder.WithProofOfPossession($PopNonce, $PopHttpMethod, $PoPRequestUri)
                        }
                        $task = $builder.ExecuteAsync($cts.Token)
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
                        if(-not [string]::IUsNullOrEmpty($popNonce))
                        {
                            Write-Verbose "Requesting PoP token interactively"
                            $builder = $builder.WithProofOfPossession($PopNonce, $PopHttpMethod, $PoPRequestUri)
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
