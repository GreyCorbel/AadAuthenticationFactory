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
            $task = $Factory.AcquireTokenOnBehalfOf($Scopes, $assertion).ExecuteAsync($cts.Token)
        }
        else
        {
            $account = Get-AadAccount -UserName $UserName -Factory $Factory
            switch($Factory.FlowType)
            {
                ([AuthenticationFlow]::PublicClient) {
                    try
                    {
                        $task = $factory.AcquireTokenSilent($scopes,$account).WithForceRefresh($forceRefresh).ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    catch [Microsoft.Identity.Client.MsalUiRequiredException]
                    {
                        $task = $factory.AcquireTokenInteractive($Scopes).ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    break;
                }
                ([AuthenticationFlow]::PublicClientWithWia) {
                    if($null -ne $Account)
                    {
                        $task = $factory.AcquireTokenSilent($Scopes, $account).WithForceRefresh($forceRefresh).ExecuteAsync()
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    else
                    {
                        $task = $factory.AcquireTokenByIntegratedWindowsAuth($Scopes).WithUserName($UserName).ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                        #let the app throw to caller when UI required as the purpose here is to stay silent
                    }
                    break;
                }
                ([AuthenticationFlow]::PublicClientWithWam) {
                    if($null -eq $Account) {$account = [Microsoft.Identity.Client.PublicClientApplication]::OperatingSystemAccount}
                    try
                    {
                        $task = $factory.AcquireTokenSilent($scopes,$account).WithForceRefresh($forceRefresh).ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    catch [Microsoft.Identity.Client.MsalUiRequiredException]
                    {
                        $task = $factory.AcquireTokenInteractive($Scopes).WithAccount($account).WithParentActivityOrWindow().ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    break;
                }
                ([AuthenticationFlow]::PublicClientWithDeviceCode) {
                    try
                    {
                        $task = $factory.AcquireTokenSilent($scopes,$account).WithForceRefresh($forceRefresh).ExecuteAsync($cts.Token)
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    catch [Microsoft.Identity.Client.MsalUiRequiredException]
                    {
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
                            $task = $factory.AcquireTokenByUsernamePassword($Scopes, $UserName, $creds.GetNetworkCredential().Password).WithPrompt('ForceLogin').ExecuteAsync()
                            $rslt = $task | AwaitTask -CancellationTokenSource $cts
                        }
                        else
                        {
                            $task = $factory.AcquireTokenSilent($scopes,$account).ExecuteAsync($cts.Token)
                            $rslt = $task | AwaitTask -CancellationTokenSource $cts
                        }
                    }
                    catch [Microsoft.Identity.Client.MsalUiRequiredException]
                    {
                        $task = $factory.AcquireTokenByUsernamePassword($Scopes, $UserName, $creds.GetNetworkCredential().Password).WithPrompt('ForceLogin').ExecuteAsync()
                        $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    }
                    break;
                }
                ([AuthenticationFlow]::ConfidentialClient) {

                    $task = $factory.AcquireTokenForClient($scopes).WithForceRefresh($forceRefresh).ExecuteAsync($cts.Token)
                    $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    break
                }
                ([AuthenticationFlow]::ManagedIdentity) {
                    $task = $Factory.AcquireTokenForManagedIdentity($scopes).WithForceRefresh($forceRefresh).ExecuteAsync()
                    $rslt = $task | AwaitTask -CancellationTokenSource $cts
                    break
                }
                ([AuthenticationFlow]::UserAssignedIdentity) {
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
            $cts.Dispose()
        }
    }
}
