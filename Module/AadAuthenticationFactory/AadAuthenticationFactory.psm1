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
        [ValidateSet('AzurePublic', 'AzureGermany', 'AzureChina','AzureUsGovernment','None')]
        [string]
            #AAD auth endpoint
            #Default: endpoint for public cloud
        $AzureCloudInstance = 'AzurePublic',
        
        [Parameter(Mandatory, ParameterSetName = 'PublicClient')]
        [ValidateSet('Interactive', 'DeviceCode', 'WIA')]
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
        $useDefaultCredentials = $false
        if([string]::IsNullOrWhiteSpace($clientId)) {$clientId = $ModuleManifest.PrivateData.Configuration.DefaultClientId}

        #setup of common options
        switch($PSCmdlet.ParameterSetName)
        {
            {$_ -in 'ConfidentialClientWithSecret','ConfidentialClientWithCertificate'} {
                $opts = new-object Microsoft.Identity.Client.ConfidentialClientApplicationOptions
                $opts.ClientId = $clientId
                $opts.clientName = $moduleName
                $opts.ClientVersion = $moduleVersion
                $opts.AzureCloudInstance = $AzureCloudInstance
                $opts.TenantId = $tenantId

                $builder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::CreateWithApplicationOptions($opts)
                $builder = $builder.WithClientSecret($ClientSecret)

                $flowType = [AuthenticationFlow]::ConfidentialClient

                break;
            }
            {$_ -in 'PublicClient','ResourceOwnerPasssword'} {
                $opts = new-object Microsoft.Identity.Client.PublicClientApplicationOptions
                $opts.ClientId = $clientId
                $opts.clientName = $moduleName
                $opts.ClientVersion = $moduleVersion
                $opts.AzureCloudInstance = $AzureCloudInstance
                $opts.TenantId = $tenantId

                $builder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::CreateWithApplicationOptions($opts)
                $builder = $builder.WithDefaultRedirectUri()

                if($_ -eq 'ResourceOwnerPasssword')
                {
                    $flowType = [AuthenticationFlow]::ResourceOwnerPassword
                }
                else
                {
                    switch ($AuthMode) {
                        'WIA' { 
                            $flowType = [AuthenticationFlow]::PublicClientWithWia
                            $useDefaultCredentials = $true
                            break 
                        }
                        'DeviceCode' { 
                            $flowType = [AuthenticationFlow]::PublicClientWithDeviceCode
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
        | Add-Member -MemberType NoteProperty -Name ResourceOwnerCredential -Value $ResourceOwnerCredential -PassThru

        #Give the factory common type name for formatting
        $script:AadLastCreatedFactory.psobject.typenames.Insert(0,'AadAuthenticationFactory')
        $script:AadLastCreatedFactory 
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
        [Parameter(ValueFromPipeline)]
        #[GreyCorbel.Identity.Authentication.AadAuthenticationFactory]
            #AAD authentication factory created via New-AadAuthenticationFactory
        $Factory = $script:AadLastCreatedFactory,
        [Parameter()]
        [Alias("RequiredScopes")]
            #Scopes to be returned in the token.
            #If not specified, returns token with default scopes provided when creating the factory
        [string[]]$Scopes = $null,
        [Parameter()]
            #User name hint for authentication process
        [string]$UserName = $null,
        [Parameter()]
            #Access token for user
            #Used to identify user in on-behalf-of flows
        [string]$UserToken,
            #When specified, hashtable with Authorization header is returned instead of token
            #This is shortcut to use when just need to have token for authorization header to call REST API (e.g. via Invoke-RestMethod)
            #When not specified, returns authentication result with tokens and other metadata
        [switch]$AsHashTable,
            #Asks runtime to avoid token cache and get fresh token from AAD
            [switch]$forceRefresh
    )

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
                throw (new-object System.ArgumentException("No scopes scecified"))
            }
        }

        if([string]::IsNullOrWhiteSpace($UserName))
        {
            $UserName = $factory.DefaultUserName
        }

        try {
            [System.Threading.CancellationTokenSource]$cts = new-object System.Threading.CancellationTokenSource([timespan]::FromSeconds(180))
            
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
                if($factory.FlowType -in [AuthenticationFlow]::PublicClientWithWia, [AuthenticationFlow]::PublicClientWithDeviceCode, [AuthenticationFlow]::PublicClient)
                {
                    $accounts = $Factory.GetAccountsAsync() | AwaitTask -CancellationTokenSource $cts
                    if($null -ne $accounts -and -not [string]::IsNullOrWhiteSpace($Username))
                    {
                        $account = $accounts | Where-Object{$_.UserName -eq $Username}
                    }
                    else {$account = $null}
                }
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
        finally {
            if($null -ne $cts)
            {
                $cts.Dispose()
            }
        }
    }
}

function Test-AadToken
{
    <#
.SYNOPSIS
    Parses and validates AAD issues token

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
        $parts = $token.split('.')
        if($parts.Length -ne 3)
        {
            Write-Error 'Invalid format of provided token'
            return
        }
        
        $result = [PSCustomObject]@{
            Header = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Base64UrlDecode -Data $parts[0]))) | ConvertFrom-Json
            Payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Base64UrlDecode -Data $parts[1]))) | ConvertFrom-Json
            IsValid = $false
        }

        #validate the result using published keys
        $endpoint = $result.Payload.iss.Replace('/v2.0','/')

        $signingKeys = Invoke-RestMethod -Method Get -Uri "$($endpoint)discovery/keys"

        $key = $signingKeys.keys | Where-object{$_.kid -eq $result.Header.kid}
        if($null -eq $key)
        {
            throw "Could not find signing key with id = $($result.Header.kid)"
        }
        $cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($key.x5c[0]))
        $rsa = $cert.PublicKey.Key

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
        $result.IsValid = $rsa.VerifyData($dataToVerify,$signature,$hash,$Padding)
        $cert.Dispose()
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

#region Internals
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


function Init
{
    param()

    process
    {
        $httpFactoryDefinition = @'
        using Microsoft.Identity.Client;
        using System.Net;
        using System.Net.Http;

        public class GcMsalHttpClientFactory : Microsoft.Identity.Client.IMsalHttpClientFactory
        {
            static HttpClient _httpClient;

            protected GcMsalHttpClientFactory(WebProxy proxy, string productVersion, bool useDefaultCredentials = false)
            {
                if (null == _httpClient)
                {
                    var httpClientHandler = new HttpClientHandler()
                    {
                        UseDefaultCredentials = useDefaultCredentials
                    };

                    if (null != proxy)
                    {
                        httpClientHandler.Proxy = proxy;
                        httpClientHandler.UseProxy = true;
                    }
                    _httpClient = new HttpClient(httpClientHandler);

                    _httpClient.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("AadAuthenticationFactory", productVersion));
                }
            }

            public HttpClient GetHttpClient()
            {
                return _httpClient;
            }

            //PS5 has trouble to get interface from object instance
            public static Microsoft.Identity.Client.IMsalHttpClientFactory Create(WebProxy proxy, string productVersion, bool useDefaultCredentials = false)
            {
                return new GcMsalHttpClientFactory(proxy, productVersion,useDefaultCredentials);
            }
        }
'@

        $deviceCodeHandlerDefinition = @'
        public class DeviceCodeHandler
        {
            static System.Threading.Tasks.Task _Delegate(Microsoft.Identity.Client.DeviceCodeResult deviceCodeResult)
            {
                System.Console.WriteLine(deviceCodeResult.Message);
                return System.Threading.Tasks.Task.FromResult(0);
            }

            //PS5 has trouble to get correct type when returning static method directly
            public static System.Func<Microsoft.Identity.Client.DeviceCodeResult,System.Threading.Tasks.Task> Get()
            {
                return _Delegate;
            }
        }
'@
        $referencedAssemblies = @('System.Net.Http')
        #load platform specific
        switch($PSEdition)
        {
            'Core'
            {
                $referencedAssemblies+="$PSScriptRoot\Shared\net6.0\Microsoft.Identity.Client.dll"
                $referencedAssemblies+="$PSHome\System.Net.Primitives.dll"
                $referencedAssemblies+="System.Net.WebProxy"
                $referencedAssemblies+="System.Console"

                try {
                    [Microsoft.Identity.Client.PublicClientApplication] | Out-Null
                }
                catch
                {
                    Add-Type -Path "$PSScriptRoot\Shared\net6.0\Microsoft.IdentityModel.Abstractions.dll"
                    Add-Type -Path "$PSScriptRoot\Shared\net6.0\Microsoft.Identity.Client.dll"
                }

                break;
            }
            'Desktop'
            {
                $referencedAssemblies+="$PSScriptRoot\Shared\net461\Microsoft.Identity.Client.dll"
                #only load when not present
                try {
                    [Microsoft.Identity.Client.PublicClientApplication] | Out-Null
                }
                catch
                {
                    Add-Type -Path "$PSScriptRoot\Shared\net461\Microsoft.IdentityModel.Abstractions.dll"
                    Add-Type -Path "$PSScriptRoot\Shared\net461\Microsoft.Identity.Client.dll"
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
            Add-Type -TypeDefinition $httpFactoryDefinition -ReferencedAssemblies $referencedAssemblies -WarningAction SilentlyContinue -IgnoreWarnings
        }
        if($null -eq ('DeviceCodeHandler' -as [type])) {
            #check if we need to load or already loaded
            Add-Type -TypeDefinition $deviceCodeHandlerDefinition -ReferencedAssemblies $referencedAssemblies -WarningAction SilentlyContinue -IgnoreWarnings        
        }
    }

}


enum AuthenticationFlow
{
    #Public client with browser based auth
    PublicClient
    #Public client with console based auth
    PublicClientWithDeviceCode
    #Public client with Windows Integrated auth
    PublicClientWithWia
    #Confidential client with client secret or certificate
    ConfidentialClient
    #Confidential client with System-assigned Managed identity or Arc-enabled server
    ManagedIdentity
    #Confidential client with User-assigned Managed identity
    UserAssignedIdentity
    #Unattended Resource Owner auth with username and password
    ResourceOwnerPassword
}

#endregion

Init
