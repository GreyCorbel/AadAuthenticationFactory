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
            #Resource Owner username and password
            #Used to get access as user
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
        
        [Parameter(Mandatory, ParameterSetName = 'PublicClient')]
        [ValidateSet('Interactive', 'DeviceCode', 'WIA')]
        [string]
            #How to authenticate client - via web view, via device code flow, or via Windows Integrated Auth
            #Used in public client flows
        $AuthMode,
        
        [Parameter(ParameterSetName = 'PublicClient')]
        [string]
            #Username hint for authentication UI
            #Optional
        $UserNameHint,

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
        switch($PSCmdlet.ParameterSetName)
        {
            'ConfidentialClientWithSecret' {
                $script:AadLastCreatedFactory = new-object GreyCorbel.Identity.Authentication.AadAuthenticationFactory($tenantId, $ClientId, $clientSecret, $DefaultScopes, $LoginApi,$proxy)
                break;
            }
            'ConfidentialClientWithCertificate' {
                $script:AadLastCreatedFactory = new-object GreyCorbel.Identity.Authentication.AadAuthenticationFactory($tenantId, $ClientId, $X509Certificate, $DefaultScopes, $LoginApi,$proxy)
                break;
            }
            'PublicClient' {
                $script:AadLastCreatedFactory = new-object GreyCorbel.Identity.Authentication.AadAuthenticationFactory($tenantId, $ClientId, $DefaultScopes, $LoginApi, $AuthMode, $UserNameHint,$proxy)
                break;
            }
            'MSI' {
                $script:AadLastCreatedFactory = new-object GreyCorbel.Identity.Authentication.AadAuthenticationFactory($ClientId, $DefaultScopes,$proxy)
                break;
            }
            'ResourceOwnerPasssword' {
                $script:AadLastCreatedFactory = new-object GreyCorbel.Identity.Authentication.AadAuthenticationFactory($tenantId, $ClientId, $DefaultScopes, $ResourceOwnerCredential.UserName, $ResourceOwnerCredential.Password, $LoginApi,$proxy)
                break;
            }
        }
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
        [GreyCorbel.Identity.Authentication.AadAuthenticationFactory]
            #AAD authentication factory created via New-AadAuthenticationFactory
        $Factory = $script:AadLastCreatedFactory,
        [Parameter()]
        [Alias("RequiredScopes")]
            #Scopes to be returned in the token.
            #If not specified, returns token with default scopes provided when creating the factory
        [string[]]$Scopes = $null,
        [Parameter()]
            #Access token for user
            #Used to identify user in on-behalf-of flows
        [string]$UserToken,
            #When specified, hashtable with Authorization header is returned instead of token
            #This is shortcut to use when just need to have token for authorization header to call REST API (e.g. via Invoke-RestMethod)
            #When not specified, returns authentication result with tokens and other metadata
        [switch]$AsHashTable
    )

    process
    {
        Get-AadTokenInternal -Factory $factory -UserToken $UserToken -Scopes $Scopes 
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
        [string]
        #IdToken or AccessToken field from token returned by Get-AadToken
        $Token
    )

    process
    {
        $parts = $token.split('.')
        if($parts.Length -ne 3)
        {
            throw 'Invalid format of provided token'
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
        $result
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
function Init
{
    param()

    process
    {
        #load platform specific
        switch($PSEdition)
        {
            'Core'
            {
                #only load when not present
                try {
                    [Microsoft.Identity.Client.PublicClientApplication] | Out-Null
                }
                catch
                {
                    Add-type -Path "$PSScriptRoot\Shared\netcoreapp2.1\Microsoft.Identity.Client.dll"
                }
                break;
            }
            'Desktop'
            {
                #only load when not present
                try {
                    [Microsoft.Identity.Client.PublicClientApplication] | Out-Null
                }
                catch
                {
                    Add-Type -Path "$PSScriptRoot\Shared\net461\Microsoft.Identity.Client.dll"
                }
                #on desktop, this one is not pre-loaded
                Add-Type -Assembly System.Net.Http
                break;
            }
        }

        #load generic
        try {
            [GreyCorbel.Identity.Authentication.AadAuthenticationFactory] | Out-Null
        }
        catch
        {
            Add-Type -Path "$PSScriptRoot\Shared\netstandard2.0\GreyCorbel.Identity.Authentication.dll"
            #load binary module once.
            #Use Global so it's available in other commands of this module
            Import-Module "$PSScriptRoot\Shared\netstandard2.0\GreyCorbel.Identity.PSInternal.dll" -Scope Global
        }

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
}
#endregion

Init
