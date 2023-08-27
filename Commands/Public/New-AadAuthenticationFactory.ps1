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
        $ClientId = (Get-AadDefaultClientId),

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
        $module = $MyInvocation.MyCommand.Module
        $moduleName = $module.Name

        $moduleVersion = $module.Version
        if($null -ne $Module.privatedata.psdata.Prerelease) {$moduleVersion = "$moduleVersion`-$($Module.privatedata.psdata.Prerelease)"}

        $useDefaultCredentials = $false

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
                if($clientId -eq (Get-AadDefaultClientId) -or [string]::IsNullOrEmpty($clientId))
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