# AadAuthenticationFactory
This module provides unified experience for getting and using tokens from Azure AD authentication platform. Experience covers this authentication scenarios:
  - **Interactive authentication with Public client flow and Delegated permissions**. Uses standard MSAL implementation of Public flow with Browser based interactive authentication, or Device code authentication
  - **Non-interactive authentication with Confidential client flow and Application permissions**. Uses standard MSAL implementation of Confidential client with authentication via Client Secret of via X.509 certificate
  - **Non-Interactive authentication via Azure Managed Identity**, usable on Azure VMs, Azure App Services, Azure Functions, Automation accounts and Arc enabled servers, or other platforms that support Azure Managed identity. Supports both System Managed Identity or User Managed Identity.

Module comes with commands:

|Command|Usage|
|:------|:----|
|New-AadAuthenticationFactory | Creates factory responsible for issuing of AAD tokens for given resource, using given authentication flow|
|Get-AAdToken|Tells the factory to create a token. Factory returns cached token, if available, and takes care of token renewals silently whenever possible, after tokens expire|
|Test-AadToken|Parses Access token or Id token and validates it against published keys. Provides PowerShell way of showing token content as available in http://jwt.ms|

Module is usable two ways:
- as standalone module to provide Azure tokens ad-hoc or in scripts
- by other modules to provide instant Azure authentication services without the need to implement them - just make dependency on AadAuthenticationFactory module in other module and use it to get tokens for resources as you need. This is demonstrated by [CosmosLite module](https://github.com/jformacek/CosmosLite)

# Examples
Sections below provide example of various way of getting autthenticated with the module.
## Simple usage with single factory and default Public client
Module caches most-recently created factory. Factory uses Client Id of Azure Powershell app provided by MS. Sample uses browser based authentication and gives Delegated permissions configured for Azure Powershell for Graph API to calling user.  
Sample demonstrates examination of resulting Access and ID tokens issued for calling of Graph API.  
*Note*: Access tokens for Graph API fail to validate - this is by design according to MS - see discussion here: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609
```powershell
#create authnetication factory and cache it inside module
New-AadAuthenticationFactory -TenantId mytenant.com -DefaultScopes 'https://graph.microsoft.com/.default' -AuthMode Interactive | Out-Null

#ask for token
$Token = Get-AadToken

#examine access token data
$Token.AccessToken | Test-AadToken | Select -Expand Payload
#examine ID token data
$Token.IdToken | Test-AadToken | Select -Expand Payload
```

## Simple usage with single factory and custom client with client secret
Module caches most-recently created factory. Factory uses custom Client Id with client secret.
```powershell
$appId = '1b69b00f-08f0-4798-9976-af325f7f7526'
$secret = 'xxxx'
#create authnetication factory and cache it inside module
New-AadAuthenticationFactory -TenantId mytenant.com -ClientId $appId -ClientSecret  $secret | Out-Null

#ask for token
$Token = Get-AadToken -Scopes 'https://graph.microsoft.com/.default'

#examine access token data
$Token.AccessToken | Test-AadToken | Select -Expand Payload
#examine ID token data
$Token.IdToken | Test-AadToken | Select -Expand Payload
```

## Custom app and certificate auth with Confidential client
This sample creates authentication factory for getting tokens for different resources for application that uses X.509 certificate for authentication.

```powershell
#load certificate for auth
$thumbprint = 'e827f78a78cf532eb539479d6afe9c7f703173d5'
$appId = '1b69b00f-08f0-4798-9976-af325f7f7526'
$cert = dir Cert:\CurrentUser\My\ | where-object{$_.Thumbprint -eq $thumbprint}

#create factory for issuing of tokens for Graph Api and Azure KeyVault.
#single factory can issue tokens for multiple resources/scopes
$factory = New-AadAuthenticationfactory -tenantId mydomain.com -ClientId $appId -X509Certificate $cert -DefaultScopes 'https://graph.microsoft.com/.default'

#get tokens
$graphToken = Get-AadToken -Factory $factory
$vaultToken = $factory | Get-AadToken -Scopes 'https://vault.azure.net/.default'

#examine tokens
Test-AadToken -Token $graphToken.AccessToken
Test-AadToken -Token $vaultToken.AccessToken
```

## System assigned Managed identity or Arc-enabled server
This sample assumes that code runs in environment supporting Azure Managed identity and uses it to get tokens.
```powershell
#create factory that uses managed identity, without scopes
#factory is stored is session varioable so no need to store it explictly if it is single factory used
New-AadAuthenticationfactory -UseManagedIdentity | Out-Null

#get tokens from factory stored in session variable
$configToken = Get-AadToken -Scopes 'https://azconfig.io'
$vaultToken =  Get-AadToken -Scopes 'https://vault.azure.net'
```
## User assigned Managed identity
This sample assumes that code runs in environment supporting Azure Managed identity and uses it to get tokens.
```powershell
#create a factory with default scopes
New-AadAuthenticationfactory -DefaultScopes 'https://azconfig.io/.default' -UseManagedIdentity -ClientId '3a174b1e-7b2a-4f21-a326-90365ff741cf'
#retrieve a token from  factory and examine it
Get-AadToken | Select-object -expandProperty AccessToken | Test-AadToken | select-object -expandProperty payload
```

## Resource Owner Password Credential flow
This sample uses ROPC to get token to access Graph API

```powershell
$creds = Get-Credential
$graphFactory = New-AadAuthenticationFactory -TenantId 'mytenant.com' -ClientId $graphApiClientId -ResourceOwnerCredential $creds -RequiredScopes 'https://graph.microsoft.com/.default'
$graphToken = Get-AadToken -Factory $graphFactory

```
## On-Behalf-Of flow
This is useful for testing of authentication flows in multi-tier apps.
```powershell
$myTenant = 'mydomain.com'
$myNativeClientId = '<enter appId of client app talking to 1st tier>'
$myFrontendScopes = 'https://mycompany.com/1stTierApp/.default'
$myFrontendAppId = '<enter appId of 1st tier app talking to 2nd tier>'
$myFrontendClientSecret = "<enter client secret of 1st tier app>"
$myBackendScopes = 'https://mycompany.com/2ndTierApp/.default'


$frontendAppFactory = New-AadAuthenticationFactory -TenantId $myTenant -RequiredScopes $myFrontendScopes -ClientId $myNativeClientId -AuthMode Interactive
#get access token for frontend app
$frontendAppToken = Get-AadToken -Factory $frontendAppFactory
#observe claims in access token for frontend app
$frontendAppToken.AccessToken | Test-AadToken | Select-Object -ExpandProperty payload
#observe claims in Id token for native client app
$frontendAppToken.IdToken | Test-AadToken | Select-Object -ExpandProperty payload

#create factory to retrieve token as frontend app on behalf of user
#note that app needs to present its client secret/certificate to get onbehalf-of token
$backendAppFactory = New-AadAuthenticationFactory -TenantId $myTenant -RequiredScopes $myBackendScopes -ClientId $myFrontendAppId -ClientSecret $myFrontendClientSecret
#retrieve access token
$backendAppToken = Get-AadToken -Factory $backendAppFactory -UserToken $frontendAppToken.AccessToken
#observe claims in access token for backend app
$backendAppToken.AccessToken | Test-AadToken | Select-Object -ExpandProperty payload
#observe claims in Id token for frontend app
$backendAppToken.IdToken | Test-AadToken | Select-Object -ExpandProperty payload

```
