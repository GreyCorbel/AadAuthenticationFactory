# AadAuthenticationFactory
This module provides unified experience for getting and using tokens from Azure AD authentication platform. Experience covers this authentication scenarios:
  - **Interactive authentication with Public client flow and Delegated permissions**. Uses standard MSAL implementation of Public flow with Browser based Interactive authentication, Device code authentication, Resource Owner credentials, Windows integrated authentication (supports ADFS-federated tenants) and WAM (authentication with Windows broker)
  - **Non-interactive authentication with Confidential client flow and Application permissions**. Uses standard MSAL implementation of Confidential client with authentication via Client Secret of via X.509 certificate or with Federated credentials (Workload authentication scenario)
  - **Non-Interactive authentication via Azure Managed Identity**, usable on Azure VMs, Azure App Services, Azure Functions, Automation accounts and Arc enabled servers, or other platforms that support Azure Managed identity. Supports both System Managed Identity or User Managed Identity.

Module supports standard AAD tenants as well as AAD B2C tenants. Module has been tested on Windows (PS Desktop and Core), MacOS and Linux.

_Note_: Some authentication methods are not available in all scenarios (e.g. WAM and Windows integrated authentication only work on Windows)

Module comes with commands:

|Command|Usage|
|:------|:----|
|New-AadAuthenticationFactory | Creates factory responsible for issuing of AAD tokens for given resource, using given authentication flow|
|Get-AadAuthenticationFactory|Returns instance of factory specified by name (or null if factory with given name was nto created) or all factories created in current sesison|
|Get-AadToken|Tells the factory to create a token. Factory returns cached token, if available, and takes care of token renewals silently whenever possible, after tokens expire|
|Test-AadToken|Parses Access token or Id token and validates it against published keys. Provides PowerShell way of showing token content as available in http://jwt.ms|
|Get-AadDefaultClientId|Returns default client id used by module when client id not specified in New-AadAuthenticationFactory command|
|Get-AadAccount|Returns specified account or all accounts cached in specified instance of factory|

Module is usable in two ways:
- as standalone module to provide Azure tokens ad-hoc or in scripts
- by other modules to provide instant Azure authentication services without the need to implement them - just make dependency on AadAuthenticationFactory module in other module and use it to get tokens for resources as you need. This is demonstrated by [CosmosLite module](https://github.com/jformacek/CosmosLite) and [ExoHelper module](https://github.com/greycorbel/ExoHelper)

For documentation and code samples, see  [Wiki pages](https://github.com/greycorbel/AadAuthenticationFactory/wiki)
