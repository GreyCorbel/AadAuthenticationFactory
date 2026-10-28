# AadAuthenticationFactory - Entra ID token provider
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg?style=plastic)](./LICENSE.md)
[![PowerShell Desktop | Core](https://img.shields.io/badge/PowerShell-Desktop%20|%20Core%207.4+%20-blue.svg?logo=PowerShell&style=plastic)](#)
[![Platform Windows | Mac | Linux](https://img.shields.io/badge/Platform-Windows%20|%20Mac%20|%20Linux%20%20-808080.svg?logo=Amazon%20EC2&style=plastic)](#)

This module provides unified experience for getting and using tokens from Entra ID authentication platform. Experience covers this authentication scenarios:
  - **Interactive authentication with Public client flow and Delegated permissions**. Uses standard MSAL implementation of Public flow with Browser based Interactive authentication, Device code authentication, Resource Owner credentials, Windows integrated authentication (supports ADFS-federated tenants) and WAM (authentication with Windows broker)
  - **Non-interactive authentication with Confidential client flow and Application permissions**. Uses standard MSAL implementation of Confidential client with authentication via Client Secret of via X.509 certificate or with Federated credentials (Workload authentication scenario)
  - **Non-Interactive authentication via Azure Managed Identity**, usable on Azure VMs, Azure App Services, Azure Functions, Automation accounts and Arc enabled servers, or other platforms that support Azure Managed identity. Supports both System Managed Identity or User Managed Identity.

Module supports standard AAD tenants as well as AAD B2C tenants. Module has been tested on Windows (PS Desktop and Core), MacOS and Linux.

**Obsolete flow:** The Resource Owner Password flow is obsolete and support for it will be removed in the next release because Microsoft's initiative to enforce multifactor authentication is incompatible with password-only sign-in. Use an interactive, device code, broker, confidential client, or managed identity flow instead.

_Note_: Some authentication methods are not available in all scenarios (e.g. Windows integrated authentication only works on Windows).

Broker authentication supports Windows x64, x86, and ARM64; macOS x64 and ARM64; and Linux x64. Linux ARM64 is not supported because the MSAL native runtime package does not currently include that runtime. macOS broker authentication requires an enrolled device with Company Portal, uses the unsigned-script redirect URI `msauth.com.msauth.unsignedapp://auth`, and interactive calls must run on the main thread.

On PowerShell Core, the module resolves MSAL broker native imports directly from its bundled `runtimes/<rid>/native` directory. No global native-library search path changes or copies into the PowerShell installation are required.

### macOS broker helper

Ordinary PowerShell runspaces do not run on the native macOS main thread required
by interactive broker authentication. The console project in
[`MacBroker`](./MacBroker) owns its main thread and runs MSAL's main-thread
scheduler. On macOS, `-AuthMode Broker` (and its `WAM` alias) automatically uses
this helper for account discovery and token acquisition. Windows and Linux keep
their existing in-process broker implementation; other authentication modes do
not start the helper.

The release workflow packages just three helper files:

- `bin/AadAuthenticationFactory.MacBroker.dll`: one shared managed assembly.
- `bin/osx-arm64/AadAuthenticationFactory.MacBroker`: Apple Silicon launcher.
- `bin/osx-x64/AadAuthenticationFactory.MacBroker`: Intel launcher.

The small native launcher starts the calling PowerShell's bundled .NET runtime
from `$PSHOME` on its own main thread. Framework assemblies come from that
PowerShell installation; MSAL dependencies come from `shared/netstandard2.0`,
and native MSAL libraries come from `runtimes/<rid>/native`. No duplicate .NET
runtime or MSAL distribution, apphost, deps JSON, or runtimeconfig JSON is needed.
The module passes `$PSHOME` privately in the child process environment and selects
the PowerShell process architecture, including under Rosetta.

This requires a complete PowerShell 7.4+ installation with its bundled .NET 8+
runtime, on macOS 12 or later (subject to the installed PowerShell's own OS
requirements). Users need no .NET SDK or separate runtime. For local development,
build on macOS with Xcode Command Line Tools and a .NET 8 SDK (or a newer SDK
supporting .NET 8):

```powershell
./Workflow/BuildMacBroker.ps1
./Workflow/BuildModule.ps1 -RootPath . -ModuleName AadAuthenticationFactory
Import-Module ./Module/AadAuthenticationFactory/AadAuthenticationFactory.psd1 -Force

$factory = New-AadAuthenticationFactory -AuthMode Broker -TenantId organizations `
    -DefaultScopes 'https://management.azure.com/.default'
Get-AadAccount -Factory $factory
$result = Get-AadToken -Factory $factory
# $result is Microsoft.Identity.Client.AuthenticationResult, not a JSON object.
```

When `-ClientId` is omitted, macOS Broker/WAM factories use the Azure PowerShell
public client `04b07795-8ddb-461a-bbee-02f9e1bf7b46`, which supports the broker
redirect URI. The general default (`1950a258-227b-4e31-a9cf-717495945fc2`, returned
by `Get-AadDefaultClientId`) and all other flows/platforms are unchanged. Explicit
client IDs are always respected and must support the broker redirect URI.
The helper tries silent acquisition first, opening broker UI only
for `MsalUiRequiredException`. `-ForceRefresh`, login/account selection,
claims/authority challenges, client capabilities, multicloud configuration, and
SSH certificate requests are forwarded. Explicit `-Proxy` and B2C policies are
rejected for macOS broker factories rather than silently ignored. Device and
tenant policies may still require interaction or reject a request.

`Get-AadAccount` returns `IAccount` implementations; `Get-AadToken` reconstructs
an MSAL `AuthenticationResult`, including account identity, token type, expiry,
scopes, correlation ID, and broker token-source metadata. `-AsHashTable` and
`Test-AadToken` continue to work. Use the module commands: directly calling the
factory's MSAL methods bypasses the helper and is not a main-thread workaround.

Each operation uses a short-lived process. Versioned JSON is exchanged through
redirected stdin/stdout, not command arguments or temporary files. Token
responses are consumed privately by the module, and neither logged nor persisted
by the helper. The broker retains its own SSO state. Cancellation/timeouts stop
the helper; errors are surfaced as MSAL exceptions without browser fallback.
The module restores the helper's executable bit after package extraction.

Apple Developer signing/notarization is **not configured**. The standalone
launcher uses the toolchain's default signing behavior and the unsigned-app redirect URI;
PowerShell Authenticode signing does not sign this Mach-O binary. Do not add an
Apple Developer signature to the standalone executable without revisiting app
bundle packaging and broker redirect requirements.

#### Standalone diagnostics

The helper retains the probe commands for troubleshooting. For Intel PowerShell,
replace `osx-arm64` with `osx-x64`:

```powershell
$env:AAD_AUTHENTICATION_POWERSHELL_HOME = $PSHOME
$probe = './Module/AadAuthenticationFactory/bin/osx-arm64/AadAuthenticationFactory.MacBroker'

# No sign-in: verify main-thread scheduling and real MSAL native imports.
& $probe --probe

# No sign-in: verify broker initialization and device prerequisites.
& $probe --startup

$client = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
$tenant = 'organizations' # Prefer your tenant ID for a tenant-specific test.
$scope = 'https://management.azure.com/.default'

# Discover accounts through the broker; no token request or sign-in prompt.
& $probe --accounts --client-id $client --tenant $tenant

# Silent-only test in a fresh process. Never falls back to interactive sign-in.
& $probe --silent --client-id $client --tenant $tenant --scope $scope `
    --login-hint 'you@contoso.com'

# If initial interaction/consent is needed: broker UI, followed by a forced
# silent broker request using the returned account.
& $probe --sso-test --client-id $client --tenant $tenant --scope $scope `
    --login-hint 'you@contoso.com'
```

Use a client ID, tenant, and scopes permitted by your organization's policies.
The application must support the redirect URI `msauth.com.msauth.unsignedapp://auth`.
The probe deliberately uses this broker URI, not `http://localhost`. It checks
native broker startup before account/token operations and rejects token results
whose MSAL `TokenSource` is not `Broker`; browser success cannot pass this test.

`--interactive` performs only the interactive broker step. `--sso-test` prints
separate `interactive` and `silent` results; both must succeed and the process must
exit with code zero. All silent requests force refresh to bypass the application
access-token cache (the broker may still use its own cache). To prove SSO across
processes, run `--silent` again as a separate invocation after `--sso-test`.
`--silent` discovers broker accounts and requires exactly one matching account:
use `--login-hint` for an exact username match, or `--home-account-id` with an ID
from `--accounts` when usernames are ambiguous. With neither selector, exactly
one discovered account is required. `OperatingSystemAccount` is not used on macOS.

Company Portal must be installed, the Mac enrolled, and the Enterprise SSO
extension configuration deployed and active. Conditional Access, MFA, or consent
can still require interaction; a silent failure is reported, never hidden by an
interactive fallback. Native startup success alone does not prove token issuance.

Diagnostic commands write diagnostic/error JSON to stderr, successful result JSON
lines to stdout, and return a nonzero exit code on failure. Each invocation times
out after three minutes; Ctrl+C requests cancellation. Tokens are never printed
by diagnostic commands. The internal `--module` protocol returns tokens only
through the module's redirected pipe and must not be used as a logging command.
Success metadata includes stage, token source, account,
tenant, scopes, expiry, and correlation ID. Error metadata identifies
`MsalUiRequiredException` with `interactionRequired: true`. Account and correlation
metadata may be sensitive; redact it before sharing.

Module comes with commands:

|Command|Usage|
|:------|:----|
|New-AadAuthenticationFactory|Creates factory responsible for issuing of AAD tokens, using specified authentication flow|
|Get-AadAuthenticationFactory|Returns instance of factory specified by name (or null if factory with given name was not created) or all factories created in current sesison|
|Get-AadToken|Tells the factory to create a token. Factory returns cached token, if available, and takes care of token renewals silently whenever possible, after tokens expire|
|Test-AadToken|Parses Access token or Id token and validates it against Entra ID published keys. Provides PowerShell way of showing token content as available in http://jwt.ms|
|Get-AadDefaultClientId|Returns default client id used by module when client id not specified in New-AadAuthenticationFactory command|
|Get-AadAccount|Returns specified account or all accounts cached in specified instance of factory|

Module is usable in two ways:
- as standalone module to provide Azure tokens ad-hoc or in scripts
- by other modules to provide instant Azure authentication services without the need to implement them - just make dependency on AadAuthenticationFactory module in other module and use it to get tokens for resources as you need. This is demonstrated by [CosmosLite module](https://github.com/jformacek/CosmosLite) and [ExoHelper module](https://github.com/greycorbel/ExoHelper)

For documentation and code samples, see  [Wiki pages](https://github.com/greycorbel/AadAuthenticationFactory/wiki)
