# AadAuthenticationFactory - Entra ID token provider
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg?style=plastic)](./LICENSE)
[![PowerShell Desktop | Core](https://img.shields.io/badge/PowerShell-Desktop%20|%20Core%207.4+%20-blue.svg?logo=PowerShell&style=plastic)](#)
[![Platform Windows | Mac | Linux](https://img.shields.io/badge/Platform-Windows%20|%20Mac%20|%20Linux%20%20-808080.svg?logo=Amazon%20EC2&style=plastic)](#)

This PowerShell module wraps MSAL and Azure Identity authentication in reusable factories. It targets Windows PowerShell 5.1 and PowerShell 7.4 or later, and is tested on Windows, macOS, and Linux.

### Authentication flows

|Flow|Factory configuration|Behavior and limits|
|:---|:---|:---|
|Delegated public client|`-AuthMode Interactive`, `DeviceCode`, `WIA`, or `Broker` (`WAM` is an alias)|Interactive and device-code acquisition try the cached account silently first. WIA uses Windows integrated authentication and is Windows-only. Broker availability depends on the platform and architecture below.|
|Confidential client|`-ClientSecret`, `-X509Certificate`, or `-Assertion`|Acquires application tokens. Pass `-UserToken` to `Get-AadToken` to acquire a token on behalf of that user.|
|Managed identity|`-UseManagedIdentity`|Uses a system-assigned identity by default; set `-ClientId` to select a user-assigned identity. Availability depends on the hosting environment.|
|Resource owner password (ROPC)|`-ResourceOwnerCredential`|Obsolete and retained for compatibility. Password-only authentication is incompatible with many MFA and Conditional Access requirements; do not use for new integrations.|

`TenantId`, `DefaultScopes`, and optional factory `Name` configure the factory. `Get-AadToken` can override scopes, force refresh, process WWW-Authenticate challenges, and return an Authorization-header hashtable. Supported public-client flows can request an SSH certificate proof-of-possession token with `-SshKeyLength` (2048, 3072, or 4096 bits). Multicloud and claims-request support are available for public-client factories. B2C policies are supported for non-macOS-broker flows; macOS broker factories reject B2C policies and an explicit proxy.

Broker authentication supports Windows x64, x86, and ARM64; macOS x64 and ARM64; and Linux x64. Linux ARM64 is not supported because the bundled MSAL native runtime has no Linux ARM64 asset. On Linux, broker authentication also requires the WebKitGTK 4.1 runtime (`libwebkit2gtk-4.1-0` on Ubuntu). macOS broker authentication requires an enrolled device with Company Portal, uses the unsigned-script redirect URI `msauth.com.msauth.unsignedapp://auth`, and interactive calls must run on the main thread.

### Install and develop

Install the published prerelease from PowerShell Gallery with:

```powershell
Install-Module AadAuthenticationFactory -AllowPrerelease
Import-Module AadAuthenticationFactory
```

To build from a checkout, restore the pinned MSAL dependencies and generate the module. Build the macOS launchers on macOS only:

```powershell
./Workflow/SetupPackages.ps1 -RootPath .
./Workflow/BuildModule.ps1 -RootPath . -ModuleName AadAuthenticationFactory
# macOS only; Xcode Command Line Tools and a .NET 8 SDK or newer are required.
./Workflow/BuildMacBroker.ps1 -RootPath .
```

Run the unit and platform tests with Pester 5.5 or later:

```powershell
./Workflow/RunTests.ps1 -RootPath . -ModuleName AadAuthenticationFactory -ExcludeTag integration
```

Confidential-client integration tests are tagged `integration` and need the tenant, client, scope, and expected-token settings described in `.github/workflows/Test-AadAuthenticationFactory.yml`; `-RequireIntegrationConfiguration` makes missing settings an error.

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
requirements). Users need no .NET SDK or separate runtime. For broker authentication to work on macOS, 
machine has to be onboarded to Intune, and Intune has to publish SSO extension to machine.

For local development, build on macOS with Xcode Command Line Tools and a .NET 8 SDK (or a newer SDK
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
|New-AadAuthenticationFactory|Creates a reusable public-client, confidential-client, ROPC, or managed-identity factory. Factories can be named and retrieved later.|
|Get-AadAuthenticationFactory|Returns the most recently created factory by default, a named factory with `-Name`, or all session factories with `-All`.|
|Get-AadToken|Acquires a token using a factory. Supports delegated, application, on-behalf-of, and managed-identity requests; returns an MSAL `AuthenticationResult` or, with `-AsHashTable`, an Authorization header.|
|Get-AadAccount|Lists accounts cached by a public-client factory. `-UserName` filters usernames using PowerShell's `-match` operator. macOS broker account discovery uses the helper process.|
|Get-AadDefaultClientId|Returns the general Azure PowerShell public-client ID used when `-ClientId` is omitted. macOS Broker/WAM uses a separate broker-compatible default; explicit IDs are preserved.|
|Test-AadToken|Parses a JWT and validates its signature against the issuer's published signing keys. Accepts a raw JWT, `AuthenticationResult`, Authorization hashtable, or token-bearing object; `-PayloadOnly` returns claims without the validation result. SSH certificate tokens are not JWTs and are not supported.|

Module is usable in two ways:
- as standalone module to provide Azure tokens ad-hoc or in scripts
- as a dependency of other PowerShell modules, which can create factories and request tokens for their target resources. Example consumers include [CosmosLite](https://github.com/jformacek/CosmosLite) and [ExoHelper](https://github.com/greycorbel/ExoHelper).

For further documentation and code samples, see the [project wiki](https://github.com/GreyCorbel/AadAuthenticationFactory/wiki).
