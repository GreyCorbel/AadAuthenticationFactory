using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.NativeInterop;
using Microsoft.Identity.Client.SSHCertificates;
using Microsoft.Identity.Client.Utils;

internal sealed class BrokerRequest
{
    public int Version { get; set; }
    public string Operation { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string Authority { get; set; } = "";
    public string[] Scopes { get; set; } = Array.Empty<string>();
    public string? LoginHint { get; set; }
    public string? HomeAccountId { get; set; }
    public bool ForceRefresh { get; set; }
    public bool AllowInteractive { get; set; }
    public bool MultiCloud { get; set; }
    public bool ClaimsSupport { get; set; }
    public bool ExperimentalFeatures { get; set; }
    public string? Claims { get; set; }
    public string? SshJwk { get; set; }
    public string? SshKeyId { get; set; }

    public void Validate()
    {
        if (Version != 1)
            throw new ArgumentException("Unsupported broker protocol version.");
        if (Operation != "accounts" && Operation != "token")
            throw new ArgumentException("Unsupported broker operation.");
        if (!Guid.TryParse(ClientId, out _) ||
            !Uri.TryCreate(Authority, UriKind.Absolute, out var authority) ||
            authority.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(authority.UserInfo))
            throw new ArgumentException("A client ID and absolute HTTPS authority are required.");
        if (Operation == "token" && (Scopes == null || Scopes.Length == 0 ||
            Scopes.Any(string.IsNullOrWhiteSpace)))
            throw new ArgumentException("Token requests require nonempty scopes.");
        if ((SshJwk == null) != (SshKeyId == null))
            throw new ArgumentException("SSH requests require both a public JWK and key ID.");
    }
}

internal sealed class BrokerResponse
{
    public int Version { get; set; } = 1;
    public BrokerAccount[]? Accounts { get; set; }
    public BrokerToken? Result { get; set; }
    public BrokerError? Error { get; set; }
}

internal sealed class BrokerError
{
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
    public bool InteractionRequired { get; set; }
    public string? Claims { get; set; }
    public string? CorrelationId { get; set; }
}

internal sealed class BrokerAccount
{
    public string Username { get; set; } = "";
    public string Environment { get; set; } = "";
    public string HomeAccountId { get; set; } = "";

    public static BrokerAccount From(IAccount account) => new BrokerAccount
    {
        Username = account.Username,
        Environment = account.Environment,
        HomeAccountId = account.HomeAccountId.Identifier
    };
}

internal sealed class BrokerToken
{
    public string AccessToken { get; set; } = "";
    public string? IdToken { get; set; }
    public string? UniqueId { get; set; }
    public string? TenantId { get; set; }
    public string TokenType { get; set; } = "";
    public DateTimeOffset ExpiresOn { get; set; }
    public DateTimeOffset ExtendedExpiresOn { get; set; }
    public bool IsExtendedLifeTimeToken { get; set; }
    public string[] Scopes { get; set; } = Array.Empty<string>();
    public Guid CorrelationId { get; set; }
    public BrokerAccount? Account { get; set; }
    public string TokenSource { get; set; } = "";
    public string? SpaAuthCode { get; set; }
    public IReadOnlyDictionary<string, string>? AdditionalResponseParameters { get; set; }
    public BrokerIdentity[]? Identities { get; set; }
}

internal sealed class BrokerIdentity
{
    public string? AuthenticationType { get; set; }
    public string NameClaimType { get; set; } = "";
    public string RoleClaimType { get; set; } = "";
    public BrokerClaim[] Claims { get; set; } = Array.Empty<BrokerClaim>();

    public static BrokerIdentity From(ClaimsIdentity identity) => new BrokerIdentity
    {
        AuthenticationType = identity.AuthenticationType,
        NameClaimType = identity.NameClaimType,
        RoleClaimType = identity.RoleClaimType,
        Claims = identity.Claims.Select(claim => new BrokerClaim
        {
            Type = claim.Type,
            Value = claim.Value,
            ValueType = claim.ValueType,
            Issuer = claim.Issuer,
            OriginalIssuer = claim.OriginalIssuer,
            Properties = claim.Properties
        }).ToArray()
    };
}

internal sealed class BrokerClaim
{
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public string ValueType { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string OriginalIssuer { get; set; } = "";
    public IDictionary<string, string>? Properties { get; set; }
}

internal static class ModuleProtocol
{
    public static async Task<BrokerResponse> RunAsync(BrokerRequest request, CancellationToken cancellationToken)
    {
        // Check native broker availability instead of allowing MSAL's browser fallback.
        using (var core = new Core()) { }

        var builder = PublicClientApplicationBuilder.Create(request.ClientId)
            .WithAuthority(request.Authority)
            .WithRedirectUri("msauth.com.msauth.unsignedapp://auth")
            .WithMultiCloudSupport(request.MultiCloud)
            .WithExperimentalFeatures(request.ExperimentalFeatures)
            .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.OSX)
            {
                Title = "AadAuthenticationFactory",
                ListOperatingSystemAccounts = true
            });
        if (request.ClaimsSupport)
            builder = builder.WithClientCapabilities(new[] { "cp1" });
        var application = builder.Build();

        var accounts = (await application.GetAccountsAsync().WaitAsync(cancellationToken)
            .ConfigureAwait(false)).ToList();
        if (request.Operation == "accounts")
            return new BrokerResponse { Accounts = accounts.Select(BrokerAccount.From).ToArray() };

        var matches = accounts.Where(account =>
            (string.IsNullOrEmpty(request.HomeAccountId) ||
                account.HomeAccountId.Identifier == request.HomeAccountId) &&
            (string.IsNullOrEmpty(request.LoginHint) ||
                string.Equals(account.Username, request.LoginHint, StringComparison.OrdinalIgnoreCase))).ToList();
        if (matches.Count > 1)
            throw new ArgumentException("Multiple broker accounts match the request. Specify an account.");
        var selectedAccount = matches.SingleOrDefault();

        AuthenticationResult result;
        try
        {
            var silent = application.AcquireTokenSilent(request.Scopes, selectedAccount)
                .WithForceRefresh(request.ForceRefresh);
            if (!string.IsNullOrEmpty(request.Claims))
                silent = silent.WithClaims(request.Claims);
            if (request.SshJwk != null)
                silent = silent.WithSSHCertificateAuthenticationScheme(request.SshJwk, request.SshKeyId);
            result = await silent.ExecuteAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (MsalUiRequiredException) when (request.AllowInteractive)
        {
            AuthenticationResult? interactiveResult = null;
            await MacMainThreadScheduler.Instance().RunOnMainThreadAsync(async () =>
            {
                var interactive = application.AcquireTokenInteractive(request.Scopes);
                if (!string.IsNullOrEmpty(request.LoginHint))
                    interactive = interactive.WithLoginHint(request.LoginHint);
                else if (selectedAccount != null)
                    interactive = interactive.WithAccount(selectedAccount);
                if (!string.IsNullOrEmpty(request.Claims))
                    interactive = interactive.WithClaims(request.Claims);
                if (request.SshJwk != null)
                    interactive = interactive.WithSSHCertificateAuthenticationScheme(request.SshJwk, request.SshKeyId);
                interactiveResult = await interactive.ExecuteAsync(cancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);
            result = interactiveResult ?? throw new InvalidOperationException("The broker returned no interactive result.");
        }

        if (result.AuthenticationResultMetadata.TokenSource != TokenSource.Broker)
            throw new InvalidOperationException("Authentication did not use the macOS broker.");

        return new BrokerResponse
        {
            Result = new BrokerToken
            {
                AccessToken = result.AccessToken,
                IdToken = result.IdToken,
                UniqueId = result.UniqueId,
                TenantId = result.TenantId,
                TokenType = result.TokenType,
                ExpiresOn = result.ExpiresOn,
#pragma warning disable CS0618 // Preserve these fields when reconstructing the public MSAL result.
                ExtendedExpiresOn = result.ExtendedExpiresOn,
                IsExtendedLifeTimeToken = result.IsExtendedLifeTimeToken,
#pragma warning restore CS0618
                Scopes = result.Scopes.ToArray(),
                CorrelationId = result.CorrelationId,
                Account = result.Account == null ? null : BrokerAccount.From(result.Account),
                TokenSource = result.AuthenticationResultMetadata.TokenSource.ToString(),
                SpaAuthCode = result.SpaAuthCode,
                AdditionalResponseParameters = result.AdditionalResponseParameters,
                Identities = result.ClaimsPrincipal?.Identities.Select(BrokerIdentity.From).ToArray()
            }
        };
    }
}
