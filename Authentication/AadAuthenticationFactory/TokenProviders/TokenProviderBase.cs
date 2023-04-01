using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GreyCorbel.Identity.Authentication.TokenProviders
{
    internal abstract class TokenProviderBase: ITokenProvider
    {
        protected static string IdentityEndpoint => Environment.GetEnvironmentVariable("IDENTITY_ENDPOINT");
        protected static string IdentityHeader => Environment.GetEnvironmentVariable("IDENTITY_HEADER");
        protected static string MsiEndpoint => Environment.GetEnvironmentVariable("MSI_ENDPOINT");
        protected static string MsiSecret => Environment.GetEnvironmentVariable("MSI_SECRET");
        protected static string ImdsEndpoint => Environment.GetEnvironmentVariable("IMDS_ENDPOINT");
        protected static string SecretHeaderName => "X-IDENTITY-HEADER";
        protected static string ClientIdHeaderName => "client_id";

        public abstract Task<AuthenticationResult> AcquireTokenForClientAsync(string[] scopes, CancellationToken cancellationToken);
    }
}
