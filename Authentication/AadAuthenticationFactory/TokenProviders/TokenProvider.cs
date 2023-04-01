using GreyCorbel.Identity.Authentication.Helpers;
using Microsoft.Identity.Client;
using System;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GreyCorbel.Identity.Authentication.TokenProviders
{
    internal abstract class TokenProvider : TokenProviderBase
    {
        protected IMsalHttpClientFactory _httpClientFactory;
        protected readonly string _clientId = null;

        protected string _endpointAddress;
        protected string _apiVersion;

        public TokenProvider(IMsalHttpClientFactory factory, string clientId = null)
        {
            _httpClientFactory = factory;
            _clientId = clientId;
        }
        public override async Task<AuthenticationResult> AcquireTokenForClientAsync(string[] scopes, CancellationToken cancellationToken)
        {
            var client = _httpClientFactory.GetHttpClient();
            using HttpRequestMessage message = CreateRequestMessage(_endpointAddress, _apiVersion, scopes);

            string rawToken = await GetRawTokenFromEndpointAsync(client, message, cancellationToken).ConfigureAwait(false);
            var authResponse = rawToken.FromJson<ManagedIdentityAuthenticationResponse>();
            if (authResponse != null)
            {
                return CreateAuthenticationResult(authResponse);
            }
            else
                throw new FormatException($"Invalid authentication response received: {rawToken}");
        }

        public abstract Task<string> GetRawTokenFromEndpointAsync(HttpClient client, HttpRequestMessage request, CancellationToken cancellationToken);

        protected virtual HttpRequestMessage CreateRequestMessage(string endpointAddress, string apiVersion, string[] scopes)
        {
            HttpRequestMessage message = new HttpRequestMessage();
            message.Method = HttpMethod.Get;
            StringBuilder sb = new StringBuilder(endpointAddress);

            //the same for all types so far
            sb.Append($"?api-version={Uri.EscapeDataString(apiVersion)}");
            sb.Append($"&resource={Uri.EscapeDataString(ScopeHelper.ScopeToResource(scopes))}");

            if (!string.IsNullOrEmpty(_clientId))
            {
                sb.Append($"&{ClientIdHeaderName}={Uri.EscapeDataString(_clientId)}");
            }
            message.RequestUri = new Uri(sb.ToString());
            message.Headers.Add("Metadata", "true");
            return message;
        }

        protected AuthenticationResult CreateAuthenticationResult(ManagedIdentityAuthenticationResponse authResponse)
        {
            long.TryParse(authResponse.expires_on,  out long expiresOn);
            DateTimeOffset tokenExpiresOn = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(expiresOn);
            ClaimsPrincipal principal = null;
            if(!string.IsNullOrEmpty(authResponse.client_id))
            {
                principal = new();
                GenericIdentity identity = new(authResponse.client_id, "aad");
                principal.AddIdentity(new ClaimsIdentity(identity));
            }

            Guid tokenId = Guid.NewGuid();
            return new AuthenticationResult(
                authResponse.access_token,
                false,
                tokenId.ToString(),
                tokenExpiresOn,
                tokenExpiresOn,
                null,
                null,
                null,
                ScopeHelper.ResourceToScope(authResponse.resource),
                tokenId,
                authResponse.token_type,
                null,
                principal
                );
        }

        protected async Task<string> ProcessEndpointResponseAsync(HttpResponseMessage response)
        {
            string payload = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                return payload;
            }
            else
            {
                throw new MsalClientException(response.StatusCode.ToString(), $"{payload}");
            }
        }
    }
}
