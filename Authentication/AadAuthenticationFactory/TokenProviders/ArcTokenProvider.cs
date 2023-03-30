using Microsoft.Identity.Client;
using System;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace GreyCorbel.Identity.Authentication
{
    internal class ArcTokenProvider : TokenProvider
    {
        public ArcTokenProvider(IMsalHttpClientFactory factory, string clientId = null)
            : base(factory, clientId)
        {

        }

        public override async Task<AuthenticationResult> AcquireTokenForClientAsync(string[] scopes, CancellationToken cancellationToken)
        {
            var client = _httpClientFactory.GetHttpClient();

            using HttpRequestMessage message = CreateRequestMessage(scopes);
            using var response = await client.SendAsync(message, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                var header = response.Headers.WwwAuthenticate.FirstOrDefault();
                if (header != null)
                {
                    string keyFile = header.Parameter.Replace("realm=", string.Empty);
                    string secret = Encoding.Default.GetString(System.IO.File.ReadAllBytes(keyFile));
                    using HttpRequestMessage tokenMessage = CreateRequestMessage(scopes);
                    tokenMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", $"{secret}");
                    using var tokenResponse = await client.SendAsync(tokenMessage, cancellationToken).ConfigureAwait(false);

                    if (tokenResponse.IsSuccessStatusCode)
                    {
                        string payload = await tokenResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                        var authResponse = payload.FromJson<ManagedIdentityAuthenticationResponse>();
                        if (authResponse != null)
                        {
                            return CreateAuthenticationResult(authResponse);
                        }
                        else
                            throw new FormatException($"Invalid authentication response received: {payload}");
                    }
                    else
                    {
                        throw new MsalClientException(tokenResponse.StatusCode.ToString(), tokenResponse.ReasonPhrase);
                    }
                }
            }
            throw new InvalidOperationException($"Unexpected response from identity endpoint");
        }

        HttpRequestMessage CreateRequestMessage(string[] scopes)
        {
            HttpRequestMessage message = new HttpRequestMessage();
            message.Method = HttpMethod.Get;
            StringBuilder sb= new StringBuilder(IdentityEndpoint);

            //the same for all types so far
            sb.Append($"?api-version={Uri.EscapeDataString(ArcApiVersion)}");
            sb.Append($"&resource={Uri.EscapeDataString(ScopeHelper.ScopeToResource(scopes))}");

            message.RequestUri = new Uri(sb.ToString());
            message.Headers.Add("Metadata", "true");
            return message;
        }
    }
}
