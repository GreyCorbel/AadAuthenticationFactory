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
            _endpointAddress = IdentityEndpoint;
            _apiVersion = "2020-06-01";
        }

        public override async Task<string> GetRawTokenFromEndpointAsync(HttpClient client, HttpRequestMessage request, CancellationToken cancellationToken)
        {
            using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                var header = response.Headers.WwwAuthenticate.FirstOrDefault();
                if (header != null)
                {
                    string keyFile = header.Parameter.Replace("realm=", string.Empty);
                    string secret = Encoding.Default.GetString(System.IO.File.ReadAllBytes(keyFile));
                    using HttpRequestMessage message = new HttpRequestMessage()
                    {
                        Method = request.Method,
                        RequestUri = request.RequestUri,

                    };
                    message.Headers.Add("Metadata", "true");
                    message.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", $"{secret}");
                    using var tokenResponse = await client.SendAsync(message, cancellationToken).ConfigureAwait(false);
                    return await ProcessEndpointResponseAsync(response).ConfigureAwait(false);
                }
            }
            string detail = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            throw new InvalidOperationException($"Unexpected response from identity endpoint: {detail}");
        }
    }
}
