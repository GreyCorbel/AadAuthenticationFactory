using Microsoft.Identity.Client;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace GreyCorbel.Identity.Authentication.TokenProviders
{
    internal class AppServiceTokenProvider : TokenProvider
    {
        public AppServiceTokenProvider(IMsalHttpClientFactory factory, string clientId = null)
            : base(factory, clientId)
        {
            _endpointAddress = IdentityEndpoint;
            _apiVersion = "2019-08-01";
        }

        public override async Task<string> GetRawTokenFromEndpointAsync(HttpClient client, HttpRequestMessage request, CancellationToken cancellationToken)
        {
            using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            return await ProcessEndpointResponseAsync(response).ConfigureAwait(false);
        }

        protected override HttpRequestMessage CreateRequestMessage(string endpointAddress, string apiVersion, string[] scopes)
        {
            var message = base.CreateRequestMessage(endpointAddress, apiVersion, scopes);
            message.Headers.Add("X-IDENTITY-HEADER", IdentityHeader);
            return message;
        }
    }
}
