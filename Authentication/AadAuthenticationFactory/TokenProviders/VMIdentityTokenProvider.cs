using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace GreyCorbel.Identity.Authentication
{
    internal class VMIdentityTokenProvider : TokenProvider
    {
        
        public VMIdentityTokenProvider(IMsalHttpClientFactory factory, string clientId = null)
        : base(factory, clientId)
        {
            _endpointAddress = "http://169.254.169.254/metadata/identity/oauth2/token";
            _apiVersion = "2019-08-01";
        }

        public override async Task<string> GetRawTokenFromEndpointAsync(HttpClient client, HttpRequestMessage request, CancellationToken cancellationToken)
        {
            using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            return await ProcessEndpointResponseAsync(response).ConfigureAwait(false);
        }
    }
}
