using GreyCorbel.Identity.Authentication.Helpers;
using Microsoft.Identity.Client;
using System.Net;
using System.Net.Http;

namespace GreyCorbel.Identity.Authentication
{
    internal class GcMsalHttpClientFactory : IMsalHttpClientFactory
    {
        static HttpClient _httpClient;

        public GcMsalHttpClientFactory(WebProxy proxy, bool useDefaultCredentials = false)
        {

            if (null == _httpClient)
            {
                var httpClientHandler = new HttpClientHandler()
                {
                    UseDefaultCredentials = useDefaultCredentials
                };

                if (null != proxy)
                {
                    httpClientHandler.Proxy = proxy;
                    httpClientHandler.UseProxy = true;
                }
                _httpClient = new HttpClient(httpClientHandler);

                _httpClient.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("AadAuthenticationFactory", CoreAssembly.Version.ToString()));
            }
        }
        public HttpClient GetHttpClient()
        {
            return _httpClient;
        }
    }
}
