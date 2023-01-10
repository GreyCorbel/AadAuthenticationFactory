using Microsoft.Identity.Client;
using System.Net;
using System.Net.Http;

namespace GreyCorbel.Identity.Authentication
{
    internal class GcMsalHttpClientFactory : IMsalHttpClientFactory
    {
        static HttpClient httpClient;

        public GcMsalHttpClientFactory(WebProxy proxy, bool useDefaultCredentials = false)
        {

            if (null == httpClient)
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
                httpClient = new HttpClient(httpClientHandler);

                httpClient.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("AadAuthenticationFactory", CoreAssembly.Version.ToString()));
            }
        }
        public HttpClient GetHttpClient()
        {
            return httpClient;
        }
    }
}
