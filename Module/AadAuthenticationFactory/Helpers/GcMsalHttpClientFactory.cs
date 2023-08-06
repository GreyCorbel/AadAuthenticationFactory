using Microsoft.Identity.Client;
using System.Net;
using System.Net.Http;

public class GcMsalHttpClientFactory : Microsoft.Identity.Client.IMsalHttpClientFactory
{
    static HttpClient _httpClient;

    protected GcMsalHttpClientFactory(WebProxy proxy, string productVersion, bool useDefaultCredentials = false)
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

            _httpClient.DefaultRequestHeaders.UserAgent.Add(new System.Net.Http.Headers.ProductInfoHeaderValue("AadAuthenticationFactory", productVersion));
        }
    }

    public HttpClient GetHttpClient()
    {
        return _httpClient;
    }

    //PS5 has trouble to get interface from object instance
    public static Microsoft.Identity.Client.IMsalHttpClientFactory Create(WebProxy proxy, string productVersion, bool useDefaultCredentials = false)
    {
        return new GcMsalHttpClientFactory(proxy, productVersion,useDefaultCredentials);
    }
}
