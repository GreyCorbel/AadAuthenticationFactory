using Microsoft.Identity.Client;
using System.Threading;
using System.Threading.Tasks;

namespace GreyCorbel.Identity.Authentication.TokenProviders
{
    internal interface ITokenProvider
    {
        Task<AuthenticationResult> AcquireTokenForClientAsync(string[] scopes, CancellationToken cancellationToken);
    }
}
