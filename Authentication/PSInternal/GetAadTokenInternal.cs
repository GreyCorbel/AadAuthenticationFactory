using System;
using System.Collections.Generic;
using System.Text;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace GreyCorbel.Identity.Authentication
{
    /// <summary>
    /// Command to retrieve token from factory, supporting cancellation via Ctrl+C/Ctrl+Break
    /// </summary>
    [Cmdlet("Get", "AadTokenInternal")]
    public class GetAadTokenInternal:Cmdlet
    {
        /// <summary>
        /// Instance of AadAuthentication factory
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true)]
        public GreyCorbel.Identity.Authentication.AadAuthenticationFactory Factory;
        /// <summary>
        /// Required scopes, if different from default registered when creating factory
        /// </summary>
        [Parameter(Position = 1)]
        [Alias("RequiredScopes")]
        public string[] Scopes;
        /// <summary>
        /// User token for on-behalf-of flow
        /// </summary>
        [Parameter(Position = 2)]
        public string UserToken;

        private readonly CancellationTokenSource _cts = new CancellationTokenSource(TimeSpan.FromSeconds(120));

        /// <summary>
        /// Processes the request
        /// </summary>
        protected override void ProcessRecord()
        {
            AuthenticationResult result;
            if (string.IsNullOrWhiteSpace(UserToken))
            {
                result = Factory.AuthenticateAsync(_cts.Token, Scopes).GetAwaiter().GetResult();
            }
            else
            {
                result = Factory.AuthenticateAsync(UserToken, _cts.Token, Scopes).GetAwaiter().GetResult();
            }
            WriteObject(result);
        }

        /// <summary>
        /// To support Ctrl+Break
        /// </summary>
        protected override void StopProcessing()
        {
            base.StopProcessing();
            _cts.Cancel();
        }
    }
}
