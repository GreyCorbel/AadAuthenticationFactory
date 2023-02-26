using Microsoft.Identity.Client;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace GreyCorbel.Identity.Authentication
{
    /// <summary>
    /// Main object responsible for authentication according to constructor and parameters used
    /// </summary>
    public class AadAuthenticationFactory
    {
        /// <summary>
        /// Tenant Id of AAD tenant that authenticates the user / app
        /// </summary>
        public string TenantId { get { return _tenantId; } }
        private readonly string _tenantId;

        /// <summary>
        /// ClientId to be used for authentication flows
        /// </summary>
        public string ClientId {get {return _clientId;}}
        private readonly string _clientId;

        /// <summary>
        /// AAD authorization endpoint. Defaults to public AAD
        /// </summary>
        public string LoginApi {get {return _loginApi;}}
        private readonly string _loginApi;

        /// <summary>
        /// Scopes the factory asks for when asking for tokens
        /// </summary>
        public string[] DefaultScopes {get {return _scopes;}}
        private readonly string[] _scopes;
        
        /// <summary>
        /// UserName hint to use in authentication flows to help select proper user. Useful in case multiple accounts are logged in.
        /// </summary>
        public string UserName { get { return _userNameHint; } }
        private readonly string _userNameHint;

        /// <summary>
        /// AuthenticationMode factory uses to get tokens
        /// </summary>
        public AuthenticationMode AuthenticationMode
        {
            get
            {
                return _authMode;
            }
        }
        private readonly AuthenticationMode _authMode;

        //type of auth flow to use
        private readonly AuthenticationFlow _flow;


        /// <summary>
        /// Password for ROPC flow
        /// </summary>
        private readonly SecureString _resourceOwnerPassword;

        private readonly IPublicClientApplication _publicClientApplication;
        private readonly IConfidentialClientApplication _confidentialClientApplication;
        private readonly ManagedIdentityClientApplication _managedIdentityClientApplication;
        private readonly string _defaultClientId = "1950a258-227b-4e31-a9cf-717495945fc2";

        #region Constructors

        /// <summary>
        /// Creates factory that supports Public client flows with Interactive, DeviceCode or WIA authentication
        /// </summary>
        /// <param name="tenantId">DNS name or Id of tenant that authenticates user</param>
        /// <param name="clientId">ClientId to use. If not specified, clientId of Azure Powershell is used</param>
        /// <param name="scopes">List of scopes that clients asks for</param>
        /// <param name="loginApi">AAD endpoint that will handle the authentication.</param>
        /// <param name="authenticationMode">Type of public client flow to use. Supported flows as Interactive, DeviceCode and WIA</param>
        /// <param name="userNameHint">Which username to use in auth UI in case there may be multiple names available</param>
        /// <param name="proxy">Optional configuration of proxy for internet access</param>
        public AadAuthenticationFactory(
            string tenantId, 
            string clientId, 
            string [] scopes, 
            string loginApi = "https://login.microsoftonline.com", 
            AuthenticationMode authenticationMode = AuthenticationMode.Interactive, 
            string userNameHint = null,
            WebProxy proxy = null)
        {
            if (string.IsNullOrWhiteSpace(clientId))
                _clientId = _defaultClientId;
            else
                _clientId = clientId;

            _loginApi = loginApi;
            _scopes = scopes;
            _userNameHint = userNameHint;
            _tenantId = tenantId;
            _authMode = authenticationMode;

            bool useDefaultCredentials = false;
            switch(authenticationMode)
            {
                case AuthenticationMode.WIA:
                    _flow = AuthenticationFlow.PublicClientWithWia;
                    //we're expected to send creds with request to federated IdP (e.g. ADFS)
                    useDefaultCredentials = true;
                    break;
                case AuthenticationMode.DeviceCode:
                    _flow = AuthenticationFlow.PublicClientWithDeviceCode;
                    break;
                default:
                    _flow = AuthenticationFlow.PublicClient;
                    break;
            }
            
            var builder = PublicClientApplicationBuilder.Create(_clientId)
                .WithDefaultRedirectUri()
                .WithAuthority($"{_loginApi}/{tenantId}")
                .WithHttpClientFactory(new GcMsalHttpClientFactory(proxy, useDefaultCredentials));

            _publicClientApplication = builder.Build();
        }

        /// <summary>
        /// Static method that creates factory for Public client flows with Interactive, DeviceCode or WIA authentication
        /// </summary>
        /// <param name="tenantId">DNS name or Id of tenant that authenticates user</param>
        /// <param name="clientId">ClientId to use. If not specified, clientId of Azure Powershell is used</param>
        /// <param name="scopes">List of scopes that clients asks for</param>
        /// <param name="loginApi">AAD endpoint that will handle the authentication.</param>
        /// <param name="authenticationMode">Type of public client flow to use. Supported flows as Interactive, DeviceCode and WIA</param>
        /// <param name="userNameHint">Which username to use in auth UI in case there may be multiple names available</param>
        /// <param name="proxy">Optional configuration of proxy for internet access</param>
        public static AadAuthenticationFactory Create(
            string tenantId,
            string clientId,
            string[] scopes,
            string loginApi = "https://login.microsoftonline.com",
            AuthenticationMode authenticationMode = AuthenticationMode.Interactive,
            string userNameHint = null,
            WebProxy proxy = null)
        {
            return new AadAuthenticationFactory(tenantId, clientId, scopes, loginApi, authenticationMode, userNameHint, proxy);
        }

        /// <summary>
        /// Creates factory that supports Confidential client flows via MSAL with ClientSecret authentication
        /// </summary>
        /// <param name="tenantId">DNS name or Id of tenant that authenticates user</param>
        /// <param name="clientId">ClientId to use</param>
        /// <param name="scopes">List of scopes that clients asks for</param>
        /// <param name="loginApi">AAD endpoint that will handle the authentication.</param>
        /// <param name="clientSecret">Client secret to be used</param>
        /// <param name="proxy">Optional configuration of proxy for internet access</param>
        public AadAuthenticationFactory(
            string tenantId,
            string clientId,
            string clientSecret,
            string[] scopes,
            string loginApi = "https://login.microsoftonline.com",
            WebProxy proxy = null)
        {
            _clientId = clientId;
            _loginApi = loginApi;
            _scopes = scopes;
            _authMode = AuthenticationMode.Silent;

            _flow = AuthenticationFlow.ConfidentialClient;

            var builder = ConfidentialClientApplicationBuilder.Create(_clientId)
                .WithClientSecret(clientSecret)
                .WithAuthority($"{_loginApi}/{tenantId}")
                .WithHttpClientFactory(new GcMsalHttpClientFactory(proxy));

            _confidentialClientApplication = builder.Build();
        }

        /// <summary>
        /// Creates factory for Confidential client authentication flow via MSAL and X509 certificate
        /// </summary>
        /// <param name="tenantId">Dns domain name or tenant guid</param>
        /// <param name="clientId">Client id that represents application asking for token</param>
        /// <param name="clientCertificate">X509 certificate with private key. Public part of certificate is expected to be registered with app registration for given client id in AAD.</param>
        /// <param name="scopes">Scopes application asks for</param>
        /// <param name="loginApi">AAD endpoint URL for special instance of AAD (/e.g. US Gov)</param>
        /// <param name="proxy">Optional configuration of proxy for internet access</param>
        public AadAuthenticationFactory(
            string tenantId,
            string clientId,
            X509Certificate2 clientCertificate,
            string[] scopes,
            string loginApi = "https://login.microsoftonline.com",
            WebProxy proxy = null)
        {
            _clientId = clientId;
            _loginApi = loginApi;
            _scopes = scopes;
            _authMode = AuthenticationMode.Silent;

            _flow = AuthenticationFlow.ConfidentialClient;

            var builder = ConfidentialClientApplicationBuilder.Create(_clientId)
                .WithCertificate(clientCertificate)
                .WithAuthority($"{_loginApi}/{tenantId}")
                .WithHttpClientFactory(new GcMsalHttpClientFactory(proxy));

            _confidentialClientApplication = builder.Build();
        }


        /// <summary>
        /// Creates factory that supports SystemAssignedIdentity (clientId passed is null) 
        /// or UserAssignedIdentity (clientId parameter represents user assigned identity) authentication
        /// </summary>
        /// <param name="clientId">AppId of User Assigned Identity or null (which means to use System Assigned Identity)</param>
        /// <param name="scopes">Required scopes to obtain. Currently obtains all assigned scopes for first resource in the array.</param>
        /// <param name="proxy">Optional configuration of proxy for internet access</param>
        public AadAuthenticationFactory(string clientId, string[] scopes, WebProxy proxy = null)
        {
            _scopes = scopes;
            if (!string.IsNullOrWhiteSpace(clientId))
            {
                _clientId = clientId;
            }
            else
            { 
                _clientId=null;
            }
            _managedIdentityClientApplication = new ManagedIdentityClientApplication(new GcMsalHttpClientFactory(proxy), _clientId);
            _flow = AuthenticationFlow.UserAssignedIdentity;
            _authMode = AuthenticationMode.Silent;
        }

        /// <summary>
        /// Creates factory that supports Public client ROPC flow
        /// </summary>
        /// <param name="tenantId">DNS name or Id of tenant that authenticates user</param>
        /// <param name="clientId">ClientId to use</param>
        /// <param name="scopes">List of scopes that clients asks for</param>
        /// <param name="loginApi">AAD endpoint that will handle the authentication.</param>
        /// <param name="userName">Resource owner username</param>
        /// <param name="password">Resource owner password</param>
        /// <param name="proxy">Optional configuration of proxy for internet access</param>
        public AadAuthenticationFactory(
            string tenantId,
            string clientId,
            string[] scopes,
            string userName,
            SecureString password,
            string loginApi = "https://login.microsoftonline.com",
            WebProxy proxy = null
            )
        {
            if (string.IsNullOrWhiteSpace(clientId))
                _clientId = _defaultClientId;
            else
                _clientId = clientId;

            _loginApi = loginApi;
            _scopes = scopes;
            _userNameHint = userName;
            _resourceOwnerPassword = password;
            _tenantId = tenantId;

            _flow = AuthenticationFlow.ResourceOwnerPassword;
            _authMode = AuthenticationMode.Silent;

            var builder = PublicClientApplicationBuilder.Create(_clientId)
                .WithDefaultRedirectUri()
                .WithAuthority($"{_loginApi}/{tenantId}")
                .WithHttpClientFactory(new GcMsalHttpClientFactory(proxy));

            _publicClientApplication = builder.Build();
        }


        #endregion

        #region Static methods
        /// <summary>
        /// Static method that creates factory that supports SystemAssignedIdentity (clientId passed is null) 
        /// or UserAssignedIdentity (clientId parameter represents user assigned identity) authentication
        /// </summary>
        /// <param name="clientId">AppId of User Assigned Identity or null (which means to use System Assigned Identity)</param>
        /// <param name="scopes">Required scopes to obtain. Currently obtains all assigned scopes for first resource in the array.</param>
        /// <param name="proxy">Optional configuration of proxy for internet access</param>
        public static AadAuthenticationFactory Create(string clientId, string[] scopes, WebProxy proxy = null) => new(clientId, scopes, proxy);

        /// <summary>
        /// Creates factory that supporrts Public client ROPC flow
        /// </summary>
        /// <param name="tenantId">DNS name or Id of tenant that authenticates user</param>
        /// <param name="clientId">ClientId to use</param>
        /// <param name="scopes">List of scopes that clients asks for</param>
        /// <param name="loginApi">AAD endpoint that will handle the authentication.</param>
        /// <param name="userName">Resource owner username</param>
        /// <param name="password">Resource owner password</param>
        /// <param name="proxy">Optional configuration of proxy for internet access</param>
        public static AadAuthenticationFactory Create(
            string tenantId,
            string clientId,
            string[] scopes,
            string userName,
            SecureString password,
            string loginApi = "https://login.microsoftonline.com",
            WebProxy proxy = null
            ) => new(tenantId, clientId, scopes, userName, password, loginApi, proxy);

        /// <summary>
        /// Static method that creates factory for Confidential client authentication flow via MSAL and X509 certificate
        /// </summary>
        /// <param name="tenantId">Dns domain name or tenant guid</param>
        /// <param name="clientId">Client id that represents application asking for token</param>
        /// <param name="clientCertificate">X509 certificate with private key. Public part of certificate is expected to be registered with app registration for given client id in AAD.</param>
        /// <param name="scopes">Scopes application asks for</param>
        /// <param name="loginApi">AAD endpoint URL for special instance of AAD (/e.g. US Gov)</param>
        /// <param name="proxy">Optional configuration of proxy for internet access</param>
        public static AadAuthenticationFactory Create(
            string tenantId,
            string clientId,
            X509Certificate2 clientCertificate,
            string[] scopes,
            string loginApi = "https://login.microsoftonline.com",
            WebProxy proxy = null) => new(tenantId, clientId, clientCertificate, scopes, loginApi, proxy);

        /// <summary>
        /// Static method that creates factory that supports Confidential client flows via MSAL with ClientSecret authentication
        /// </summary>
        /// <param name="tenantId">DNS name or Id of tenant that authenticates user</param>
        /// <param name="clientId">ClientId to use</param>
        /// <param name="scopes">List of scopes that clients asks for</param>
        /// <param name="loginApi">AAD endpoint that will handle the authentication.</param>
        /// <param name="clientSecret">Client secret to be used</param>
        /// <param name="proxy">Optional configuration of proxy for internet access</param>
        public static AadAuthenticationFactory Create(
            string tenantId,
            string clientId,
            string clientSecret,
            string[] scopes,
            string loginApi = "https://login.microsoftonline.com",
            WebProxy proxy = null) => new(tenantId, clientId, clientSecret, scopes, loginApi, proxy);

        #endregion

        #region Authentication
        /// <summary>
        /// Returns authentication result for on-behalf-of flow
        /// Microsoft says we should not instantiate directly - but how to achieve unified experience of caller without being able to return it?
        /// </summary>
        /// <param name="jwtBearerToken">Access token for user to be used as an assertion for on-behal-of flow</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <param name="requiredScopes">Scopes to ask for</param>
        /// <returns cref="AuthenticationResult">Authentication result object either returned MSAL library</returns>
        /// <exception cref="ArgumentException">Throws if unsupported authentication mode or flow detected</exception>
        public async Task<AuthenticationResult> AuthenticateAsync(string jwtBearerToken, string[] requiredScopes, CancellationToken cancellationToken)
        {
            if (null == requiredScopes)
                requiredScopes = _scopes;

            if (null == requiredScopes || requiredScopes.Count() == 0)
                throw new ArgumentException("No scope(s) specified");

            UserAssertion ua = new UserAssertion(jwtBearerToken);
            switch (_flow)
            {
                case AuthenticationFlow.ConfidentialClient:
                    return await _confidentialClientApplication.AcquireTokenOnBehalfOf(requiredScopes, ua)
                        .ExecuteAsync(cancellationToken);
            }
            throw new ArgumentException($"Unsupported authentication flow for on-behalf-of: {_flow}");
        }

        /// <summary>
        /// Returns authentication result
        /// Microsoft says we should not instantiate directly - but how to achieve unified experience of caller without being able to return it?
        /// </summary>
        /// <param name="requiredScopes">Scopes to ask for and if different than passed to factory constructor.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns cref="AuthenticationResult">Authentication result object either returned fropm MSAL libraries, or - for ManagedIdentity - constructed from Managed Identity endpoint response, as returned by cref="ManagedIdentityClientApplication.ApiVersion" version of endpoint</returns>
        /// <exception cref="ArgumentException">Throws if unsupported authentication mode or flow detected</exception>
        public async Task<AuthenticationResult> AuthenticateAsync(string[] requiredScopes, CancellationToken cancellationToken)
        {
            AuthenticationResult result;
            if (null == requiredScopes)
                requiredScopes = _scopes;
            
            if (null == requiredScopes || requiredScopes.Count() == 0)
                throw new ArgumentException("No scope(s) specified");

            switch(_flow)
            {
                case AuthenticationFlow.PublicClientWithWia:
                {
                        var accounts = await _publicClientApplication.GetAccountsAsync();
                        IAccount account;
                        if (string.IsNullOrWhiteSpace(_userNameHint))
                            account = accounts.FirstOrDefault();
                        else
                            account = accounts.Where(x => string.Compare(x.Username, _userNameHint, true) == 0).FirstOrDefault();
                        if (null!=account)
                        {
                            result = await _publicClientApplication.AcquireTokenSilent(requiredScopes, account)
                                .ExecuteAsync();
                        }
                        else
                        {
                            result = await _publicClientApplication.AcquireTokenByIntegratedWindowsAuth(_scopes).WithUsername(_userNameHint)
                                .ExecuteAsync(cancellationToken);
                            //let the app throw to caller when UI required as the purpose here is to stay silent
                        }
                        return result;
                }
                //public client flow
                case AuthenticationFlow.PublicClient:
                    {
                        var accounts = await _publicClientApplication.GetAccountsAsync();
                        IAccount account;
                        if (string.IsNullOrWhiteSpace(_userNameHint))
                            account = accounts.FirstOrDefault();
                        else
                            account = accounts.Where(x => string.Compare(x.Username, _userNameHint, true) == 0).FirstOrDefault();
                        try
                        {
                            result = await _publicClientApplication.AcquireTokenSilent(requiredScopes, account)
                                              .ExecuteAsync(cancellationToken);
                        }
                        catch (MsalUiRequiredException)
                        {
                            result = await _publicClientApplication.AcquireTokenInteractive(requiredScopes)
                                .ExecuteAsync(cancellationToken);
                        }
                        return result;
                    }
                case AuthenticationFlow.PublicClientWithDeviceCode:
                    {
                        var accounts = await _publicClientApplication.GetAccountsAsync();
                        IAccount account;
                        if (string.IsNullOrWhiteSpace(_userNameHint))
                            account = accounts.FirstOrDefault();
                        else
                            account = accounts.Where(x => string.Compare(x.Username, _userNameHint, true) == 0).FirstOrDefault();
                        try
                        {
                            result = await _publicClientApplication.AcquireTokenSilent(requiredScopes, account)
                                              .ExecuteAsync(cancellationToken);
                        }
                        catch (MsalUiRequiredException)
                        {
                            result = await _publicClientApplication.AcquireTokenWithDeviceCode(requiredScopes, callback =>
                                {
                                    Console.WriteLine(callback.Message);
                                    return Task.FromResult(0);
                                }).ExecuteAsync(cancellationToken);
                        }
                        return result;
                    }
                case AuthenticationFlow.ConfidentialClient:
                    return await _confidentialClientApplication.AcquireTokenForClient(requiredScopes).ExecuteAsync(cancellationToken);
                //System Managed identity
                case AuthenticationFlow.ManagedIdentity:
                    return await _managedIdentityClientApplication.AcquireTokenForClientAsync(requiredScopes, cancellationToken);
                //User managed identity
                case AuthenticationFlow.UserAssignedIdentity:
                    return await _managedIdentityClientApplication.AcquireTokenForClientAsync(requiredScopes, cancellationToken);
                //ROPC flow
                case AuthenticationFlow.ResourceOwnerPassword:
                {
                    var accounts = await _publicClientApplication.GetAccountsAsync();
                    IAccount account;
                    if (string.IsNullOrWhiteSpace(_userNameHint))
                        account = accounts.FirstOrDefault();
                    else
                        account = accounts.Where(x => string.Compare(x.Username, _userNameHint, true) == 0).FirstOrDefault();

                    try
                    {
                        result = await _publicClientApplication.AcquireTokenSilent(requiredScopes, account)
                                            .ExecuteAsync(cancellationToken);
                    }
                    catch (MsalUiRequiredException)
                    {
                        result = await _publicClientApplication.AcquireTokenByUsernamePassword(requiredScopes, _userNameHint, _resourceOwnerPassword)
                                .ExecuteAsync(cancellationToken);
                    }
                    return result;
                }
            }

            throw new ArgumentException($"Unsupported authentication flow: {_flow}");
        }
        #endregion

        void DebugLogging(LogLevel level, string message, bool containsPii)
        {
            Console.WriteLine($"MSAL {level} {containsPii} {message}");
        }
    }
}
