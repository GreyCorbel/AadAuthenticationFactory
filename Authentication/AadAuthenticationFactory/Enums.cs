namespace GreyCorbel.Identity.Authentication
{
    /// <summary>
    /// Public client supported authentication flows
    /// </summary>
    public enum AuthenticationMode
    {
        /// <summary>
        /// Interactive flow with webview or browser
        /// </summary>
        Interactive,
        /// <summary>
        /// DeviceCode flow with authentication performed with code on different device
        /// </summary>
        DeviceCode,
        /// <summary>
        /// Windows Integrated Authentication - supported on machines joined to AD, or hybrid joined, and authenticating with ADFS
        /// </summary>
        WIA,
        /// <summary>
        /// Non-interactive flow - login process does not require UI
        /// </summary>
        Silent
    }

    /// <summary>
    /// Type of client we use for auth
    /// </summary>
    enum AuthenticationFlow
    {
        /// <summary>
        /// Public client with browser based auth
        /// </summary>
        PublicClient,
        /// <summary>
        /// Public client with console based auth
        /// </summary>
        PublicClientWithDeviceCode,
        /// <summary>
        /// Public client with Windows Integrated auth
        /// </summary>
        PublicClientWithWia,
        /// <summary>
        /// Confidential client with client secret or certificate
        /// </summary>
        ConfidentialClient,
        /// <summary>
        /// Confidential client with System-assigned Managed identity or Arc-enabled server
        /// </summary>
        ManagedIdentity,
        /// <summary>
        /// Confidential client with User-assigned Managed identity
        /// </summary>
        UserAssignedIdentity,
        /// <summary>
        /// Unattended Resource Owner auth with username and password
        /// </summary>
        ResourceOwnerPassword
    }
}