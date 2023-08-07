enum AuthenticationFlow
{
    #Public client with browser based auth
    PublicClient
    #Public client with console based auth
    PublicClientWithDeviceCode
    #Public client with Windows Integrated auth
    PublicClientWithWia
    #Public client with Windows Authentication Broker
    PublicClientWithWam
    #Confidential client with client secret or certificate
    ConfidentialClient
    #Confidential client with System-assigned Managed identity or Arc-enabled server
    ManagedIdentity
    #Confidential client with User-assigned Managed identity
    UserAssignedIdentity
    #Unattended Resource Owner auth with username and password
    ResourceOwnerPassword
}
