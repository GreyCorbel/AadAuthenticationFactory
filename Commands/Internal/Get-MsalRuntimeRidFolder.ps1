function Get-MsalRuntimeRidFolder {
    (Get-MsalBrokerPlatformConfiguration).RuntimeIdentifier
}