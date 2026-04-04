function Get-AadDefaultClientId
{
    <#
.SYNOPSIS
    Returns the module's default Entra ID client ID.

.DESCRIPTION
    Returns the default client ID used when New-AadAuthenticationFactory is
    called without an explicit ClientId. The configured default is the Azure
    PowerShell public client application ID.

.OUTPUTS
    System.String

.EXAMPLE
Get-AadDefaultClientId

Description
-----------
Returns the client ID that the module uses by default for public client flows.

    #>
    [CmdletBinding()]
    param
    ( )

    process
    {
        $module = $MyInvocation.MyCommand.Module
        $Module.PrivateData.Configuration.DefaultClientId
    }
}
