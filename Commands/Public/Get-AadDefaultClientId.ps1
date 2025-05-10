function Get-AadDefaultClientId
{
    <#
.SYNOPSIS
    Returns default AAD client ID used by module, which is client id for Azure Powershell

.DESCRIPTION
    Returns default AAD client ID used by module, which is client id for Azure Powershell

.OUTPUTS
    Default client id used by module
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
