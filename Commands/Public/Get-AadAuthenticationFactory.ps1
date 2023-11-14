function Get-AadAuthenticationFactory
{
    <#
.SYNOPSIS
    Returns most authentication factory cached by module

.DESCRIPTION
    Returns most authentication factory cached by module

.OUTPUTS
    Existing authentication factory, or null

#>
    [CmdletBinding()]
    param
    ( )

    process
    {
        $script:AadLastCreatedFactory
    }
}
