function Get-AadAuthenticationFactory
{
    <#
.SYNOPSIS
    Returns one or more authentication factories from the current session.

.DESCRIPTION
    Returns the authentication factory specified by name.
    If Name is not specified, the most recently created factory is returned.
    When All is specified, all factories created in the current session are returned.
    If a requested factory does not exist, the command returns $null.

.PARAMETER Name
    Name of the factory to retrieve. If omitted, the most recently created
    factory is returned.

.PARAMETER All
    Returns every authentication factory created in the current session.

.OUTPUTS
    Authentication factory object, a collection of factories, or $null

.EXAMPLE
Get-AadAuthenticationFactory

Description
-----------
Returns the most recently created authentication factory.

.EXAMPLE
Get-AadAuthenticationFactory -Name 'Vault'

Description
-----------
Returns the factory created with the name 'Vault', or $null if it does not exist.

.EXAMPLE
Get-AadAuthenticationFactory -All

Description
-----------
Returns all authentication factories created in the current PowerShell session.

#>
    [CmdletBinding(DefaultParameterSetName = 'SpecificFactory')]
    param
    ( 
        [Parameter(ValueFromPipeline, ParameterSetName = 'SpecificFactory')]
        [string]
            #name of the factory to retrieve. If not specified, returns last created factory
        $Name,
        [Parameter(ParameterSetName = 'All')]
        [switch]
            #returns all factories created in current session
        $All
    )

    process
    {
        Switch($PSCmdlet.ParameterSetName)
        {
            'All' {
                $script:AadAuthenticationFactories.Values
                break;
            }
            'SpecificFactory' {
                if([string]::IsNullOrEmpty($Name))
                {
                    $script:AadLastCreatedFactory
                }
                else
                {
                    $script:AadAuthenticationFactories[$Name]
                }
                break;
            }
        }
    }
}
