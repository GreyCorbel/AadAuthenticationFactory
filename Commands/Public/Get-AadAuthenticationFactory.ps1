function Get-AadAuthenticationFactory
{
    <#
.SYNOPSIS
    Returns authentication factory specified by name or most recently created factory

.DESCRIPTION
    Returns authentication factory specified by name.
    If no name is specified, returns the last created factory.
    If factory specified by name does not exist, returns null
    If -All switch is specified, returns all factories created in current session
    if no factory created yet, returns null

.OUTPUTS
    Authentication factory, or null

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
