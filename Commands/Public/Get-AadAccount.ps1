function Get-AadAccount
{
    <#
.SYNOPSIS
    Returns cached Entra ID accounts from an authentication factory.

.DESCRIPTION
    Returns cached account objects for a public client authentication factory.
    When UserName is specified, the command filters cached accounts by using
    PowerShell's -match operator against the account user name.
    Managed identity and other non-public client factories do not return accounts.

.PARAMETER UserName
    Optional user name pattern used to filter cached accounts.

.PARAMETER Factory
    Authentication factory instance, or the name of a previously created factory.
    If not specified, the most recently created factory is used.

.OUTPUTS
    Microsoft.Identity.Client.IAccount

.NOTES
    UserName filtering uses the PowerShell -match operator.

.EXAMPLE
New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('https://management.azure.com/.default') -AuthMode Interactive
Get-AadToken | Test-AadToken -PayloadOnly
Get-AadAccount

Description
-----------
Returns all cached accounts for the most recently created public client factory.

.EXAMPLE
Get-AadAccount -Factory 'Default' -UserName 'john'

Description
-----------
Returns cached accounts from the named factory whose user name matches 'john'.

#>
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline)]
            #User name to get account information for
            #If not specified, all accounts cached in factory are returned
        [string]$UserName,
            #AAD authentication factory created via New-AadAuthenticationFactory
        $Factory = $script:AadLastCreatedFactory
    )

    begin
    {
        [System.Threading.CancellationTokenSource]$cts = new-object System.Threading.CancellationTokenSource([timespan]::FromSeconds(180))
    }
    process
    {
        if($factory -is [string])
        {
            $factory = Get-AadAuthenticationFactory -Name $factory
        }

        if($factory -is [Microsoft.Identity.Client.PublicClientApplication])
        {
            if([string]::IsNullOrEmpty($Factory.B2CPolicy))
            {
                $allAccounts = $Factory.GetAccountsAsync() | AwaitTask -CancellationTokenSource $cts
            }
            else
            {
                $allAccounts = $Factory.GetAccountsAsync($Factory.B2CPolicy) | AwaitTask -CancellationTokenSource $cts
            }

            if(-not [string]::IsNullOrEmpty($UserName))
            {
                $allAccounts | Where-Object{$_.UserName -match $Username}
            }
            else 
            {
                $allAccounts
            }
        }
    }
    end
    {
        if($null -ne $cts)
        {
            $cts.Dispose()
        }
    }
}
