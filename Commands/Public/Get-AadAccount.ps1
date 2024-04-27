function Get-AadAccount
{
    <#
.SYNOPSIS
    Returns account(s) from AAD authentication factory cache

.DESCRIPTION
    For supported factory types, command returns either account(s) that match provided user account, or all accounts available in the cche.
    For unsupported factories (those working with Managed Identities) does not return anything

.OUTPUTS
    One or more accounts found in factory cache

.NOTES
    Command uses -match operator to match value of UserName parameter with usernames of accounts in factory's cache

.EXAMPLE
New-AadAuthenticationFactory -TenantId mydomain.com -RequiredScopes @('https://eventgrid.azure.net/.default') -AuthMode Interactive
Get-AadToken
Get-AadAccount

Description
-----------
Returns all accounts from cache of most recently created factory.

.EXAMPLE
New-AadAuthenticationFactory -TenantId mydomain.com -RequiredScopes @('https://eventgrid.azure.net/.default') -AuthMode Interactive
Get-AadAccount -UserName John

Description
-----------
Returns all accounts from factory cache that match pattern 'John'.

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
