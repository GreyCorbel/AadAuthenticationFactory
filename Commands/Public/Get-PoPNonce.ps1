function Get-PoPNonce
{
<#
.SYNOPSIS
    Returns Proof-of-Possession nonce from resource, or $null if resource does nto support PoP

.DESCRIPTION
    Returns Proof-of-Possession nonce from resource, or $null if resource does nto support PoP

.OUTPUTS
    String with PoP nonce, or $null if resource does not support PoP

#>
    [CmdletBinding()]
    param
    ( 
        #Resource to get PoP nonce for
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        [Parameter(Mandatory=$true)]
        [System.Net.Http.HttpMethod]$Method,
        [Parameter(ValueFromPipeline)]
            #AAD authentication factory created via New-AadAuthenticationFactory
        $Factory = $script:AadLastCreatedFactory

    )
    begin
    {
        [System.Threading.CancellationTokenSource]$cts = new-object System.Threading.CancellationTokenSource([timespan]::FromSeconds(10))
    }

    process
    {
        try {
            $message = New-Object System.Net.Http.HttpRequestMessage
            $message.Method = $Method
            $message.RequestUri = [System.Uri]::new($Uri)
            $client = $factory.HttpClientFactory.GetHttpClient()
            $response = $client.SendAsync($message) | AwaitTask -CancellationTokenSource $cts
            if($response.StatusCode -eq [System.Net.HttpStatusCode]::Unauthorized -and $null -ne $response.Headers.WwwAuthenticate)
            {
                $popHeader = $response.Headers.WwwAuthenticate | Where-Object {$_.scheme -eq 'PoP'}
                if($null -ne $popHeader)
                {
                    $r = [Microsoft.Identity.Client.WwwAuthenticateParameters]::CreateFromAuthenticationHeaders($response.Headers, 'PoP')  
                    $r.Nonce
                }
            }
        }
        finally
        {
            if($null -ne $message)
            {
                $message.Dispose()
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
