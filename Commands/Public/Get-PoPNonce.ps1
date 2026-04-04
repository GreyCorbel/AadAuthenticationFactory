function Get-PoPNonce
{
<#
.SYNOPSIS
    Retrieves a Proof-of-Possession nonce from a resource.

.DESCRIPTION
    Sends an unauthenticated request to a resource and inspects the
    WWW-Authenticate response headers for a PoP challenge. If the resource
    advertises PoP and provides a nonce, that nonce is returned; otherwise the
    command returns $null.

.PARAMETER Uri
    Resource URI to probe for a PoP challenge.

.PARAMETER Method
    HTTP method to use when probing the resource.

.PARAMETER Factory
    Authentication factory whose HTTP client should be used to send the request.
    If not specified, the most recently created factory is used.

.OUTPUTS
    System.String or $null

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('api://myapi/.default') -AuthMode Broker
Get-PoPNonce -Uri 'https://myapi.contoso.com/items' -Method ([System.Net.Http.HttpMethod]::Get) -Factory $factory

Description
-----------
Checks whether the target API challenges clients for a PoP token and returns the nonce if one is provided.

#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
            #URI of the resource to get PoP nonce for            
        [string]$Uri,
        [Parameter(Mandatory=$true)]
            #HTTP method to use for request
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
