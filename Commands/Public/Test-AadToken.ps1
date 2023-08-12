function Test-AadToken
{
    <#
.SYNOPSIS
    Parses and validates AAD-issued token

.DESCRIPTION
    Parses provided IdToken or AccessToken and checks for its validity.
    Note that some tokens may not be properly validated - this is in case then 'nonce' field present and set in the haeder. AAD issues such tokens for Graph API and nonce is taken into consideration when validating the token.
    See discussion at https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609 for more details.

.OUTPUTS
    Parsed token and information about its validity

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId mydomain.com  -RequiredScopes @('https://eventgrid.azure.net/.default') -AuthMode Interactive
$token = $factory | Get-AadToken
$token.idToken | Test-AadToken | fl

Description
-----------
Command creates authentication factory, asks it to issue token for EventGrid and parses IdToken and validates it

.EXAMPLE
New-AadAuthenticationFactory -TenantId mydomain.com  -DefaultScopes @('https://graph.microsoft.com/.default') -AuthMode Interactive
Get-AadToken | Test-AadToken -PayloadOnly

Description
-----------
Command creates authentication factory, asks it to issue token for MS Graph and parses AccessToken (this is token to use when passing complete response from Get-AadToken), validates it and shows claims contained
#>
[CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [object]
        #IdToken or AccessToken field from token returned by Get-AadToken
        #or complete result of Get-AadToken - in such case, AccessToken is examined
        $Token,
        [switch]
        $PayloadOnly
    )

    process
    {
        if($token -is [Microsoft.Identity.Client.AuthenticationResult])
        {
            $Token = $Token.AccessToken
        }
        if($token -is [System.Collections.Hashtable])
        {
            $token = $token['Authorization'].Replace('Bearer ','')
        }
        $parts = $token.split('.')
        if($parts.Length -ne 3)
        {
            Write-Error 'Invalid format of provided token'
            return
        }
        
        Write-Verbose "Parsing the token"
        $result = [PSCustomObject]@{
            Header = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Base64UrlDecode -Data $parts[0]))) | ConvertFrom-Json
            Payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Base64UrlDecode -Data $parts[1]))) | ConvertFrom-Json
            IsValid = $false
        }

        #validate the result using published keys
        if($null -eq $result.Payload.tfp)
        {
            #AAD token
            Write-Verbose "It's standard AAD token"
            $endpoint = $result.Payload.iss.Replace('/v2.0','')
            $keysEndpoint = "$($endpoint)/discovery/v2.0/keys"
        }
        else
        {
            #AAD B2C token
            Write-Verbose "It's B2C token"
            $endpoint = $result.Payload.iss.Replace('/v2.0/','')
            $keysEndpoint = "$endpoint/$($result.Payload.tfp)/discovery/v2.0/keys"
        }

        Write-Verbose "Getting signing keys from $keysEndpoint"
        $signingKeys = Invoke-RestMethod -Method Get -Uri $keysEndpoint
        Write-Verbose "Received signing keys:"
        Write-Verbose ($signingKeys | ConvertTo-Json -Depth 9)

        $key = $signingKeys.keys | Where-object{$_.kid -eq $result.Header.kid}
        if($null -eq $key)
        {
            Write-Warning "Could not find signing key with id = $($result.Header.kid) on endpoint $keysEndpoint"
            return $result
        }
        Write-Verbose "Using key with kid: $($key.kid)"

        $rsa = $null
        if($null -ne $key.e -and $null -ne $key.n)
        {
            Write-Verbose "Getting public key from modulus $($key.n) and exponent $($key.e)"
            $exponent = Base64UrlDecode -data $key.e
            $exponent = [convert]::FromBase64String($exponent)
            $modulus = Base64UrlDecode -data $key.n
            $modulus = [convert]::FromBase64String($modulus)
            $rsa = new-object System.Security.Cryptography.RSACryptoServiceProvider
            $params = new-object System.Security.Cryptography.RSAParameters
            $params.Exponent = $exponent
            $params.Modulus = $modulus
            $rsa.ImportParameters($params)
        }
        else {
            if($null -ne $key.x5c)
            {
                Write-Verbose "Getting public key from x5c: $($key.x5c)"
                $cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($key.x5c[0]))
                $rsa = $cert.PublicKey.Key
            }    
        }

        if($null -eq $rsa)
        {
            Write-Warning "Could not validate the token as both x5c and n/e information is missing"
            return $result
        }

        Write-Verbose "Creating payload to validate"
        $payload = "$($parts[0]).$($parts[1])"
        $dataToVerify = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $sig = Base64UrlDecode -Data $parts[2]
        $signature = [Convert]::FromBase64String($sig)

        switch($result.Header.alg)
        {
            'RS384' {
                $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA384
                break;
            }
            'RS512' {
                $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA512
                break;
            }
            default {
                $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
                break;
            }
        }
        $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        Write-Verbose "Validating payload"
        $result.IsValid = $rsa.VerifyData($dataToVerify,$signature,$hash,$Padding)
        if($null -ne $cert) {$cert.Dispose()}
        if($null -ne $result.Header.nonce)
        {
            Write-Verbose "Header contains nonce, so token may not be properly validated. See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609"
        }
        $result.psobject.typenames.Insert(0,'GreyCorbel.Identity.Authentication.TokenValidationResult')
        if($PayloadOnly)
        {
            $result.Payload
        }
        else
        {
            $result
        }
    }
}
