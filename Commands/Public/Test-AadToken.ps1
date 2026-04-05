function Test-AadToken
{
    <#
.SYNOPSIS
    Parses and validates an Entra ID token.

.DESCRIPTION
    Parses a JWT access token or ID token and validates its signature against the
    issuer's OpenID configuration and signing keys. The Token parameter accepts a
    raw JWT string, an AuthenticationResult returned by Get-AadToken, or a
    hashtable containing an Authorization header.
    Some tokens that contain nonce-related header data may not validate cleanly.
    See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/609 for details.

.PARAMETER Token
    Raw JWT string, AuthenticationResult, or Authorization header hashtable.

.PARAMETER OidcConfigUri
    OpenID configuration endpoint to use instead of deriving it from the token.

.PARAMETER PayloadOnly
    Returns only the parsed payload claims instead of the full validation result.

.OUTPUTS
    Token validation result object or the parsed token payload

.EXAMPLE
$factory = New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('https://eventgrid.azure.net/.default') -AuthMode Interactive
$token = $factory | Get-AadToken
$token.idToken | Test-AadToken | fl

Description
-----------
Acquires a token, extracts the ID token, and validates it.

.EXAMPLE
New-AadAuthenticationFactory -TenantId contoso.onmicrosoft.com -DefaultScopes @('https://graph.microsoft.com/.default') -AuthMode Interactive
Get-AadToken | Test-AadToken -PayloadOnly

Description
-----------
Acquires an access token, validates it, and returns only the parsed claims.

.EXAMPLE
$headers = Get-AadToken -AsHashtable
Test-AadToken -Token $headers

Description
-----------
Validates a bearer token when it is supplied as an Authorization header hashtable.
#>
[CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [object]
            #IdToken or AccessToken field from token returned by Get-AadToken
            #or complete result of Get-AadToken - in such case, AccessToken is examined
        $Token,
        [Parameter()]
        [string]
            #OpenID configuration URI - if not provided, it's taken from token
        $OidcConfigUri,
        [switch]
            #Causes to retun just parsed payload of token - contains list of claims
        $PayloadOnly
    )

    process
    {
        if($token -is [Microsoft.Identity.Client.AuthenticationResult])
        {
            if($null -ne $token.AccessToken)
            {
                Write-Verbose 'Using AccessToken from provided token'
                $Token = $Token.AccessToken
            }
            else
            {
                if($null -ne $token.IdToken)
                {
                    Write-Verbose 'Using IdToken from provided token'
                    $Token = $Token.IdToken
                }
                else
                {
                    Write-Error 'Invalid format of provided token'
                    return
                }
            }
        }
        else
        {
            if($token -is [System.Collections.Hashtable])
            {
                if($null -ne $token['Authorization'])
                {
                    Write-Verbose 'Using AccessToken from provided hashtable'
                    $token = $token['Authorization'].Replace('Bearer ','')
                }
                else
                {
                    Write-Error 'Provided hashtable does not contain Authorization key'
                }
            }
            else
            {
                Write-Verbose 'Using provided plaintext token'
            }
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

        try {
            if($null -eq $result.Payload.iss)
            {
                Write-Warning "Token does not contain issuer information --> most likely not valid AAD token. Cannot perform token validation against issuer's signature"
                return
            }
            #validate the token

            #validate the result using published keys
            if(-not [string]::IsNullOrEmpty($OidcConfigUri))
            {
                $endpoint = $OidcConfigUri
            }
            else
            {
                if($null -eq $result.Payload.tfp)
                {
                    #AAD token
                    $endpoint = $result.Payload.iss
                    if(-not $endpoint.EndsWith('/'))
                    {
                        $endpoint += '/'
                    }
                    $endpoint = "$endpoint`.well-known/openid-configuration"
                }
                else
                {
                    #AAD B2C token
                    Write-Verbose "It's B2C token"
                    $endpoint = $result.Payload.iss.Replace('/v2.0/','')
                    $endpoint = "$endpoint/$($result.Payload.tfp)/.well-known/openid-configuration"
                }
            }
            Write-Verbose "Getting openid configuration from $endpoint"
            try {
                $config = Invoke-RestMethod -Method Get -Uri $endpoint -ErrorAction Stop -Verbose:$false
            }
            catch {
                Write-Warning "Could not get openid configuration from endpoint $endpoint"
                return
            }
            $keysEndpoint = $config.jwks_uri
    
            Write-Verbose "Getting signing keys from $keysEndpoint"
            try {
                $signingKeys = Invoke-RestMethod -Method Get -Uri $keysEndpoint -ErrorAction Stop -Verbose:$false
            }
            catch {
                Write-Warning "Could not get signing keys from endpoint $keysEndpoint"
                return
            }
            Write-Verbose "Received $($signingKeys.keys.count) signing keys:"
            Write-Verbose ($signingKeys | ConvertTo-Json -Depth 9)
    
            $key = $signingKeys.keys | Where-object{$_.kid -eq $result.Header.kid}
            if($null -eq $key)
            {
                Write-Warning "Could not find signing key with id = $($result.Header.kid) on endpoint $keysEndpoint"
                return
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
                return
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
        }
        finally
        {
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
}
