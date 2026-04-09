function NewJwk
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [int]$KeyLength = 2048,
        [Parameter()]
        [string]$kid = 'key1'
    )

    process
    {
        $rsa = [System.Security.Cryptography.RSA]::Create($KeyLength)
        $parameters = $rsa.ExportParameters($false)

        $jwk = @{
            kty = 'RSA'
            n   = Base64UrlEncode -Data $parameters.Modulus
            e   = Base64UrlEncode -Data $parameters.Exponent
            kid = $kid
        }
        $jwk
    }
}
