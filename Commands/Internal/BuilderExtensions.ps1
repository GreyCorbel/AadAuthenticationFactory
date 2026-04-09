function WithSshCertificate
{
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]   $builder,
        [Parameter(Mandatory)]                      [int]$SshKeyLength
    )

    process
    {
        if($SshKeyLength -gt 0)
        {
            $keyId = 'key01'
            $jwkData = NewJwk -KeyLength $SshKeyLength | ConvertTo-Json -Depth 10
            Write-Verbose "Requesting SSH certificate with JWK: $jwkData and keyId: $keyId"
            $builder = [Microsoft.Identity.Client.SSHCertificates.SSHExtensions]::WithSSHCertificateAuthenticationScheme($builder,$jwkData, $keyId)
        }
        return $builder
    }
}

function WithJwk
{
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]   $builder,
        [Parameter(Mandatory=$true)]                [hashtable]$Jwk
    )

    process
    {
        $jwkData = [PSCustomObject]$jwk | Select-object -ExcludeProperty kid | ConvertTo-Json -Depth 10
        Write-Verbose "Requesting SSH certificate with JWK: $jwkData and keyId: $($jwk.kid)"
        $builder = [Microsoft.Identity.Client.SSHCertificates.SSHExtensions]::WithSSHCertificateAuthenticationScheme($builder,$jwkData, $jwk.kid)
        return $builder
    }  
}

function WithWwwAuthenticateParameters
{
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]   $builder,
        [Parameter()]                               [hashtable]$WwwAuthenticateParameters
    )

    process
    {
        if($null -ne $WwwAuthenticateParameters -and $WwwAuthenticateParameters.ContainsKey('Authority') -and $WwwAuthenticateParameters.ContainsKey('Claims'))
        {
            $builder = $builder.WithAuthority($WwwAuthenticateParameters.Authority)
            $builder = $builder.WithClaims($WwwAuthenticateParameters.Claims)
        }
        return $builder
    }
}

function WithForceRefresh
{
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]   $builder,
        [Parameter()]                               [bool]$ForceRefresh
    )

    process
    {
        if($ForceRefresh)
        {
            Write-Verbose "Forcing refresh of token"
        }
        $builder = $builder.WithForceRefresh($ForceRefresh)
        return $builder
    }
}
