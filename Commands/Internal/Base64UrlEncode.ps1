function Base64UrlEncode
{
    param
    (
        [Parameter(Mandatory,ValueFromPipeline)]
        [byte[]]$Data
    )

    process
    {
        $result = [System.Convert]::ToBase64String($Data)
        $result = $result.Replace('+','-').Replace('/','_').TrimEnd('=')

        $result
    }
}
