function Add-TypeSafePath {
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path $Path) {
        Add-Type -Path $Path -ErrorAction Stop | Out-Null
        return $true
    }
    return $false
}
