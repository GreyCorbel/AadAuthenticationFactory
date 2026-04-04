function Get-AssemblyVersionFromPath {
    param([Parameter(Mandatory)][string]$Path)

    try {
        return [AssemblyName]::GetAssemblyName($Path).Version
    } catch {
        return $null
    }
}
