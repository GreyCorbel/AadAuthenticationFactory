using namespace System.IO
param
(
    [string]$rootPath = '.',
    [string]$moduleName
)
Function Update-Manifest
{
    param
    (
        
        [Parameter(Mandatory)]
        $ManifestFile,
        [Parameter(Mandatory)]
        $AttributeName,
        [Parameter(Mandatory)]
        $AttributeValue
    )

    process
    {
        $Tokens = $Null; $ParseErrors = $Null
        $ManifestContent = Get-Content $manifestFile -Raw
        $AST = [System.Management.Automation.Language.Parser]::ParseInput( $ManifestContent, $ManifestFile, [ref]$Tokens, [ref]$ParseErrors )
        $ManifestHash = $AST.Find( {$args[0] -is [System.Management.Automation.Language.HashtableAst]}, $true )
        $keyValue = $ManifestHash.KeyValuePairs.Where{$_.Item1.Value -eq $AttributeName}.Item2
        $Extent = $KeyValue.Extent

        while($KeyValue.parent) { $KeyValue = $KeyValue.parent }
        $ManifestContent = $KeyValue.Extent.Text.Remove($Extent.StartOffset, ($Extent.EndOffset - $Extent.StartOffset)).Insert($Extent.StartOffset,$AttributeValue)
        Set-Content $manifestFile $ManifestContent.Trim()
    }
}

if([string]::IsNullOrWhiteSpace($moduleName))
{
    Write-Error 'Module name must be provided'
    return
}

$moduleFile = [Path]::Combine($rootPath,'Module',$moduleName,"$moduleName`.psm1")
$publicCommands = new-object System.Collections.Generic.List[string]

#clear the file
Clear-Content -Path $moduleFile

if(Test-Path ([Path]::Combine($rootPath,'Commands','ModuleStart.ps1')))
{
    Get-Content ([Path]::Combine($rootPath,'Commands','ModuleStart.ps1')) | Out-File -FilePath $moduleFile -Append
}

'#region Public commands' | Out-File -FilePath $moduleFile -Append
foreach($file in Get-ChildItem -Path ([Path]::Combine($rootPath,'Commands','Public')))
{
    Get-Content $file.FullName | Out-File -FilePath $moduleFile -Append
    [void]$publicCommands.Add($file.BaseName)
}
'#endregion Public commands' | Out-File -FilePath $moduleFile -Append

'#region Internal commands' | Out-File -FilePath $moduleFile -Append
foreach($file in Get-ChildItem -Path([Path]::Combine($rootPath,'Commands','Internal')))
{
    Get-Content $file.FullName | Out-File -FilePath $moduleFile -Append
}
'#endregion Internal commands' | Out-File -FilePath $moduleFile -Append

if(Test-Path ([Path]::Combine($rootPath,'Commands','ModuleInitialization.ps1')))
{
    '#region Module initialization' | Out-File -FilePath $moduleFile -Append
    Get-Content ([Path]::Combine($rootPath,'Commands','ModuleInitialization.ps1')) | Out-File -FilePath $moduleFile -Append
    '#endregion Module initialization' | Out-File -FilePath $moduleFile -Append
}
#region  module manifest
$manifestFile = [Path]::Combine($rootPath,'Module',$moduleName,"$moduleName`.psd1")
if(Test-Path $manifestFile)
{
    Update-Manifest -ManifestFile $manifestFile -AttributeName 'FunctionsToExport' -AttributeValue "@('$(($publicCommands -join "','"))')"
}
#endregion