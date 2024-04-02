param
(
    [string]$rootPath = '.',
    [string]$moduleName
)

if([string]::IsNullOrWhiteSpace($moduleName))
{
    Write-Error 'Module name must be provided'
    return
}

$moduleFile = "$rootPath\Module\$moduleName\$moduleName.psm1"
'#region Public commands' | Out-File -FilePath $moduleFile
foreach($file in Get-ChildItem -Path "$rootPath\Commands\Public")
{
    Get-Content $file.FullName | Out-File -FilePath $moduleFile -Append
}
'#endregion Public commands' | Out-File -FilePath $moduleFile -Append

'#region Internal commands' | Out-File -FilePath $moduleFile -Append
foreach($file in Get-ChildItem -Path "$rootPath\Commands\Internal")
{
    Get-Content $file.FullName | Out-File -FilePath $moduleFile -Append
}
'#endregion Internal commands' | Out-File -FilePath $moduleFile -Append

if(Test-Path "$rootPath\Commands\ModuleInitialization.ps1")
{
    '#region Module initialization' | Out-File -FilePath $moduleFile -Append
    Get-Content "$rootPath\Commands\ModuleInitialization.ps1" | Out-File -FilePath $moduleFile -Append
    '#endregion Module initialization' | Out-File -FilePath $moduleFile -Append
}