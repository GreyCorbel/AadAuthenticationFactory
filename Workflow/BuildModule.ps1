using namespace System.IO
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

$moduleFile = [Path]::Combine($rootPath,'Module',$moduleName,"$moduleName`.psm1")
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