using namespace System.IO

param
(
 [string]$RootPath,
 [string]$nugetPath
)

$packagesDir = [Path]::Combine($RootPath,'packages')
$modulePath = [Path]::Combine($RootPath,'Module','AadAuthenticationFactory')
$sharedPath = [Path]::Combine($modulePath,'Shared')
$runtimesPath = [Path]::Combine($modulePath,'Runtimes')

&"$nugetPath" restore ([Path]::Combine($RootPath,'Workflow','packages.config')) -packagesDirectory $packagesDir | Out-Null
"Updating packages in the module"
$packages = ([xml](get-content -path ([Path]::Combine($RootPath,'Workflow','packages.config')) -raw)).packages.package
$packages
if(-not (Test-Path -Path $sharedPath)) { New-Item -ItemType Directory -Path $sharedPath | Out-Null}
if(-not (Test-Path -Path ([Path]::Combine($sharedPath, 'net462')))) { New-Item -ItemType Directory -Path ([Path]::Combine($sharedPath, 'net462')) | Out-Null}
if(-not (Test-Path -Path ([Path]::Combine($sharedPath, 'netstandard2.0')))) { New-Item -ItemType Directory -Path ([Path]::Combine($sharedPath, 'netstandard2.0')) | Out-Null}
if(-not (Test-Path -Path ([Path]::Combine($sharedPath, 'net6.0')))) { New-Item -ItemType Directory -Path ([Path]::Combine($sharedPath, 'net6.0')) | Out-Null}
if(-not (Test-Path -Path $runtimesPath)) { New-Item -ItemType Directory -Path $runtimesPath | Out-Null}

$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client"}
"Processing: $($pkg.id)"
$packageFolder = [Path]::Combine($packagesDir, "$($pkg.id)`.$($pkg.version)")
Copy-Item -Path ([Path]::Combine($packageFolder,'lib','net462',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'net462')) -Force
Copy-Item -Path ([Path]::Combine($packageFolder,'lib','net6.0',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'net6.0')) -Force

$pkg = $packages | where-object{$_.id -eq "Microsoft.IdentityModel.Abstractions"}
"Processing: $($pkg.id)"
$packageFolder = [Path]::Combine($packagesDir, "$($pkg.id)`.$($pkg.version)")
Copy-Item -Path ([Path]::Combine($packageFolder,'lib','net462',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'net462')) -Force
Copy-Item -Path ([Path]::Combine($packageFolder,'lib','net6.0',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'net6.0')) -Force

$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client.NativeInterop"}
"Processing: $($pkg.id)"
$packageFolder = [Path]::Combine($packagesDir, "$($pkg.id)`.$($pkg.version)")
Copy-Item -Path ([Path]::Combine($packageFolder,'lib','netstandard2.0',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'netstandard2.0')) -Force
#runtimes for native interop
Copy-Item -Path ([Path]::Combine($packageFolder,'runtimes')) -Destination $modulePath -Recurse -Force

$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client.Broker"}
"Processing: $($pkg.id)"
$packageFolder = [Path]::Combine($packagesDir, "$($pkg.id)`.$($pkg.version)")
Copy-Item -Path ([Path]::Combine($packageFolder,'lib','netstandard2.0',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'netstandard2.0')) -Force
