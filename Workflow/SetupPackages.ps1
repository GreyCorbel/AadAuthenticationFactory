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
if(-not (Test-Path -Path ([Path]::Combine($sharedPath, 'net461')))) { New-Item -ItemType Directory -Path ([Path]::Combine($sharedPath, 'net461')) | Out-Null}
if(-not (Test-Path -Path ([Path]::Combine($sharedPath, 'net462')))) { New-Item -ItemType Directory -Path ([Path]::Combine($sharedPath, 'net462')) | Out-Null}
if(-not (Test-Path -Path ([Path]::Combine($sharedPath, 'netstandard2.0')))) { New-Item -ItemType Directory -Path ([Path]::Combine($sharedPath, 'netstandard2.0')) | Out-Null}
if(-not (Test-Path -Path ([Path]::Combine($sharedPath, 'net6.0')))) { New-Item -ItemType Directory -Path ([Path]::Combine($sharedPath, 'net6.0')) | Out-Null}
if(-not (Test-Path -Path ([Path]::Combine($sharedPath, 'net8.0')))) { New-Item -ItemType Directory -Path ([Path]::Combine($sharedPath, 'net8.0')) | Out-Null}
if(-not (Test-Path -Path $runtimesPath)) { New-Item -ItemType Directory -Path $runtimesPath | Out-Null}
"==============================="
$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client"}
"Processing: $($pkg.id)"
$packageFolder = [Path]::Combine($packagesDir, "$($pkg.id)`.$($pkg.version)")
Copy-Item -Path ([Path]::Combine($packageFolder,'lib','net462',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'net462')) -Force
Copy-Item -Path ([Path]::Combine($packageFolder,'lib','net8.0',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'net8.0')) -Force

#$pkg = $packages | where-object{$_.id -eq "Microsoft.IdentityModel.Abstractions"}
foreach($pkg in $packages | where-object{$_.id -eq "Microsoft.IdentityModel.Abstractions"})
{
    "Processing: $($pkg.id) - $($pkg.version)"
    $packageFolder = [Path]::Combine($packagesDir, "$($pkg.id)`.$($pkg.version)")
    switch($pkg.version)
    {
        "6.35.0" {
            #.NET Framework requires exact version
            "   .NET Framework"
            Copy-Item -Path ([Path]::Combine($packageFolder,'lib','net462',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'net462')) -Force
            break;
        }
        default {
            #.NET Core can use any version
            "   .NET Core"
            Copy-Item -Path ([Path]::Combine($packageFolder,'lib','net6.0',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'net6.0')) -Force
            break;
        }
    }
}

$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client.NativeInterop"}
foreach($pkg in $packages | where-object{$_.id -eq "Microsoft.Identity.Client.NativeInterop"})
{
    "Processing: $($pkg.id) - $($pkg.version)"
    $packageFolder = [Path]::Combine($packagesDir, "$($pkg.id)`.$($pkg.version)")
    switch($pkg.version)
    {
        "0.16.2" {
            #.NET Framework requires exact version
            "   .NET Framework"
            Copy-Item -Path ([Path]::Combine($packageFolder,'lib','net461',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'net461')) -Force
            break;
        }
        default {
            #.NET Core can use any version
            "   .NET Core"
            Copy-Item -Path ([Path]::Combine($packageFolder,'lib','netstandard2.0',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'netstandard2.0')) -Force
            #runtimes for native interop taken from higher version
            Copy-Item -Path ([Path]::Combine($packageFolder,'runtimes')) -Destination $modulePath -Recurse -Force
            break;
        }
    }
}

$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client.Broker"}
"Processing: $($pkg.id)"
$packageFolder = [Path]::Combine($packagesDir, "$($pkg.id)`.$($pkg.version)")
Copy-Item -Path ([Path]::Combine($packageFolder,'lib','netstandard2.0',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'netstandard2.0')) -Force
