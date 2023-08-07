param
(
 [string]$RootPath,
 [string]$nugetPath
)

&"$nugetPath" restore "$RootPath\Workflow\packages.config" -packagesDirectory "$RootPath\packages" | Out-Null
"Updating packages in the module"
$packages = ([xml](get-content -path "$RootPath\Workflow\packages.config" -raw)).packages.package
$packages
if(-not (Test-Path -Path "$RootPath\Module\AadAuthenticationFactory\Shared")) { New-Item -ItemType Directory -Path "$RootPath\Module\AadAuthenticationFactory\Shared" | Out-Null}
if(-not (Test-Path -Path "$RootPath\Module\AadAuthenticationFactory\shared\net461")) { New-Item -ItemType Directory -Path "$RootPath\Module\AadAuthenticationFactory\shared\net461" | Out-Null}
if(-not (Test-Path -Path "$RootPath\Module\AadAuthenticationFactory\shared\netstandard2.0")) { New-Item -ItemType Directory -Path "$RootPath\Module\AadAuthenticationFactory\shared\netstandard2.0" | Out-Null}
if(-not (Test-Path -Path "$RootPath\Module\AadAuthenticationFactory\shared\net6.0")) { New-Item -ItemType Directory -Path "$RootPath\Module\AadAuthenticationFactory\shared\net6.0" | Out-Null}
if(-not (Test-Path -Path "$RootPath\Module\AadAuthenticationFactory\Runtimes")) { New-Item -ItemType Directory -Path "$RootPath\Module\AadAuthenticationFactory\Runtimes" | Out-Null}

$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client"}
"Processing: $($pkg.id)"
Copy-Item -Path "$RootPath\packages\$($pkg.id)`.$($pkg.version)\lib\net461\$($pkg.id)`.dll" -Destination "$RootPath\Module\AadAuthenticationFactory\shared\net461" -Force
Copy-Item -Path "$RootPath\packages\$($pkg.id)`.$($pkg.version)\lib\net6.0\$($pkg.id)`.dll" -Destination "$RootPath\Module\AadAuthenticationFactory\shared\net6.0" -Force

$pkg = $packages | where-object{$_.id -eq "Microsoft.IdentityModel.Abstractions"}
"Processing: $($pkg.id)"
Copy-Item -Path "$RootPath\packages\$($pkg.id)`.$($pkg.version)\lib\net461\$($pkg.id)`.dll" -Destination "$RootPath\Module\AadAuthenticationFactory\shared\net461" -Force
Copy-Item -Path "$RootPath\packages\$($pkg.id)`.$($pkg.version)\lib\net6.0\$($pkg.id)`.dll" -Destination "$RootPath\Module\AadAuthenticationFactory\shared\net6.0" -Force

$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client.NativeInterop"}
"Processing: $($pkg.id)"
Copy-Item -Path "$RootPath\packages\$($pkg.id)`.$($pkg.version)\lib\net461\$($pkg.id)`.dll" -Destination "$RootPath\Module\AadAuthenticationFactory\shared\net461" -Force
Copy-Item -Path "$RootPath\packages\$($pkg.id)`.$($pkg.version)\lib\netstandard2.0\$($pkg.id)`.dll" -Destination "$RootPath\Module\AadAuthenticationFactory\shared\netstandard2.0" -Force
#runtimes for native interop
Copy-Item -Path "$RootPath\packages\$($pkg.id)`.$($pkg.version)\runtimes" -Destination "$RootPath\Module\AadAuthenticationFactory" -recurse -force

$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client.Broker"}
"Processing: $($pkg.id)"
Copy-Item -Path "$RootPath\packages\$($pkg.id)`.$($pkg.version)\lib\net461\$($pkg.id)`.dll" -Destination "$RootPath\Module\AadAuthenticationFactory\shared\net461" -Force
Copy-Item -Path "$RootPath\packages\$($pkg.id)`.$($pkg.version)\lib\netstandard2.0\$($pkg.id)`.dll" -Destination "$RootPath\Module\AadAuthenticationFactory\shared\netstandard2.0" -Force
