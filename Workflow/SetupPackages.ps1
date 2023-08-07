param
(
 [string]$Root
)

&"$env:nuget" restore "$Root\Workflow\packages.config" -packagesDirectory "$Root\packages" | Out-Null
"Updating packages in the module"
$packages = ([xml](get-content -path "$Root\Workflow\packages.config" -raw)).packages.package
$packages
$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client"}
"Processing: $($pkg.id)"
Copy-Item -Path "$Root\packages\$($pkg.id)`.$($pkg.version)\lib\net461\$($pkg.id)`.dll" -Destination "$Root\Module\AadAuthenticationFactory\shared\net461" -Force
Copy-Item -Path "$Root\packages\$($pkg.id)`.$($pkg.version)\lib\net6.0\$($pkg.id)`.dll" -Destination "$Root\Module\AadAuthenticationFactory\shared\net6.0" -Force

$pkg = $packages | where-object{$_.id -eq "Microsoft.IdentityModel.Abstractions"}
"Processing: $($pkg.id)"
Copy-Item -Path "$Root\packages\$($pkg.id)`.$($pkg.version)\lib\net461\$($pkg.id)`.dll" -Destination "$Root\Module\AadAuthenticationFactory\shared\net461" -Force
Copy-Item -Path "$Root\packages\$($pkg.id)`.$($pkg.version)\lib\net6.0\$($pkg.id)`.dll" -Destination "$Root\Module\AadAuthenticationFactory\shared\net6.0" -Force

$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client.NativeInterop"}
"Processing: $($pkg.id)"
Copy-Item -Path "$Root\packages\$($pkg.id)`.$($pkg.version)\lib\net461\$($pkg.id)`.dll" -Destination "$Root\Module\AadAuthenticationFactory\shared\net461" -Force
Copy-Item -Path "$Root\packages\$($pkg.id)`.$($pkg.version)\lib\netstandard2.0\$($pkg.id)`.dll" -Destination "$Root\Module\AadAuthenticationFactory\shared\netstandard2.0" -Force
#runtimes for native interop
Copy-Item -Path "$Root\packages\$($pkg.id)`.$($pkg.version)\runtimes" -Destination "$Root\Module\AadAuthenticationFactory" -recurse -force

$pkg = $packages | where-object{$_.id -eq "Microsoft.Identity.Client.Broker"}
"Processing: $($pkg.id)"
Copy-Item -Path "$Root\packages\$($pkg.id)`.$($pkg.version)\lib\net461\$($pkg.id)`.dll" -Destination "$Root\Module\AadAuthenticationFactory\shared\net461" -Force
Copy-Item -Path "$Root\packages\$($pkg.id)`.$($pkg.version)\lib\netstandard2.0\$($pkg.id)`.dll" -Destination "$Root\Module\AadAuthenticationFactory\shared\netstandard2.0" -Force
