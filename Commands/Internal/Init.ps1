function Init {
    param()

    process {
        $moduleRoot = $PSScriptRoot

        # Base referenced assemblies used for compiling helper .cs files
        $referencedAssemblies = @('System.Net.Http')

        # Some hosts require TLS 1.2; keep your existing behavior
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        } catch {
            # On newer .NET this may be ignored; safe to swallow
        }

        # Initialize cache for factories
        if ($null -eq $script:AadAuthenticationFactories -or -not ($script:AadAuthenticationFactories -is [hashtable])) {
            $script:AadAuthenticationFactories = @{}
        }

        # Determine whether MSAL is already loaded
        $msalAlreadyLoaded = $false
        $msalAssemblyPath  = $null
        $msalLoadedVersion = $null

        try {
            $existingType = [Microsoft.Identity.Client.PublicClientApplication]
            $msalAlreadyLoaded = $true
            $msalAssemblyPath  = $existingType.Assembly.Location
            $msalLoadedVersion = $existingType.Assembly.GetName().Version
            Write-Information "MSAL already loaded from: $msalAssemblyPath (v$msalLoadedVersion)"

            # --- Warnings ---
            # 1) Always warn that MSAL is already loaded (but keep it informative)
            Write-Information "MSAL already loaded in session: $msalAssemblyPath (v$msalLoadedVersion). AadAuthenticationFactory will reuse it."

            # 2) Warn if versions differ (this is the dangerous case)
            if ($moduleMsalVersion -and ($moduleMsalVersion -ne $msalLoadedVersion)) {
                Write-Warning "AadAuthenticationFactory ships MSAL v{0} at '{1}', but the session already loaded MSAL v{2} from '{3}'. PowerShell loads assemblies into a shared context, so version conflicts are common. If authentication fails, start a new session and import AadAuthenticationFactory first (before Az/Graph/EXO modules)." -f $moduleMsalVersion, $moduleMsalPath, $msalLoadedVersion, $msalAssemblyPath
            }

            # 3) If versions match but paths differ, warn at Verbose (or Warning if you prefer)
            elseif ($moduleMsalVersion -and ($moduleMsalPath -and ($moduleMsalPath -ne $msalAssemblyPath))) {
                Write-Information ("MSAL version matches (v{0}) but was loaded from a different path. `nModule path: '{1}'. ``nLoaded path: '{2}'." -f $msalLoadedVersion, $moduleMsalPath, $msalAssemblyPath)
            }
        } catch {
            # Not loaded yet
        }

        # --------------------------------------------------------
        # Select module-shipped MSAL directories
        # --------------------------------------------------------
        $sharedDir = $null
        $sharedMsalPath = $null

        if ($PSEdition -eq 'Core') {
            # PS7.3+: prefer netstandard2.0
            $sharedDir = Resolve-MsalSharedDirForCore -ModuleRoot $moduleRoot
            
            $brokerDir = [Path]::Combine($moduleRoot, 'shared', 'netstandard2.0')
            # Extra references commonly needed in PS Core for compiling helpers
            $referencedAssemblies += 'System.Net.Primitives'
            $referencedAssemblies += 'System.Net.WebProxy'
            $referencedAssemblies += 'System.Console'
            $referencedAssemblies += 'netstandard'
        }
        else {
            # Windows PowerShell 5.1: use net462
            $sharedDir = [Path]::Combine($moduleRoot, 'shared', 'net462')
            $brokerDir = [Path]::Combine($moduleRoot, 'shared', 'net462')
        }

        $sharedMsalPath = [Path]::Combine($sharedDir, 'Microsoft.Identity.Client.dll')
        $sharedMsalVersion = if (Test-Path $sharedMsalPath) { Get-AssemblyVersionFromPath -Path $sharedMsalPath } else { $null }

        # Broker bits are typically netstandard2.0
        $brokerDll = [Path]::Combine($brokerDir, 'Microsoft.Identity.Client.Broker.dll')
        $brokerVersion = if (Test-Path $brokerDll) { Get-AssemblyVersionFromPath -Path $brokerDll } else { $null }

        # --------------------------------------------------------
        # Load MSAL managed assemblies if not already loaded
        # --------------------------------------------------------
        if (-not $msalAlreadyLoaded) {
            if (-not (Test-Path $sharedMsalPath)) {
                throw "MSAL not found at $sharedMsalPath. Populate Shared folder appropriately."
            }

            Add-Type -Path $sharedMsalPath -ErrorAction Stop | Out-Null

            $msalAssemblyPath  = $sharedMsalPath
            $msalLoadedVersion = ([Assembly]::LoadFrom($sharedMsalPath)).GetName().Version
            Write-Information "Loaded MSAL from module: $msalAssemblyPath (v$msalLoadedVersion)"
        }
        else {
            # MSAL was already loaded; use it for helper compilation reference
            # Also, if your shipped broker version doesn't match MSAL, we may skip loading broker
            if ($sharedMsalVersion -and $msalLoadedVersion -and ($sharedMsalVersion -ne $msalLoadedVersion)) {
                Write-Information "Module-shipped MSAL version is $sharedMsalVersion but session already has $msalLoadedVersion. Will not attempt to load another MSAL copy."
            }
        }

        # Ensure helper compilation references MSAL assembly currently in use
        if ($msalAssemblyPath) {
            $referencedAssemblies += $msalAssemblyPath
        }

        # Desktop: ensure System.Net.Http is available
        if ($PSEdition -eq 'Desktop') {
            Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue | Out-Null
        }

        # --------------------------------------------------------
        # Load Broker (if not loaded) + native runtime (cross-platform)
        # --------------------------------------------------------
        $brokerTypePresent = ($null -ne ('Microsoft.Identity.Client.Broker.BrokerExtension' -as [type]))
        if (-not $brokerTypePresent) {

            # If MSAL already loaded from elsewhere, ensure broker version matches MSAL version before loading
            if ($msalLoadedVersion -and $brokerVersion -and ($msalLoadedVersion -ne $brokerVersion)) {
                Write-Warning ("MSAL version in session is {0} but module broker is {1}. Skipping broker load to avoid version conflicts. Broker-based auth may be unavailable; browser/device-code fallback still works." -f $msalLoadedVersion, $brokerVersion)
            }
            else {
                # Load broker extension assembly
                if (-not (Test-Path $brokerDll)) {
                    Write-Warning "Broker DLL not found at $brokerDll. Broker-based auth will be unavailable."
                }
                else {
                    Add-Type -Path $brokerDll -ErrorAction Stop | Out-Null

                    # Load native runtime for broker (Windows/Linux/macOS)
                    Import-MsalNativeRuntime -ModuleRoot $moduleRoot
                }
            }
        }

        # --------------------------------------------------------
        # Compile helper .cs files (your existing pattern)
        # --------------------------------------------------------
        $helpers = @('GcMsalHttpClientFactory', 'DeviceCodeHandler', 'ParentWindowHelper')

        foreach ($helper in $helpers) {
            if ($null -eq ($helper -as [type])) {
                
                $helperPath = [Path]::Combine($moduleRoot, 'Helpers', "$helper.cs")
                if (-not (Test-Path $helperPath)) {
                    Write-Warning "Helper $helper not found at $helperPath - skipping."
                    continue
                }

                Write-Information "Compiling helper $helper"
                $helperDefinition = Get-Content $helperPath -Raw

                Add-Type -TypeDefinition $helperDefinition `
                    -ReferencedAssemblies $referencedAssemblies `
                    -WarningAction SilentlyContinue -IgnoreWarnings | Out-Null
            }
        }

        Write-Information "Init completed. MSAL v$msalLoadedVersion; Broker loaded: $(-not (-not ('Microsoft.Identity.Client.Broker.BrokerExtension' -as [type])))"
    }
}
