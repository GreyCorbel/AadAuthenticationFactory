#
# Module manifest for module 'AadAuthenticationFactory'
#
# Generated by: Jiri Formacek, GreyCorbel Solutions
#
# Generated on: 11.01.2022
#

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\AadAuthenticationFactory.psm1'

# Version number of this module.
ModuleVersion = '3.0.4'

# Supported PSEditions
CompatiblePSEditions = @('Core', 'Desktop')

# ID used to uniquely identify this module
GUID = '9d860f96-4bde-41d3-890b-1a3f51c34d68'

# Author of this module
Author = 'Jiri Formacek'

# Company or vendor of this module
CompanyName = 'GreyCorbel Solutions'

# Copyright statement for this module
Copyright = '(c) 2022 - 2023, Jiri Formacek, GreyCorbel Solutions. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Provides AAD authentication factory for easy Public Client, Confidential Client flow and Managed Identity authentication with AAD in PowerShell'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the Windows PowerShell host required by this module
PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @('AadAuthenticationFactory.format.ps1xml')

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @('New-AadAuthenticationFactory', 'Get-AadToken', 'Get-AadAccount', 'Test-AadToken', 'Get-AadDefaultClientId','Get-AadAuthenticationFactory')

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
ModuleList = @()

# List of all files packaged with this module
FileList =     '.\Shared\net6.0\Microsoft.Identity.Client.dll', 
                '.\Shared\net6.0\Microsoft.IdentityModel.Abstractions.dll',
                '.\Shared\net461\Microsoft.Identity.Client.dll',
                '.\Shared\net461\Microsoft.IdentityModel.Abstractions.dll',
                '.\Shared\net461\Microsoft.Identity.Client.Broker.dll',
                '.\Shared\net461\Microsoft.Identity.Client.NativeInterop.dll',
                '.\Shared\netstandard2.0\Microsoft.Identity.Client.Broker.dll',
                '.\Shared\netstandard2.0\Microsoft.Identity.Client.NativeInterop.dll', 
                '.\Runtimes\win-arm64\native\msalruntime_arm64.dll',
                '.\Runtimes\win-x86\native\msalruntime_x86.dll'
# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('AAD','PublicClient','ConfidentialClient','MamagedIdentity','WIA','ROPC','PSEdition_Core','PSEdition_Desktop')

        # A URL to the license for this module.
        LicenseUri = 'https://raw.githubusercontent.com/GreyCorbel/AadAuthenticationFactory/main/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/GreyCorbel/AadAuthenticationFactory'

        # Prerelease string of this module
        #Prerelease = 'beta4'

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        RequireLicenseAcceptance = $false

        # A URL to an icon representing this module.
        IconUri = 'https://raw.githubusercontent.com/GreyCorbel/AadAuthenticationFactory/main/Icons/module.png'

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable
    Configuration = @{
        DefaultClientId = '1950a258-227b-4e31-a9cf-717495945fc2'
    }
    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
    }
}
