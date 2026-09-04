param(
    [string]$RootPath = (Split-Path -Parent $PSScriptRoot),
    [string]$ModuleName = 'AadAuthenticationFactory',
    [string[]]$Tag,
    [string[]]$ExcludeTag,
    [switch]$RequireIntegrationConfiguration,
    [switch]$CI
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleManifestPath = [System.IO.Path]::Combine($RootPath, 'Module', $ModuleName, "$ModuleName.psd1")
$testsPath = Join-Path $RootPath 'Tests'

if (-not (Test-Path $moduleManifestPath)) {
    throw "Module manifest not found at $moduleManifestPath"
}

if (-not (Test-Path $testsPath)) {
    throw "Tests folder not found at $testsPath"
}

if ($RequireIntegrationConfiguration.IsPresent) {
    $requiredVariables = @(
        'AAD_TEST_TENANT_ID',
        'AAD_TEST_SCOPE',
        'AAD_TEST_CLIENT_ID',
        'AAD_TEST_CLIENT_SECRET',
        'AAD_TEST_EXPECTED_AUD',
        'AAD_TEST_OIDC_AUDIENCE',
        'AAD_TEST_OIDC_SUBJECT',
        'ACTIONS_ID_TOKEN_REQUEST_URL',
        'ACTIONS_ID_TOKEN_REQUEST_TOKEN'
    )
    $missingVariables = $requiredVariables.Where{
        [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_))
    }

    if ($missingVariables.Count -gt 0) {
        throw "Required integration environment variables are missing: $($missingVariables -join ', ')."
    }
}

$minimumPesterVersion = [Version]'5.5.0'
$pester = Get-Module -ListAvailable -Name Pester |
    Sort-Object Version -Descending |
    Select-Object -First 1

if ($null -eq $pester -or $pester.Version -lt $minimumPesterVersion) {
    Write-Host "Installing Pester $minimumPesterVersion or newer"
    Install-Module -Name Pester -Scope CurrentUser -Force -MinimumVersion $minimumPesterVersion -SkipPublisherCheck
}

Import-Module Pester -MinimumVersion $minimumPesterVersion -Force -ErrorAction Stop

$configuration = [PesterConfiguration]::Default
$configuration.Run.Path = $testsPath
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = 'Detailed'

if (@($Tag).Count -gt 0) {
    $configuration.Filter.Tag = $Tag
}

if (@($ExcludeTag).Count -gt 0) {
    $configuration.Filter.ExcludeTag = $ExcludeTag
}

if ($CI.IsPresent) {
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputFormat = 'NUnitXml'
    $configuration.TestResult.OutputPath = Join-Path $RootPath 'TestResults.xml'
}

$result = Invoke-Pester -Configuration $configuration

if ($result.Result -ne 'Passed') {
    throw "Pester run finished with result '$($result.Result)'."
}

if ($result.FailedCount -gt 0) {
    throw "Pester reported $($result.FailedCount) failed test(s)."
}

Write-Host "Pester completed successfully. Passed: $($result.PassedCount), Skipped: $($result.SkippedCount), Failed: $($result.FailedCount)."
