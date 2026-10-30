Set-StrictMode -Version Latest

Describe 'Mac broker probe diagnostics' -Skip:(
    -not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::OSX
    )
) {
    BeforeAll {
        $architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()
        $script:probePath = Join-Path $PSScriptRoot "../Module/AadAuthenticationFactory/bin/osx-$architecture/AadAuthenticationFactory.MacBroker"
        if (-not (Test-Path -LiteralPath $script:probePath)) {
            throw 'Build the macOS helpers using Workflow/BuildMacBroker.ps1 before running tests.'
        }

        function Invoke-Probe {
            param([string[]]$Arguments, [string]$InputJson)

            $startInfo = [System.Diagnostics.ProcessStartInfo]::new($script:probePath)
            $startInfo.UseShellExecute = $false
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $startInfo.RedirectStandardInput = $true
            $startInfo.Environment['AAD_AUTHENTICATION_POWERSHELL_HOME'] = $PSHOME
            foreach ($argument in $Arguments) {
                $startInfo.ArgumentList.Add($argument)
            }
            $process = [System.Diagnostics.Process]::Start($startInfo)
            try {
                if (-not [string]::IsNullOrEmpty($InputJson)) {
                    $process.StandardInput.WriteLine($InputJson)
                }
                $process.StandardInput.Close()
                $stdout = $process.StandardOutput.ReadToEndAsync()
                $stderr = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit(30000)) {
                    $process.Kill()
                    $process.WaitForExit()
                    throw 'Probe did not exit within 30 seconds.'
                }
                [pscustomobject]@{
                    ExitCode = $process.ExitCode
                    Output = $stdout.GetAwaiter().GetResult()
                    Error = $stderr.GetAwaiter().GetResult()
                }

            }
            finally {
                $process.Dispose()
            }
        }
    }

    It 'executes real native imports on the process main thread' {
        $result = Invoke-Probe -Arguments @('--probe')
        $result.ExitCode | Should -Be 0
        $diagnostic = $result.Error | ConvertFrom-Json
        $diagnostic.nativeMainThread | Should -BeTrue
        $diagnostic.managedThreadId | Should -Be 1
        $diagnostic.schedulerRunning | Should -BeTrue
        $diagnostic.runtimeDirectory | Should -Be $PSHOME
        $moduleRoot = (Resolve-Path (Join-Path $PSScriptRoot '../Module/AadAuthenticationFactory')).Path
        $diagnostic.msalAssembly | Should -Be (Join-Path $moduleRoot 'shared/netstandard2.0/Microsoft.Identity.Client.dll')
        $diagnostic.nativeRuntime | Should -BeLike "$moduleRoot/runtimes/osx-*/native/msalruntime*.dylib"
        ($result.Output | ConvertFrom-Json).nativeImports | Should -Be 'ok'
    }

    It 'packages only one managed assembly and two native launchers' {
        $binPath = Join-Path $PSScriptRoot '../Module/AadAuthenticationFactory/bin'
        $files = @(Get-ChildItem -LiteralPath $binPath -File -Recurse)
        $files.Count | Should -Be 3
        @(Get-ChildItem -LiteralPath $binPath -Filter '*.dll' -File -Recurse).Count | Should -Be 1
        ($files | Measure-Object -Property Length -Sum).Sum | Should -BeLessThan 1048576
    }

    It 'rejects invalid arguments before contacting the broker: <Label>' -ForEach @(
        @{ Label = 'missing mode'; Arguments = @() }
        @{ Label = 'unknown mode'; Arguments = @('--unknown') }
        @{ Label = 'missing silent options'; Arguments = @('--silent') }
        @{ Label = 'missing interactive scopes'; Arguments = @('--interactive', '--client-id', '04b07795-8ddb-461a-bbee-02f9e1bf7b46', '--tenant', 'organizations') }
        @{ Label = 'invalid client ID'; Arguments = @('--accounts', '--client-id', 'invalid', '--tenant', 'organizations') }
        @{ Label = 'duplicate option'; Arguments = @('--accounts', '--client-id', '04b07795-8ddb-461a-bbee-02f9e1bf7b46', '--tenant', 'organizations', '--tenant', 'common') }
        @{ Label = 'missing option value'; Arguments = @('--accounts', '--client-id', '--tenant', 'organizations') }
        @{ Label = 'conflicting selectors'; Arguments = @('--silent', '--client-id', '04b07795-8ddb-461a-bbee-02f9e1bf7b46', '--tenant', 'organizations', '--scope', 'test', '--login-hint', 'user@example.com', '--home-account-id', 'account') }
        @{ Label = 'unexpected probe options'; Arguments = @('--probe', '--tenant', 'organizations') }
    ) {
        $result = Invoke-Probe -Arguments $Arguments
        $result.ExitCode | Should -Be 1
        $result.Output | Should -BeNullOrEmpty
        $errorResult = $result.Error | ConvertFrom-Json
        $errorResult.error | Should -Be 'System.ArgumentException'
        $errorResult.interactionRequired | Should -BeFalse
    }

    It 'rejects invalid module protocol requests before broker initialization: <Label>' -ForEach @(
        @{ Label = 'unsupported version'; Request = @{ Version = 2; Operation = 'accounts' } }
        @{ Label = 'unknown operation'; Request = @{ Version = 1; Operation = 'unknown' } }
        @{ Label = 'invalid authority'; Request = @{ Version = 1; Operation = 'accounts'; ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'; Authority = 'http://example.com' } }
        @{ Label = 'empty scopes'; Request = @{ Version = 1; Operation = 'token'; ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'; Authority = 'https://login.microsoftonline.com/organizations' } }
        @{ Label = 'incomplete SSH parameters'; Request = @{ Version = 1; Operation = 'token'; ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'; Authority = 'https://login.microsoftonline.com/organizations'; Scopes = @('test'); SshJwk = '{}' } }
    ) {
        $result = Invoke-Probe -Arguments @('--module') -InputJson ($Request | ConvertTo-Json -Compress)
        $result.ExitCode | Should -Be 1
        $result.Error | Should -BeNullOrEmpty
        $response = $result.Output | ConvertFrom-Json
        $response.Version | Should -Be 1
        $response.Error.Code | Should -Be 'ArgumentException'
        $response.Result | Should -BeNullOrEmpty
    }
}
