function Invoke-MacBroker {
    param(
        [Parameter(Mandatory)] $Factory,
        [Parameter(Mandatory)] [ValidateSet('accounts', 'token')] [string] $Operation,
        [string[]] $Scopes = @(),
        [string] $LoginHint,
        [string] $HomeAccountId,
        [bool] $ForceRefresh,
        [bool] $AllowInteractive,
        [string] $Claims,
        [string] $Authority,
        [string] $SshJwk,
        [string] $SshKeyId,
        [Parameter(Mandatory)] [System.Threading.CancellationTokenSource] $CancellationTokenSource
    )

    $configuration = $Factory.MacBrokerConfiguration
    $request = @{
        Version = 1
        Operation = $Operation
        ClientId = $Factory.AppConfig.ClientId
        Authority = if ([string]::IsNullOrEmpty($Authority)) { $configuration.Authority } else { $Authority }
        Scopes = @($Scopes)
        LoginHint = $LoginHint
        HomeAccountId = $HomeAccountId
        ForceRefresh = $ForceRefresh
        AllowInteractive = $AllowInteractive
        MultiCloud = $configuration.MultiCloud
        ClaimsSupport = $configuration.ClaimsSupport
        ExperimentalFeatures = $configuration.ExperimentalFeatures
        Claims = $Claims
        SshJwk = if ([string]::IsNullOrEmpty($SshJwk)) { $null } else { $SshJwk }
        SshKeyId = if ([string]::IsNullOrEmpty($SshKeyId)) { $null } else { $SshKeyId }
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $configuration.ExecutablePath
    $startInfo.ArgumentList.Add('--module')
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment['AAD_AUTHENTICATION_POWERSHELL_HOME'] = $PSHOME
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = $false
    try {
        $CancellationTokenSource.Token.ThrowIfCancellationRequested()
        $started = $process.Start()
        if (-not $started) {
            throw [System.IO.IOException]::new('The macOS broker helper did not start.')
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.WriteLine(($request | ConvertTo-Json -Depth 6 -Compress))
        $process.StandardInput.Close()
        while (-not $process.WaitForExit(100)) {
            $CancellationTokenSource.Token.ThrowIfCancellationRequested()
        }
        $output = $stdout.GetAwaiter().GetResult()
        $errorOutput = $stderr.GetAwaiter().GetResult()
        if ([string]::IsNullOrWhiteSpace($output)) {
            throw [System.IO.IOException]::new(
                "The macOS broker helper exited with code $($process.ExitCode) without a protocol response."
            )
        }
        $response = $output | ConvertFrom-Json -ErrorAction Stop
        if ($response.Version -ne 1) {
            throw [System.IO.InvalidDataException]::new('Unsupported macOS broker response version.')
        }
        if ($null -ne $response.Error) {
            $errorData = $response.Error
            if ($errorData.InteractionRequired) {
                $exception = [Microsoft.Identity.Client.MsalUiRequiredException]::new($errorData.Code, $errorData.Message)
                $exception.Claims = $errorData.Claims
            }
            else {
                $exception = [Microsoft.Identity.Client.MsalClientException]::new($errorData.Code, $errorData.Message)
            }
            if (-not [string]::IsNullOrEmpty($errorData.CorrelationId)) {
                $exception.CorrelationId = $errorData.CorrelationId
            }
            throw $exception
        }
        if ($process.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($errorOutput)) {
            throw [System.IO.IOException]::new(
                "The macOS broker helper failed (exit code $($process.ExitCode)). Its diagnostic output was not logged because it may contain authentication data."
            )
        }
        if ($Operation -eq 'accounts') {
            if ($null -eq $response.Accounts) {
                throw [System.IO.InvalidDataException]::new('The macOS broker returned no account collection.')
            }
            foreach ($account in $response.Accounts) {
                ConvertFrom-MacBrokerAccount -Account $account
            }
        }
        else {
            ConvertFrom-MacBrokerResult -Result $response.Result
        }
    }
    finally {
        if ($started -and -not $process.HasExited) {
            $process.Kill($true)
            $process.WaitForExit()
        }
        $process.Dispose()
    }
}
