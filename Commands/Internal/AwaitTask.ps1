function AwaitTask {
    param (
        [Parameter(ValueFromPipeline, Mandatory)]
        $task,
        [Parameter(Mandatory)]
        [System.Threading.CancellationTokenSource]$CancellationTokenSource
    )

    process {
        try {
            $errorHappened = $false
            while (-not $task.AsyncWaitHandle.WaitOne(200)) { }
            $rslt = $task.GetAwaiter().GetResult()
            $rslt
        }
        catch [System.OperationCanceledException]{
            $errorHappened = $true
            Write-Warning 'Authentication process has timed out'
        }
        catch {
            $errorHappened = $true
            throw $_.Exception
        }
        finally {
            if(-not $errorHappened -and $null -eq $rslt)
            {
                #we do not have result and did not went thru Catch block --> likely Ctrl+Break scenario
                #let`s cancel authentication in the factory
                $CancellationTokenSource.Cancel()
                Write-Verbose 'Authentication canceled by Ctrl+Break'
            }
        }
    }
}
