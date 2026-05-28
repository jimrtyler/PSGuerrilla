# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-GuerrillaGuiAsync {
    <#
    .SYNOPSIS
        Runs a scriptblock on a background runspace and posts its result back to the
        WPF UI thread via Dispatcher.
    .DESCRIPTION
        Used to drive long-running cmdlets (Invoke-Reconnaissance, Invoke-Campaign,
        etc.) without freezing the GUI. The Action runs in its own runspace with the
        PSGuerrilla module imported and any caller-supplied parameters available as
        $args. OnLog (optional) receives Verbose / Information streams; OnComplete
        gets the final return value; OnError gets the terminating error if any.

        Returns a handle the caller can hold to call Stop / IsCompleted on.

        NOTE: This is intentionally simple — no runspace pool, one runspace per call,
        and a 100ms polling loop on a DispatcherTimer to drain output streams. Good
        enough for the GUI's one-scan-at-a-time model; not appropriate for batch
        parallelism.
    .PARAMETER ModulePath
        Path to the .psd1 to Import-Module in the runspace. Required because the
        runspace starts clean (no inherited module state).
    .PARAMETER Action
        Scriptblock to execute. Use $using:variableName to capture from the caller's
        scope.
    .PARAMETER Dispatcher
        The WPF UI thread dispatcher (typically $window.Dispatcher).
    .PARAMETER OnLog
        Scriptblock invoked on the UI thread for each Verbose / Information line.
        Receives the message string as $args[0].
    .PARAMETER OnComplete
        Scriptblock invoked on the UI thread when Action returns. Receives the
        return value as $args[0].
    .PARAMETER OnError
        Scriptblock invoked on the UI thread when Action throws. Receives the
        ErrorRecord as $args[0].
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ModulePath,
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)]$Dispatcher,
        # Arguments splatted positionally onto the Action scriptblock. Use this
        # instead of closure capture for anything Action needs — closures don't
        # survive the runspace boundary cleanly.
        [object[]]$Arguments = @(),
        [scriptblock]$OnLog,
        [scriptblock]$OnComplete,
        [scriptblock]$OnError
    )

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $iss.ImportPSModule([string[]]@($ModulePath))

    $ps = [PowerShell]::Create($iss)
    [void]$ps.AddScript({
        param($Action, $ArgArray)
        $VerbosePreference = 'Continue'
        try {
            & $Action @ArgArray
        } catch {
            throw
        }
    })
    [void]$ps.AddArgument($Action)
    [void]$ps.AddArgument($Arguments)

    # Capture all output streams in one buffer so the polling timer can drain them.
    # BeginInvoke's two-arg overload needs typed PSDataCollection<T>s — passing $null
    # for the input throws "Cannot find an overload" because the generic type can't
    # be inferred. Hand it an empty (completed) input collection instead.
    $inputColl  = New-Object System.Management.Automation.PSDataCollection[PSObject]
    $inputColl.Complete()
    $output     = New-Object System.Management.Automation.PSDataCollection[PSObject]
    $handle     = $ps.BeginInvoke($inputColl, $output)

    $state = [PSCustomObject]@{
        PowerShell      = $ps
        Handle          = $handle
        Output          = $output
        LastVerboseIdx  = 0
        LastInfoIdx     = 0
        Timer           = $null
        Completed       = $false
    }

    # DispatcherTimer ticks on the UI thread — safe to mutate WPF controls from inside.
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    $timer.Add_Tick({
        # Drain any new verbose / information messages
        if ($OnLog) {
            try {
                $vstream = $state.PowerShell.Streams.Verbose
                while ($state.LastVerboseIdx -lt $vstream.Count) {
                    $msg = $vstream[$state.LastVerboseIdx].Message
                    & $OnLog $msg
                    $state.LastVerboseIdx++
                }
                $istream = $state.PowerShell.Streams.Information
                while ($state.LastInfoIdx -lt $istream.Count) {
                    $rec = $istream[$state.LastInfoIdx]
                    & $OnLog "$($rec.MessageData)"
                    $state.LastInfoIdx++
                }
            } catch {
                # Don't crash the GUI on a logging hiccup
            }
        }

        if ($state.Handle.IsCompleted -and -not $state.Completed) {
            $state.Completed = $true
            $state.Timer.Stop()
            try {
                $result = $state.PowerShell.EndInvoke($state.Handle)
                if ($state.PowerShell.HadErrors -and $OnError) {
                    $firstErr = $state.PowerShell.Streams.Error[0]
                    & $OnError $firstErr
                } elseif ($OnComplete) {
                    & $OnComplete $result
                }
            } catch {
                if ($OnError) { & $OnError $_ }
            } finally {
                $state.PowerShell.Dispose()
            }
        }
    })

    $state.Timer = $timer
    $timer.Start()

    return $state
}

function Stop-GuerrillaGuiAsync {
    <#
    .SYNOPSIS
        Cancels a running async job returned by Invoke-GuerrillaGuiAsync.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)

    if ($State.Completed) { return }
    try {
        if ($State.Timer) { $State.Timer.Stop() }
        if ($State.PowerShell) {
            $State.PowerShell.Stop()
            $State.PowerShell.Dispose()
        }
    } catch { }
    $State.Completed = $true
}
