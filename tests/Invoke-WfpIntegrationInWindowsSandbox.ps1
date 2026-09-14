# Copyright (C) 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/WFP-tool.git

# Uses the Windows Sandbox cli to run elevated tests without messing up the dev system.
#
# Flow:
# 1. Refuse to use an existing sandbox, then start a fresh unconfigured one.
# 2. Share a unique writable host directory with the guest and copy the test binary there.
# 3. Run the elevated lifecycle test as SYSTEM, redirecting guest output to result.txt.
# 4. Require both the command success code and its success marker, then stop the guest.

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [ValidateRange(30, 600)]
    [int]$StartupTimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'

function Invoke-WsbRaw {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$CaptureFailure
    )

    $output = & wsb.exe --raw @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not $CaptureFailure) {
        throw "wsb $($Arguments -join ' ') failed with exit code $exitCode.`n$output"
    }
    return [PSCustomObject]@{
        Output = $output
        ExitCode = $exitCode
    }
}

function Find-WsbId {
    param([Parameter(Mandatory)]$Value)

    if ($Value -is [string]) {
        return $null
    }
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.Name -ieq 'id' -and $property.Value -is [string] -and $property.Value) {
            return $property.Value
        }
        $nested = Find-WsbId -Value $property.Value
        if ($nested) {
            return $nested
        }
    }
    return $null
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$buildScript = Join-Path $repositoryRoot 'build.ps1'
$powerShell = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $powerShell) {
    $powerShell = (Get-Command powershell -ErrorAction Stop).Source
}
& $powerShell -NoProfile -File $buildScript -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$integrationExecutable = Join-Path $repositoryRoot 'out\build\wfp-tool-integration-tests.exe'
if (-not (Test-Path -LiteralPath $integrationExecutable -PathType Leaf)) {
    throw "The integration executable was not built: $integrationExecutable"
}
$trafficIntegrationExecutable = Join-Path $repositoryRoot 'out\build\wfp-tool-traffic-integration-tests.exe'
if (-not (Test-Path -LiteralPath $trafficIntegrationExecutable -PathType Leaf)) {
    throw "The traffic integration executable was not built: $trafficIntegrationExecutable"
}

Write-Host ""
Write-Host "Starting Windows Sandbox for elevated tests..."

$running = (Invoke-WsbRaw -Arguments @('list')).Output | ConvertFrom-Json
if (@($running.WindowsSandboxEnvironments).Count -ne 0) {
    throw 'A Windows Sandbox is already running; refuse to attach the WFP integration test.'
}

$runRoot = Join-Path $repositoryRoot 'out\windows-sandbox-integration'
$runDirectory = Join-Path $runRoot ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
Copy-Item -LiteralPath $integrationExecutable -Destination $runDirectory
Copy-Item -LiteralPath $trafficIntegrationExecutable -Destination $runDirectory
$guestDirectory = 'C:\WfpIntegration'
$testAccounts = @('WfpSandboxTestA', 'WfpSandboxTestB')
$resultPath = Join-Path $runDirectory 'result.txt'
$trafficResultPath = Join-Path $runDirectory 'traffic-result.txt'

$sandboxId = $null
# Measure the complete isolated run, including guest startup and teardown, but
# not the host build performed above.
$sandboxTiming = [PSCustomObject]@{
    Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    LastSeconds = 0.0
}

function Write-SandboxTiming {
    param([Parameter(Mandatory)][string]$Phase)

    $totalSeconds = $sandboxTiming.Stopwatch.Elapsed.TotalSeconds
    $phaseSeconds = $totalSeconds - $sandboxTiming.LastSeconds
    $sandboxTiming.LastSeconds = $totalSeconds
    Write-Host ([string]::Format(
            [Globalization.CultureInfo]::InvariantCulture,
            '{0}: {1:F2} secs (total {2:F2} secs)',
            $Phase, $phaseSeconds, $totalSeconds))
}

try {
    $started = (Invoke-WsbRaw -Arguments @('start')).Output | ConvertFrom-Json
    $sandboxId = Find-WsbId -Value $started
    if (-not $sandboxId) {
        throw "wsb start did not return a sandbox id: $($started | ConvertTo-Json -Depth 8)"
    }
    Write-SandboxTiming 'Sandbox start'

    $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
    $lastShareError = $null
    do {
        try {
            Invoke-WsbRaw -Arguments @('share', '--id', $sandboxId, '-f', $runDirectory,
                '-s', $guestDirectory, '-w') | Out-Null
            $lastShareError = $null
            break
        }
        catch {
            $lastShareError = $_
            Start-Sleep -Seconds 2
        }
    } while ((Get-Date) -lt $deadline)
    if ($lastShareError) {
        throw "Windows Sandbox did not accept the shared test directory.`n$lastShareError"
    }
    Write-SandboxTiming 'Sandbox ready and shared folder mounted'

    $provisionCommand = 'cmd.exe /d /c "(net user {0} "" /add && net user {1} "" /add)"' -f $testAccounts[0], $testAccounts[1]
    $provision = Invoke-WsbRaw -Arguments @(
        'exec', '--id', $sandboxId, '-d', $guestDirectory, '-r', 'system', '-c', $provisionCommand) -CaptureFailure
    Write-SandboxTiming 'Guest test-account provisioning'
    if ($provision.ExitCode -ne 0) {
        throw "The sandbox test-account provisioning failed with exit code $($provision.ExitCode).`n$($provision.Output)"
    }

    $testCommand = 'cmd.exe /d /c "wfp-tool-integration-tests.exe {0} {1} > {2}\result.txt 2>&1"' -f $testAccounts[0], $testAccounts[1], $guestDirectory
    $execution = Invoke-WsbRaw -Arguments @(
        'exec', '--id', $sandboxId, '-d', $guestDirectory, '-r', 'system', '-c', $testCommand) -CaptureFailure
    Write-SandboxTiming 'Guest integration tests'

    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        throw "The sandbox test did not create $resultPath.`n$($execution.Output)"
    }
    $result = Get-Content -LiteralPath $resultPath -Raw
    if ($execution.ExitCode -ne 0) {
        throw "The sandbox test command failed with exit code $($execution.ExitCode).`n$result"
    }
    if ($result -notmatch '(?m)^WFP integration tests passed\s*$') {
        throw "The sandbox test did not report success.`n$result"
    }

    $trafficCommand = 'cmd.exe /d /c "wfp-tool-traffic-integration-tests.exe {0} {1} > {2}\traffic-result.txt 2>&1"' -f $testAccounts[0], $testAccounts[1], $guestDirectory
    $trafficExecution = Invoke-WsbRaw -Arguments @(
        'exec', '--id', $sandboxId, '-d', $guestDirectory, '-r', 'system', '-c', $trafficCommand) -CaptureFailure
    Write-SandboxTiming 'Guest traffic-enforcement integration test'

    if (-not (Test-Path -LiteralPath $trafficResultPath -PathType Leaf)) {
        throw "The sandbox traffic test did not create $trafficResultPath.`n$($trafficExecution.Output)"
    }
    $trafficResult = Get-Content -LiteralPath $trafficResultPath -Raw
    if ($trafficExecution.ExitCode -ne 0) {
        throw "The sandbox traffic test command failed with exit code $($trafficExecution.ExitCode).`n$trafficResult"
    }
    if ($trafficResult -notmatch '(?m)^WFP traffic enforcement integration tests passed\s*$') {
        throw "The sandbox traffic test did not report success.`n$trafficResult"
    }

    Write-Output $result
    Write-Output $trafficResult
}
finally {
    try {
        if ($sandboxId) {
            Invoke-WsbRaw -Arguments @('stop', '--id', $sandboxId) | Out-Null
        }
    }
    finally {
        $sandboxTiming.Stopwatch.Stop()
        Write-SandboxTiming 'Sandbox teardown'
        Write-Host ([string]::Format(
                [Globalization.CultureInfo]::InvariantCulture,
                'Windows Sandbox integration test duration: {0:F2} secs',
                $sandboxTiming.Stopwatch.Elapsed.TotalSeconds))
    }
}
