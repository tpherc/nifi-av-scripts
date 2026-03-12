[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$MpCmdRunPath,

    [string]$WorkingDirectory,

    [switch]$ReturnHR,

    [bool]$DisableRemediation = $true,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Split-RawLines {
    param(
        [AllowEmptyString()]
        [string]$Text
    )

    if ($null -eq $Text) {
        return [string[]]@()
    }

    if ($Text.Length -eq 0) {
        return [string[]]@()
    }

    return [string[]][regex]::Split($Text, '\r\n|\n|\r', [System.Text.RegularExpressions.RegexOptions]::None)
}

function Format-CommandArgument {
    param(
        [string]$Value
    )

    if ($null -eq $Value) {
        return '""'
    }

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    return '"' + ($Value -replace '"', '\"') + '"'
}

function Join-CommandLine {
    param(
        [string]$Command,
        [string[]]$Arguments
    )

    $parts = New-Object 'System.Collections.Generic.List[string]'
    [void]$parts.Add((Format-CommandArgument -Value $Command))

    foreach ($argument in $Arguments) {
        [void]$parts.Add((Format-CommandArgument -Value $argument))
    }

    return ($parts -join ' ')
}

function Get-NormalizedWorkingDirectory {
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return $null
    }

    return $Value
}

function Resolve-MpCmdRunPath {
    param(
        [string]$ExplicitPath
    )

    if ($ExplicitPath) {
        return (Resolve-Path -LiteralPath $ExplicitPath).ProviderPath
    }

    $candidates = New-Object 'System.Collections.Generic.List[string]'

    if ($env:ProgramFiles) {
        [void]$candidates.Add((Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'))
    }

    $platformRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    if (Test-Path -LiteralPath $platformRoot) {
        $platformCandidates = Get-ChildItem -LiteralPath $platformRoot -Directory | Sort-Object -Property Name -Descending
        foreach ($directory in $platformCandidates) {
            [void]$candidates.Add((Join-Path $directory.FullName 'MpCmdRun.exe'))
        }
    }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).ProviderPath
        }
    }

    throw 'MpCmdRun.exe was not found. Pass -MpCmdRunPath or install Microsoft Defender Antivirus platform binaries.'
}

function Parse-DefenderOutput {
    param(
        [string[]]$StdoutLines,
        [string[]]$StderrLines,
        [string]$TargetPath,
        [int]$ScanType,
        [bool]$DisableRemediation
    )

    $summary = $null
    $threatCount = $null
    $lifecycleStatus = 'partial'
    $defenderHR = $null
    $threats = New-Object 'System.Collections.Generic.List[object]'
    $currentThreat = $null
    $sawScanStart = $false
    $sawScanFinish = $false
    $resolvedTargetPath = $TargetPath
    $combinedLines = New-Object 'System.Collections.Generic.List[string]'

    foreach ($stdoutLine in $StdoutLines) {
        [void]$combinedLines.Add($stdoutLine)
    }

    foreach ($stderrLine in $StderrLines) {
        [void]$combinedLines.Add($stderrLine)
    }

    foreach ($line in $combinedLines) {
        if (-not $defenderHR -and $line -match '(?i)\b(?:hr|hresult)\b\s*[=:]\s*(0x[0-9A-Fa-f]+|-?\d+)') {
            $defenderHR = $Matches[1]
        }

        if ($line -eq 'Scan starting...') {
            $sawScanStart = $true
            continue
        }

        if ($line -eq 'Scan finished.') {
            $sawScanFinish = $true
            continue
        }

        if ($line -match '^Scanning\s+(.+?)\s+found no threats\.$') {
            $summary = $line
            $resolvedTargetPath = $Matches[1]
            $threatCount = 0
            continue
        }

        if ($line -match '^Scanning\s+(.+?)\s+found\s+(\d+)\s+threats?\.$') {
            $summary = $line
            $resolvedTargetPath = $Matches[1]
            $threatCount = [int]$Matches[2]
            continue
        }

        if ($line -match '^Threat\s*:\s*(.+)$') {
            if ($null -ne $currentThreat) {
                [void]$threats.Add([pscustomobject]$currentThreat)
            }

            $threatName = $Matches[1].Trim()
            $category = $null
            $platform = $null
            $family = $null

            if ($threatName -match '^(?<category>[^:]+):(?<platform>[^/]+)/(?<family>.+)$') {
                $category = $Matches['category']
                $platform = $Matches['platform']
                $family = $Matches['family']
            }

            $currentThreat = [ordered]@{
                name = $threatName
                category = $category
                platform = $platform
                family = $family
                severity = $null
                actionTaken = $(if ($DisableRemediation) { 'None' } else { $null })
                remediationStatus = $(if ($DisableRemediation) { 'Not Attempted' } else { $null })
                resourcesTotal = $null
                resources = New-Object 'System.Collections.Generic.List[object]'
            }
            continue
        }

        if ($null -ne $currentThreat -and $line -match '^Resources\s*:\s*(\d+)\s+total$') {
            $currentThreat.resourcesTotal = [int]$Matches[1]
            continue
        }

        if ($null -ne $currentThreat -and $line -match '^\s+([A-Za-z0-9_-]+)\s*:\s*(.+)$') {
            [void]$currentThreat.resources.Add([pscustomobject]@{
                type = $Matches[1].Trim()
                path = $Matches[2]
                hash = $null
                size = $null
            })
            continue
        }
    }

    if ($null -ne $currentThreat) {
        [void]$threats.Add([pscustomobject]$currentThreat)
    }

    if ($sawScanFinish) {
        $lifecycleStatus = 'completed'
    }
    elseif ($sawScanStart) {
        $lifecycleStatus = 'partial'
    }

    if ($null -eq $summary -and $threats.Count -gt 0 -and $null -eq $threatCount) {
        $threatCount = $threats.Count
    }

    $targetStatus = 'unknown'
    $isClean = $null

    if ($threats.Count -gt 0 -or ($null -ne $threatCount -and $threatCount -gt 0)) {
        $targetStatus = 'infected'
        $isClean = $false
    }
    elseif ($null -ne $threatCount -and $threatCount -eq 0) {
        $targetStatus = 'clean'
        $isClean = $true
    }

    return [pscustomobject]@{
        defenderHR = $defenderHR
        target = [pscustomobject]@{
            path = $resolvedTargetPath
            status = $targetStatus
            signature = $null
            hash = $null
            size = $null
        }
        scan = [pscustomobject]@{
            scanType = $ScanType
            status = $lifecycleStatus
            isClean = $isClean
            threatCount = $threatCount
            summary = $summary
        }
        threats = $threats.ToArray()
    }
}

function Convert-ExitCodeToHex {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ExitCode
    )

    $bytes = [System.BitConverter]::GetBytes($ExitCode)
    $unsignedExitCode = [System.BitConverter]::ToUInt32($bytes, 0)
    return ('0x{0:X8}' -f $unsignedExitCode)
}

function Resolve-DefenderHR {
    param(
        [AllowNull()]
        [string]$ParsedDefenderHR,
        [AllowNull()]
        [int]$ExitCode,
        [bool]$ReturnHRRequested
    )

    if (-not [string]::IsNullOrWhiteSpace($ParsedDefenderHR)) {
        if ($ParsedDefenderHR -match '^(?i)0x[0-9a-f]+$') {
            return $ParsedDefenderHR.ToUpperInvariant().Replace('X', 'x')
        }

        if ($ParsedDefenderHR -match '^-?\d+$') {
            return (Convert-ExitCodeToHex -ExitCode ([int]$ParsedDefenderHR))
        }

        return $ParsedDefenderHR
    }

    if ($ReturnHRRequested -and $null -ne $ExitCode) {
        return (Convert-ExitCodeToHex -ExitCode $ExitCode)
    }

    return $null
}

function Get-WrapperExitCode {
    param(
        [string]$ScanStatus,
        [string]$TargetStatus,
        [AllowNull()]
        [int]$ProcessExitCode
    )

    if ($ScanStatus -eq 'completed' -and $TargetStatus -in @('clean', 'infected')) {
        return 0
    }

    if ($null -ne $ProcessExitCode -and $ProcessExitCode -ne 0) {
        return 1
    }

    return 1
}

function Get-ExitCodeMeaning {
    param(
        [AllowNull()]
        [int]$ExitCode,
        [string]$TargetStatus
    )

    if ($null -eq $ExitCode) {
        return $null
    }

    switch ($ExitCode) {
        0 {
            if ($TargetStatus -eq 'clean') {
                return 'Clean'
            }

            return 'Success'
        }
        2 { return 'Threats Found' }
        default {
            if ($TargetStatus -eq 'infected') {
                return 'Threats Found'
            }

            return 'Process Error'
        }
    }
}

$resolvedPath = $null
$resolvedMpCmdRunPath = $null
$output = $null
$wrapperExitCode = 1
$arguments = New-Object 'System.Collections.Generic.List[string]'
$commandLine = $null
$startedAt = $null
$finishedAt = $null
$processExitCode = $null
$stdoutText = ''
$stderrText = ''
$stdoutLines = [string[]]@()
$stderrLines = [string[]]@()

try {
    $resolvedPath = (Resolve-Path -LiteralPath $Path).ProviderPath
    $resolvedMpCmdRunPath = Resolve-MpCmdRunPath -ExplicitPath $MpCmdRunPath

    if (-not $WorkingDirectory) {
        $WorkingDirectory = Split-Path -Path $resolvedMpCmdRunPath -Parent
    }

    $WorkingDirectory = Get-NormalizedWorkingDirectory -Value $WorkingDirectory

    $arguments = New-Object 'System.Collections.Generic.List[string]'
    [void]$arguments.Add('-Scan')
    [void]$arguments.Add('-ScanType')
    [void]$arguments.Add('3')
    [void]$arguments.Add('-File')
    [void]$arguments.Add($resolvedPath)

    if ($DisableRemediation) {
        [void]$arguments.Add('-DisableRemediation')
    }

    if ($ReturnHR.IsPresent) {
        [void]$arguments.Add('-ReturnHR')
    }

    $commandLine = Join-CommandLine -Command $resolvedMpCmdRunPath -Arguments $arguments.ToArray()

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $resolvedMpCmdRunPath
    $startInfo.Arguments = (($arguments | ForEach-Object { Format-CommandArgument -Value $_ }) -join ' ')
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo

    $startedAt = [DateTimeOffset]::UtcNow
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdoutText = $stdoutTask.GetAwaiter().GetResult()
        $stderrText = $stderrTask.GetAwaiter().GetResult()
        $processExitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }
    $finishedAt = [DateTimeOffset]::UtcNow

    $stdoutLines = @(Split-RawLines -Text $stdoutText)
    $stderrLines = @(Split-RawLines -Text $stderrText)
    $parsedOutput = Parse-DefenderOutput -StdoutLines $stdoutLines -StderrLines $stderrLines -TargetPath $resolvedPath -ScanType 3 -DisableRemediation $DisableRemediation

    $output = [pscustomobject]@{
        scanner = [pscustomobject]@{
            name = 'Microsoft Defender'
            mode = 'MpCmdRun'
            engineVersion = $null
            signatureVersion = $null
        }
        command = [pscustomobject]@{
            program = $resolvedMpCmdRunPath
            args = $arguments.ToArray()
            cwd = $WorkingDirectory
            line = $commandLine
            returnHRRequested = $ReturnHR.IsPresent
            disableRemediation = $DisableRemediation
        }
        execution = [pscustomobject]@{
            startedAt = $startedAt.ToString('o')
            finishedAt = $finishedAt.ToString('o')
            durationMs = [int64][Math]::Max(0, ($finishedAt - $startedAt).TotalMilliseconds)
            exitCode = $processExitCode
            exitCodeMeaning = Get-ExitCodeMeaning -ExitCode $processExitCode -TargetStatus $parsedOutput.target.status
            error = $(if ([string]::IsNullOrEmpty($stderrText)) { $null } else { $stderrText })
            defenderHR = Resolve-DefenderHR -ParsedDefenderHR $parsedOutput.defenderHR -ExitCode $processExitCode -ReturnHRRequested $ReturnHR.IsPresent
        }
        target = $parsedOutput.target
        scan = $parsedOutput.scan
        threats = $parsedOutput.threats
        raw = [pscustomobject]@{
            stdoutText = $stdoutText
            stdoutLines = $stdoutLines
            stderrText = $stderrText
            stderrLines = $stderrLines
        }
    }

    $wrapperExitCode = Get-WrapperExitCode -ScanStatus $parsedOutput.scan.status -TargetStatus $parsedOutput.target.status -ProcessExitCode $processExitCode
}
catch {
    $message = $_.Exception.Message
    $commandArgs = [System.Collections.Generic.List[string]]::new()

    foreach ($argument in $arguments) {
        [void]$commandArgs.Add($argument)
    }

    if ($commandArgs.Count -eq 0 -and $resolvedPath) {
        [void]$commandArgs.Add('-Scan')
        [void]$commandArgs.Add('-ScanType')
        [void]$commandArgs.Add('3')
        [void]$commandArgs.Add('-File')
        [void]$commandArgs.Add($resolvedPath)

        if ($DisableRemediation) {
            [void]$commandArgs.Add('-DisableRemediation')
        }

        if ($ReturnHR.IsPresent) {
            [void]$commandArgs.Add('-ReturnHR')
        }
    }

    if (-not $commandLine -and $resolvedMpCmdRunPath -and $commandArgs.Count -gt 0) {
        $commandLine = Join-CommandLine -Command $resolvedMpCmdRunPath -Arguments $commandArgs.ToArray()
    }

    $stdoutLines = @(Split-RawLines -Text $stdoutText)
    $stderrLines = @(Split-RawLines -Text $stderrText)
    $targetStatus = $(if ($processExitCode -ne $null -or $startedAt -ne $null -or $finishedAt -ne $null -or $stdoutText.Length -gt 0 -or $stderrText.Length -gt 0) { 'unknown' } else { 'error' })
    $normalizedWorkingDirectory = Get-NormalizedWorkingDirectory -Value $WorkingDirectory

    $output = [pscustomobject]@{
        scanner = [pscustomobject]@{
            name = 'Microsoft Defender'
            mode = 'MpCmdRun'
            engineVersion = $null
            signatureVersion = $null
        }
        command = [pscustomobject]@{
            program = $resolvedMpCmdRunPath
            args = $commandArgs.ToArray()
            cwd = $normalizedWorkingDirectory
            line = $commandLine
            returnHRRequested = $ReturnHR.IsPresent
            disableRemediation = $DisableRemediation
        }
        execution = [pscustomobject]@{
            startedAt = $(if ($startedAt) { $startedAt.ToString('o') } else { $null })
            finishedAt = $(if ($finishedAt) { $finishedAt.ToString('o') } else { $null })
            durationMs = $(if ($startedAt -and $finishedAt) { [int64][Math]::Max(0, ($finishedAt - $startedAt).TotalMilliseconds) } else { $null })
            exitCode = $processExitCode
            exitCodeMeaning = $null
            error = $message
            defenderHR = Resolve-DefenderHR -ParsedDefenderHR $null -ExitCode $processExitCode -ReturnHRRequested $ReturnHR.IsPresent
        }
        target = [pscustomobject]@{
            path = $resolvedPath
            status = $targetStatus
            signature = $null
            hash = $null
            size = $null
        }
        scan = [pscustomobject]@{
            scanType = 3
            status = 'failed'
            isClean = $null
            threatCount = $null
            summary = $null
        }
        threats = @()
        raw = [pscustomobject]@{
            stdoutText = $stdoutText
            stdoutLines = $stdoutLines
            stderrText = $stderrText
            stderrLines = $stderrLines
        }
    }

    $wrapperExitCode = 1
}

$json = $output | ConvertTo-Json -Depth 10

if ($OutputPath) {
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
        [void](New-Item -ItemType Directory -Path $outputDirectory -Force)
    }

    Set-Content -LiteralPath $OutputPath -Value $json -Encoding utf8
}

$json
exit $wrapperExitCode
