<#
.SYNOPSIS
    Scans folders with YARA-X (yr.exe) and writes the results to the Windows
    Event Log, so they can be collected centrally (Windows Event Forwarding,
    Splunk, Elastic, Wazuh, ...).

.DESCRIPTION
    Runs "yr scan --output-format=ndjson" once per configured folder and
    writes one event per matching file. Every event message is a single-line
    JSON object, which SIEMs can parse directly.

    Events are written to the "YARA" log, source "YARA-X":

      1000  Information  Scan started
      1001  Warning      Rule match (one event per matching file)
      1002  Information  Scan finished (summary)
      1003  Warning      Files that could not be scanned (errors reported by yr)
      1004  Error        Scan failed (yr missing, invalid rules, timeout, ...)

    Settings are read from a JSON file (see config.example.json). Parameters
    given on the command line override the file.

    Works with Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
    .\Invoke-YaraScan.ps1 -ConfigPath 'C:\Program Files\YARA-X\config.json'

.EXAMPLE
    # Test a configuration interactively, printing the events instead of
    # writing them to the Event Log.
    .\Invoke-YaraScan.ps1 -ConfigPath .\config.json -NoEventLog
#>

[CmdletBinding()]
param(
    # JSON configuration file. Defaults to config.json next to this script.
    [string]$ConfigPath,

    # Path to yr.exe.
    [string]$YrPath,

    # Rules: a compiled rules file (.yarc, recommended), a .yar/.yara source
    # file, or a folder with source files.
    [string]$RulesPath,

    # Folders (or files) to scan, recursively.
    [string[]]$ScanPaths,

    # Folders or files to exclude.
    [string[]]$ExcludePaths,

    # Skip files larger than this many bytes (0 = no limit).
    [long]$SkipLargerBytes = -1,

    # Per-file scan timeout in seconds (0 = no timeout).
    [int]$FileTimeoutSeconds = -1,

    # Limit the CPU usage of yr (1-99 percent, 0 = no limit).
    [int]$CpuLimitPercent = -1,

    # Number of scanning threads (0 = automatic).
    [int]$Threads = -1,

    # Stop a scan of a single folder after this many minutes (0 = no limit).
    [int]$MaxRuntimeMinutes = -1,

    # Print events to the console as JSON instead of writing them to the
    # Event Log. Useful for testing a configuration.
    [switch]$NoEventLog
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$LogName = 'YARA'
$Source = 'YARA-X'

$EventIdScanStarted = 1000
$EventIdMatch = 1001
$EventIdScanFinished = 1002
$EventIdScanErrors = 1003
$EventIdScanFailed = 1004

# The Event Log limits a message to 31,839 characters.
$MaxMessageLength = 31000
# Maximum number of yr error lines included in a single 1003 event.
$MaxErrorLinesPerEvent = 100

$ScanId = [guid]::NewGuid().ToString()
$Computer = $env:COMPUTERNAME

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Escapes a string for inclusion in a JSON document.
function ConvertTo-JsonString([string]$Value) {
    if ($null -eq $Value) { return 'null' }
    $sb = New-Object System.Text.StringBuilder ($Value.Length + 2)
    [void]$sb.Append('"')
    foreach ($c in $Value.ToCharArray()) {
        switch ($c) {
            '"' { [void]$sb.Append('\"'); continue }
            '\' { [void]$sb.Append('\\'); continue }
            "`n" { [void]$sb.Append('\n'); continue }
            "`r" { [void]$sb.Append('\r'); continue }
            "`t" { [void]$sb.Append('\t'); continue }
            default {
                if ([int]$c -lt 0x20) {
                    [void]$sb.AppendFormat('\u{0:x4}', [int]$c)
                } else {
                    [void]$sb.Append($c)
                }
            }
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# Builds a single-line JSON object from an ordered dictionary. Values that
# are already JSON (the yr output) are passed in as [JsonRaw] objects and
# inserted verbatim; strings are escaped, numbers and booleans written as-is.
# This avoids ConvertTo-Json, whose output differs between PowerShell
# versions.
class JsonRaw { [string]$Json; JsonRaw([string]$json) { $this.Json = $json } }

function ConvertTo-JsonLine([System.Collections.Specialized.OrderedDictionary]$Fields) {
    $parts = foreach ($key in $Fields.Keys) {
        $value = $Fields[$key]
        $json = if ($null -eq $value) { 'null' }
                elseif ($value -is [JsonRaw]) { $value.Json }
                elseif ($value -is [bool]) { if ($value) { 'true' } else { 'false' } }
                elseif ($value -is [int] -or $value -is [long] -or $value -is [double]) {
                    [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $value)
                }
                elseif ($value -is [array]) {
                    '[' + (($value | ForEach-Object { ConvertTo-JsonString ([string]$_) }) -join ',') + ']'
                }
                else { ConvertTo-JsonString ([string]$value) }
        "$(ConvertTo-JsonString $key):$json"
    }
    return '{' + ($parts -join ',') + '}'
}

# Common fields included in every event.
function New-EventFields([string]$Type) {
    $fields = [ordered]@{}
    $fields['event'] = $Type
    $fields['scan_id'] = $ScanId
    $fields['computer'] = $Computer
    $fields['time'] = (Get-Date).ToUniversalTime().ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    return $fields
}

function Write-ScanEvent {
    param(
        [int]$EventId,
        [System.Diagnostics.EventLogEntryType]$EntryType,
        [System.Collections.Specialized.OrderedDictionary]$Fields
    )

    $message = ConvertTo-JsonLine $Fields

    if ($NoEventLog) {
        # Write-Host, not Write-Output: this function is called from functions
        # whose return value would otherwise include the message.
        Write-Host "[$EventId $EntryType] $message"
        return
    }

    [System.Diagnostics.EventLog]::WriteEntry($Source, $message, $EntryType, $EventId)
}

function Write-FailureEvent([string]$Reason, [string]$Target) {
    $fields = New-EventFields 'scan_failed'
    $fields['target'] = $Target
    $fields['reason'] = $Reason
    if ($fields['reason'].Length -gt $MaxMessageLength - 500) {
        $fields['reason'] = $fields['reason'].Substring(0, $MaxMessageLength - 500) + '...'
    }
    Write-ScanEvent -EventId $EventIdScanFailed -EntryType Error -Fields $fields
}

# Returns the value of a setting: command-line parameter, then config file,
# then default.
function Get-Setting([string]$Name, $ParamValue, $Unset, $Default) {
    if ($null -ne $ParamValue -and -not ($ParamValue -is [string] -and $ParamValue -eq '') -and
        -not ($ParamValue -is [array] -and $ParamValue.Count -eq 0) -and
        -not ($null -ne $Unset -and $ParamValue -eq $Unset)) {
        return $ParamValue
    }
    if ($null -ne $script:Config -and $script:Config.PSObject.Properties[$Name]) {
        return $script:Config.$Name
    }
    return $Default
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

$Config = $null

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $PSScriptRoot 'config.json'
}

if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
    $Config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

$YrPath = Get-Setting 'YrPath' $YrPath $null (Join-Path $PSScriptRoot 'yr.exe')
# Default rules: rules.yarc (compiled) or rules.yar next to this script.
$defaultRules = Join-Path $PSScriptRoot 'rules.yarc'
if (-not (Test-Path -LiteralPath $defaultRules)) { $defaultRules = Join-Path $PSScriptRoot 'rules.yar' }
$RulesPath = Get-Setting 'RulesPath' $RulesPath $null $defaultRules
$ScanPaths = @(Get-Setting 'ScanPaths' $ScanPaths $null @(
    "$env:SystemDrive\Users", "$env:ProgramData", "$env:SystemRoot\Temp"))
$ExcludePaths = @(Get-Setting 'ExcludePaths' $ExcludePaths $null @())
$SkipLargerBytes = [long](Get-Setting 'SkipLargerBytes' $SkipLargerBytes -1 104857600)
$FileTimeoutSeconds = [int](Get-Setting 'FileTimeoutSeconds' $FileTimeoutSeconds -1 60)
$CpuLimitPercent = [int](Get-Setting 'CpuLimitPercent' $CpuLimitPercent -1 50)
$Threads = [int](Get-Setting 'Threads' $Threads -1 0)
$MaxRuntimeMinutes = [int](Get-Setting 'MaxRuntimeMinutes' $MaxRuntimeMinutes -1 240)

# Expand environment variables such as %ProgramData% in paths.
$YrPath = [Environment]::ExpandEnvironmentVariables($YrPath)
$RulesPath = [Environment]::ExpandEnvironmentVariables($RulesPath)
$ScanPaths = @($ScanPaths | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) })
$ExcludePaths = @($ExcludePaths | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) })

# ---------------------------------------------------------------------------
# Event Log source
# ---------------------------------------------------------------------------

if (-not $NoEventLog) {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            # Normally created by Install-YaraScanTask.ps1. Creating it here
            # requires administrator rights.
            $data = New-Object System.Diagnostics.EventSourceCreationData ($Source, $LogName)
            [System.Diagnostics.EventLog]::CreateEventSource($data)
        }
    } catch {
        Write-Error "Event Log source '$Source' doesn't exist and can't be created (run Install-YaraScanTask.ps1 as administrator): $_"
        exit 2
    }
}

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

# Runs yr for a single target and returns a summary object.
function Invoke-YrScan([string]$Target) {
    $summary = [pscustomobject]@{
        Target = $Target; MatchingFiles = 0; Errors = 0; ExitCode = $null; TimedOut = $false
    }

    $arguments = New-Object System.Collections.Generic.List[string]
    $arguments.Add('scan')
    $arguments.Add('--output-format=ndjson')
    $arguments.Add('--print-meta')
    $arguments.Add('--print-tags')
    $arguments.Add('--print-namespace')
    $arguments.Add('--disable-console-logs')
    $arguments.Add('--disable-warnings')

    if (Test-Path -LiteralPath $Target -PathType Container) {
        $arguments.Add('--recursive')
    }
    if ($RulesPath -match '\.yarc$') { $arguments.Add('--compiled-rules') }
    if ($SkipLargerBytes -gt 0) { $arguments.Add("--skip-larger=$SkipLargerBytes") }
    if ($FileTimeoutSeconds -gt 0) { $arguments.Add("--timeout=$FileTimeoutSeconds") }
    if ($CpuLimitPercent -gt 0) { $arguments.Add("--cpu-limit=$CpuLimitPercent") }
    if ($Threads -gt 0) { $arguments.Add("--threads=$Threads") }
    foreach ($exclude in $ExcludePaths) { $arguments.Add("--exclude=$exclude") }

    $arguments.Add($RulesPath)
    $arguments.Add($Target)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $YrPath
    # Quote every argument for the Windows command line. Paths can't contain
    # double quotes, and a trailing backslash must be doubled before the
    # closing quote.
    $psi.Arguments = ($arguments | ForEach-Object {
        '"' + ($_ -replace '(\\+)$', '$1$1') + '"'
    }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

    $process = [System.Diagnostics.Process]::Start($psi)

    try {
        $process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
    } catch {
        # The process may have exited already.
    }

    # Read stderr in the background so that neither pipe can fill up.
    $stderrTask = $process.StandardError.ReadToEndAsync()

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $deadline = if ($MaxRuntimeMinutes -gt 0) { [TimeSpan]::FromMinutes($MaxRuntimeMinutes) } else { $null }
    $lineTask = $process.StandardOutput.ReadLineAsync()

    while ($true) {
        if (-not $lineTask.Wait(1000)) {
            if ($null -ne $deadline -and $stopwatch.Elapsed -gt $deadline) {
                $summary.TimedOut = $true
                try { $process.Kill() } catch { }
                break
            }
            continue
        }

        $line = $lineTask.Result
        if ($null -eq $line) { break }   # End of output.

        $lineTask = $process.StandardOutput.ReadLineAsync()
        $line = $line.Trim()
        if ($line -eq '') { continue }

        $summary.MatchingFiles++
        Write-MatchEvent $line
    }

    $process.WaitForExit()
    $summary.ExitCode = $process.ExitCode

    $stderr = $stderrTask.Result
    $errorLines = @($stderr -split "`r?`n" | Where-Object { $_.Trim() -ne '' })

    if ($summary.TimedOut) {
        Write-FailureEvent "Scan stopped after $MaxRuntimeMinutes minutes (MaxRuntimeMinutes)." $Target
    } elseif ($summary.ExitCode -ne 0) {
        # A non-zero exit code means that the scan didn't run: invalid rules,
        # invalid arguments, etc. stderr contains the reason.
        Write-FailureEvent ("yr exited with code $($summary.ExitCode): " + ($errorLines -join "`n")) $Target
    } elseif ($errorLines.Count -gt 0) {
        # Exit code 0 with errors: some files couldn't be scanned (access
        # denied, locked files, ...). Report them in batches.
        $summary.Errors = $errorLines.Count
        for ($i = 0; $i -lt $errorLines.Count; $i += $MaxErrorLinesPerEvent) {
            $batch = @($errorLines[$i..([Math]::Min($i + $MaxErrorLinesPerEvent, $errorLines.Count) - 1)])
            $fields = New-EventFields 'scan_errors'
            $fields['target'] = $Target
            $fields['error_count'] = $errorLines.Count
            $fields['errors'] = $batch
            $message = ConvertTo-JsonLine $fields
            while ($message.Length -gt $MaxMessageLength -and $batch.Count -gt 1) {
                $batch = @($batch[0..([int]($batch.Count / 2) - 1)])
                $fields['errors'] = $batch
                $message = ConvertTo-JsonLine $fields
            }
            Write-ScanEvent -EventId $EventIdScanErrors -EntryType Warning -Fields $fields
        }
    }

    return $summary
}

# Writes an event for a matching file. `Line` is one NDJSON line produced by
# yr: {"path": "...", "rules": [{"identifier": ..., "namespace": ...,
# "meta": [[key, value], ...], "tags": [...]}, ...]}
function Write-MatchEvent([string]$Line) {
    $result = $null
    try { $result = $Line | ConvertFrom-Json } catch { }

    $fields = New-EventFields 'match'

    if ($null -ne $result -and $result.PSObject.Properties['path']) {
        $fields['path'] = [string]$result.path
        $fields['rules'] = @($result.rules | ForEach-Object { [string]$_.identifier })
    }

    $fields['result'] = [JsonRaw]::new($Line)
    $message = ConvertTo-JsonLine $fields

    if ($message.Length -gt $MaxMessageLength) {
        # Too long for the Event Log (e.g. huge metadata). Keep the path and
        # rule names, drop the full result.
        $fields.Remove('result')
        $fields['truncated'] = $true
    }

    Write-ScanEvent -EventId $EventIdMatch -EntryType Warning -Fields $fields
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$totalStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

if (-not (Test-Path -LiteralPath $YrPath -PathType Leaf)) {
    Write-FailureEvent "yr.exe not found: $YrPath" ''
    exit 1
}

if (-not (Test-Path -LiteralPath $RulesPath)) {
    Write-FailureEvent "Rules not found: $RulesPath" ''
    exit 1
}

$yrVersion = ''
try { $yrVersion = (& $YrPath --version 2>$null | Select-Object -First 1) } catch { }

$rulesHash = ''
if (Test-Path -LiteralPath $RulesPath -PathType Leaf) {
    $rulesHash = (Get-FileHash -LiteralPath $RulesPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

$fields = New-EventFields 'scan_started'
$fields['yr_version'] = [string]$yrVersion
$fields['rules'] = $RulesPath
$fields['rules_sha256'] = $rulesHash
$fields['targets'] = $ScanPaths
$fields['excludes'] = $ExcludePaths
Write-ScanEvent -EventId $EventIdScanStarted -EntryType Information -Fields $fields

$summaries = @()
$failed = $false

foreach ($target in $ScanPaths) {
    if (-not (Test-Path -LiteralPath $target)) {
        # A missing folder isn't an error: not every computer has every path.
        continue
    }
    try {
        $summary = Invoke-YrScan $target
        $summaries += $summary
        if ($summary.TimedOut -or $summary.ExitCode -ne 0) { $failed = $true }
    } catch {
        $failed = $true
        Write-FailureEvent "Exception while scanning: $_" $target
    }
}

$fields = New-EventFields 'scan_finished'
$fields['success'] = -not $failed
$fields['targets_scanned'] = @($summaries).Count
$fields['matching_files'] = [int](($summaries | Measure-Object -Property MatchingFiles -Sum).Sum)
$fields['files_with_errors'] = [int](($summaries | Measure-Object -Property Errors -Sum).Sum)
$fields['duration_seconds'] = [int]$totalStopwatch.Elapsed.TotalSeconds
Write-ScanEvent -EventId $EventIdScanFinished -EntryType Information -Fields $fields

if ($failed) { exit 1 }
exit 0
