<#
.SYNOPSIS
    Installs (or removes) a scheduled task that scans this computer with
    YARA-X and writes the results to the Windows Event Log.

.DESCRIPTION
    - Copies yr.exe, the rules and Invoke-YaraScan.ps1 to the installation
      folder, and makes that folder writable only by Administrators and
      SYSTEM (the task runs as SYSTEM, so anyone who could change these
      files could run code as SYSTEM).
    - Writes config.json with the scan settings. Edit it later to change the
      settings without re-installing.
    - Creates the "YARA" event log with the "YARA-X" source.
    - Registers the scheduled task "\YARA\YARA-X Scan", running daily as
      SYSTEM at below-normal priority.

    Run as administrator. Works with Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
    .\Install-YaraScanTask.ps1 -YrPath .\yr.exe -RulesPath .\rules.yarc

.EXAMPLE
    .\Install-YaraScanTask.ps1 -YrPath .\yr.exe -RulesPath .\rules.yarc `
        -ScanPaths 'C:\Users','D:\Shares' -ExcludePaths 'C:\Users\Public\Videos' `
        -At '03:00' -RandomDelayMinutes 120

.EXAMPLE
    # Update the rules only (keeps the rest of the installation).
    .\Install-YaraScanTask.ps1 -RulesPath .\rules.yarc -UpdateRulesOnly

.EXAMPLE
    .\Install-YaraScanTask.ps1 -Uninstall
#>

[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    # yr.exe to install.
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)]
    [string]$YrPath,

    # Rules to install: a compiled rules file (.yarc, recommended; create it
    # with "yr compile -o rules.yarc <rules>"), or a .yar/.yara file.
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)]
    [Parameter(ParameterSetName = 'UpdateRules', Mandatory = $true)]
    [string]$RulesPath,

    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'UpdateRules')]
    [Parameter(ParameterSetName = 'Uninstall')]
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'YARA-X'),

    # Folders to scan recursively. Environment variables like %ProgramData%
    # are expanded when the scan runs.
    [Parameter(ParameterSetName = 'Install')]
    [string[]]$ScanPaths = @('%SystemDrive%\Users', '%ProgramData%', '%SystemRoot%\Temp'),

    [Parameter(ParameterSetName = 'Install')]
    [string[]]$ExcludePaths = @(),

    # Daily start time (local time, HH:mm).
    [Parameter(ParameterSetName = 'Install')]
    [string]$At = '02:30',

    # Random delay added to the start time, so that not all computers scan
    # (and send events) at the same time.
    [Parameter(ParameterSetName = 'Install')]
    [int]$RandomDelayMinutes = 60,

    # Skip files larger than this many bytes.
    [Parameter(ParameterSetName = 'Install')]
    [long]$SkipLargerBytes = 104857600,

    [Parameter(ParameterSetName = 'Install')]
    [int]$FileTimeoutSeconds = 60,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(0, 99)]
    [int]$CpuLimitPercent = 50,

    [Parameter(ParameterSetName = 'Install')]
    [int]$MaxRuntimeMinutes = 240,

    # Maximum size of the YARA event log, in MB.
    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(1, 2047)]
    [int]$EventLogSizeMB = 20,

    # Start a scan right after installing.
    [Parameter(ParameterSetName = 'Install')]
    [switch]$RunNow,

    [Parameter(ParameterSetName = 'UpdateRules', Mandatory = $true)]
    [switch]$UpdateRulesOnly,

    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)]
    [switch]$Uninstall,

    # With -Uninstall: also delete the YARA event log and its events.
    [Parameter(ParameterSetName = 'Uninstall')]
    [switch]$RemoveEventLog
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskPath = '\YARA\'
$TaskName = 'YARA-X Scan'
$LogName = 'YARA'
$Source = 'YARA-X'

$principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as administrator.'
}

# Rules file name inside the installation folder, keeping the extension so
# that Invoke-YaraScan.ps1 can tell compiled rules from source rules.
function Get-InstalledRulesName([string]$Path) {
    if ($Path -match '\.yarc$') { return 'rules.yarc' }
    return 'rules.yar'
}

# Makes $Path writable only by SYSTEM and Administrators, readable by Users.
function Protect-Folder([string]$Path) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)   # No inherited permissions.
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {   # SYSTEM, Administrators
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule (
            (New-Object System.Security.Principal.SecurityIdentifier $sid),
            'FullControl', $inherit, $none, $allow)))
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule (
        (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'),   # Users
        'ReadAndExecute', $inherit, $none, $allow)))
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

# Checks that yr can load the rules before installing them, so that a broken
# rules file doesn't silently disable scanning on every computer.
function Test-Rules([string]$Yr, [string]$Rules) {
    $probe = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString() + '.bin')
    [IO.File]::WriteAllBytes($probe, [byte[]](0, 1, 2, 3))
    try {
        $arguments = @('scan', '--disable-warnings')
        if ($Rules -match '\.yarc$') { $arguments += '--compiled-rules' }
        $arguments += @($Rules, $probe)
        # In Windows PowerShell 5.1, stderr output of a native command
        # becomes a terminating error when ErrorActionPreference is Stop.
        $ErrorActionPreference = 'Continue'
        $output = & $Yr @arguments 2>&1 | ForEach-Object { "$_" }
        if ($LASTEXITCODE -ne 0) {
            throw "yr can't load the rules in '$Rules': $($output -join "`n")"
        }
    } finally {
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'Uninstall') {
    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task $TaskPath$TaskName."
    }
    if (Test-Path -LiteralPath $InstallDir) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
        Write-Host "Removed $InstallDir."
    }
    if ($RemoveEventLog -and [System.Diagnostics.EventLog]::Exists($LogName)) {
        [System.Diagnostics.EventLog]::Delete($LogName)
        Write-Host "Removed event log $LogName."
    }
    return
}

# ---------------------------------------------------------------------------
# Update rules only
# ---------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'UpdateRules') {
    $installedYr = Join-Path $InstallDir 'yr.exe'
    if (-not (Test-Path -LiteralPath $installedYr)) {
        throw "No installation found in $InstallDir."
    }
    Test-Rules $installedYr $RulesPath

    $rulesName = Get-InstalledRulesName $RulesPath
    $target = Join-Path $InstallDir $rulesName
    # Copy to a temporary name first, so that a scan never sees a partially
    # written file.
    Copy-Item -LiteralPath $RulesPath -Destination "$target.new" -Force
    Move-Item -LiteralPath "$target.new" -Destination $target -Force

    # Invoke-YaraScan.ps1 uses rules.yarc if it exists, otherwise rules.yar.
    # Remove the other variant so that the new rules are the ones used.
    foreach ($other in @('rules.yarc', 'rules.yar')) {
        if ($other -ne $rulesName) {
            Remove-Item -LiteralPath (Join-Path $InstallDir $other) -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "Rules updated: $target"
    return
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

$scanScript = Join-Path $PSScriptRoot 'Invoke-YaraScan.ps1'
if (-not (Test-Path -LiteralPath $scanScript)) {
    throw "Invoke-YaraScan.ps1 must be in the same folder as this script."
}

$YrPath = (Resolve-Path -LiteralPath $YrPath).Path
$RulesPath = (Resolve-Path -LiteralPath $RulesPath).Path

Test-Rules $YrPath $RulesPath

# Installation folder and files.
if (-not (Test-Path -LiteralPath $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}
Protect-Folder $InstallDir

$installedRules = Join-Path $InstallDir (Get-InstalledRulesName $RulesPath)
Copy-Item -LiteralPath $YrPath -Destination (Join-Path $InstallDir 'yr.exe') -Force
Copy-Item -LiteralPath $RulesPath -Destination $installedRules -Force
Copy-Item -LiteralPath $scanScript -Destination (Join-Path $InstallDir 'Invoke-YaraScan.ps1') -Force

# Make every file in the folder inherit the folder's permissions (files that
# already existed may have their own).
& icacls.exe (Join-Path $InstallDir '*') /reset /T /C /Q | Out-Null

foreach ($other in @('rules.yarc', 'rules.yar')) {
    if ((Join-Path $InstallDir $other) -ne $installedRules) {
        Remove-Item -LiteralPath (Join-Path $InstallDir $other) -Force -ErrorAction SilentlyContinue
    }
}

# config.json is written by hand: ConvertTo-Json in Windows PowerShell 5.1
# sometimes serializes arrays as {"value": [...], "Count": n}. The rules and
# yr.exe are not in the file, Invoke-YaraScan.ps1 finds them next to itself.
function ConvertTo-JsonString([string]$Value) {
    # Regex pattern '\\' matches one backslash; in the replacement string a
    # backslash is literal, so '\\' inserts two.
    '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}
function ConvertTo-JsonArray([string[]]$Values) {
    '[' + ((@($Values) | ForEach-Object { ConvertTo-JsonString $_ }) -join ', ') + ']'
}

$configJson = @(
    '{'
    "  `"ScanPaths`": $(ConvertTo-JsonArray $ScanPaths),"
    "  `"ExcludePaths`": $(ConvertTo-JsonArray $ExcludePaths),"
    "  `"SkipLargerBytes`": $SkipLargerBytes,"
    "  `"FileTimeoutSeconds`": $FileTimeoutSeconds,"
    "  `"CpuLimitPercent`": $CpuLimitPercent,"
    "  `"Threads`": 0,"
    "  `"MaxRuntimeMinutes`": $MaxRuntimeMinutes"
    '}'
) -join [Environment]::NewLine

$configPath = Join-Path $InstallDir 'config.json'
[IO.File]::WriteAllText($configPath, $configJson, (New-Object System.Text.UTF8Encoding $false))

# Event log.
if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
    $data = New-Object System.Diagnostics.EventSourceCreationData ($Source, $LogName)
    [System.Diagnostics.EventLog]::CreateEventSource($data)
}

$logKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$LogName"
# Size limit (a multiple of 64 KB); old events are overwritten when full.
Set-ItemProperty -LiteralPath $logKey -Name MaxSize -Type DWord -Value ($EventLogSizeMB * 1MB)
Set-ItemProperty -LiteralPath $logKey -Name Retention -Type DWord -Value 0
# Permissions: SYSTEM full access, Administrators read/write/clear, Event Log
# Readers and NETWORK SERVICE (used by Windows Event Forwarding) read-only.
# Other users can neither read nor write, so they can't forge scan results.
Set-ItemProperty -LiteralPath $logKey -Name CustomSD -Type String `
    -Value 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)'

# Scheduled task.
$taskArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
    "-File `"$(Join-Path $InstallDir 'Invoke-YaraScan.ps1')`" -ConfigPath `"$configPath`""

$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument $taskArguments -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -Daily -At $At -RandomDelay (New-TimeSpan -Minutes $RandomDelayMinutes)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
# The task is stopped if it runs longer than all the per-folder limits plus
# 30 minutes. A zero time span means no limit.
$timeLimit = if ($MaxRuntimeMinutes -gt 0) {
    New-TimeSpan -Minutes ($MaxRuntimeMinutes * [Math]::Max(@($ScanPaths).Count, 1) + 30)
} else {
    New-TimeSpan
}
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit $timeLimit `
    -Priority 7

Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $taskPrincipal -Settings $settings `
    -Description 'Scans this computer with YARA-X and writes the results to the YARA event log.' `
    -Force | Out-Null

Write-Host "Installed to $InstallDir"
Write-Host "Scheduled task: $TaskPath$TaskName (daily at $At, random delay up to $RandomDelayMinutes min)"
Write-Host "Results: Event Viewer > Applications and Services Logs > $LogName"

if ($RunNow) {
    Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
    Write-Host 'Scan started.'
}
