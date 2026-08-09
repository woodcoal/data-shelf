param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'DataShelf'),
    [string]$Binary = (Join-Path $InstallDir 'datashelf-windows-amd64.exe'),
    [string]$RunnerScript = (Join-Path $InstallDir 'datashelf-run.ps1'),
    [string]$DataDir = (Join-Path $env:USERPROFILE 'Documents\data'),
    [int]$Port = 9090,
    [string]$Title = 'DataShelf',
    [switch]$Lan
)

$ErrorActionPreference = 'Stop'
foreach ($path in @($Binary, $RunnerScript)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required file was not found: $path"
    }
}

$taskName = 'DataShelf'
$powershell = (Get-Command powershell.exe).Source
$arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$RunnerScript`" -Binary `"$Binary`" -DataDir `"$DataDir`" -Port $Port -Title `"$Title`""
if ($Lan) {
    $arguments += ' -Lan'
}

$action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "DataShelf scheduled task installed: $taskName"
