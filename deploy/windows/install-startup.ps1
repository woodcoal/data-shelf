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

$startupDir = [Environment]::GetFolderPath('Startup')
$shortcutPath = Join-Path $startupDir 'DataShelf.lnk'
$powershell = (Get-Command powershell.exe).Source
$arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$RunnerScript`" -Binary `"$Binary`" -DataDir `"$DataDir`" -Port $Port -Title `"$Title`""
if ($Lan) {
    $arguments += ' -Lan'
}

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $powershell
$shortcut.Arguments = $arguments
$shortcut.WorkingDirectory = $InstallDir
$shortcut.Description = 'Start DataShelf at user logon'
$shortcut.Save()

Write-Host "DataShelf startup shortcut installed: $shortcutPath"
