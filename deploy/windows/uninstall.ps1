param(
    [ValidateSet('Task', 'Startup', 'Both')]
    [string]$Mode = 'Both'
)

$ErrorActionPreference = 'Stop'

if ($Mode -in @('Task', 'Both')) {
    Unregister-ScheduledTask -TaskName 'DataShelf' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host 'DataShelf scheduled task removed.'
}

if ($Mode -in @('Startup', 'Both')) {
    $shortcutPath = Join-Path ([Environment]::GetFolderPath('Startup')) 'DataShelf.lnk'
    Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction SilentlyContinue
    Write-Host 'DataShelf startup shortcut removed.'
}

Write-Host 'DataShelf data, binaries, and logs were kept. Remove them separately if required.'
