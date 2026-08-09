param(
    [Parameter(Mandatory = $true)]
    [string]$Binary,
    [string]$DataDir = (Join-Path $env:USERPROFILE 'Documents\data'),
    [int]$Port = 9090,
    [string]$Title = 'DataShelf',
    [switch]$Lan
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "DataShelf binary was not found: $Binary"
}
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$logDir = Join-Path (Split-Path -Parent $Binary) 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$listenHost = if ($Lan) { '0.0.0.0' } else { '127.0.0.1' }
$stdoutLog = Join-Path $logDir 'datashelf.stdout.log'
$stderrLog = Join-Path $logDir 'datashelf.stderr.log'

& $Binary '-dir' $DataDir '-host' $listenHost '-port' $Port '-title' $Title >> $stdoutLog 2>> $stderrLog
exit $LASTEXITCODE
