param(
    [int]$BackendPort = 8010,
    [string]$BackendUrl = "",
    [switch]$ReuseBackend
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonScript = Join-Path $scriptDir "validate_realtime_pipeline.py"

if (-not (Test-Path -LiteralPath $pythonScript)) {
    Write-Error "Missing validation script: $pythonScript"
    exit 1
}

$arguments = @($pythonScript, "--backend-port", $BackendPort)
if ($BackendUrl) {
    $arguments += @("--backend-url", $BackendUrl)
}
if ($ReuseBackend) {
    $arguments += "--reuse-backend"
}

& py -3 @arguments
exit $LASTEXITCODE
