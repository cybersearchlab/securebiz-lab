$ErrorActionPreference = "Stop"

# Repository root: directory containing this script
$scriptDir = Split-Path -Parent $PSCommandPath

$trivy = Join-Path $scriptDir ".venv\Scripts\trivy.exe"
$ignoreFile = Join-Path $scriptDir ".trivyignore.yaml"

# Check prerequisites
if (-not (Test-Path $trivy -PathType Leaf)) {
    throw "Trivy executable not found: $trivy"
}

if (-not (Test-Path $ignoreFile -PathType Leaf)) {
    throw "Trivy ignore file not found: $ignoreFile"
}

Write-Host "`n===== TRIVY IaC SCAN =====" -ForegroundColor Cyan

& $trivy config `
    --ignorefile $ignoreFile `
    --severity HIGH,CRITICAL `
    --exit-code 1 `
    $scriptDir

$trivyExitCode = $LASTEXITCODE
$global:LASTEXITCODE = $trivyExitCode

if ($trivyExitCode -ne 0) {
    throw "IaC scan failed. Trivy exit code: $trivyExitCode."
}

Write-Host "`nIaC scan passed." -ForegroundColor Green
