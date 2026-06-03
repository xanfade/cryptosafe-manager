$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$python = Join-Path $projectRoot "venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    throw "Python interpreter not found at venv\Scripts\python.exe"
}

$distDir = Join-Path $projectRoot "dist"
$buildDir = Join-Path $projectRoot "build"
$specPath = Join-Path $projectRoot "cryptosafe_manager_windows.spec"

if (Test-Path $distDir) {
    Remove-Item -LiteralPath $distDir -Recurse -Force
}
if (Test-Path $buildDir) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}

& $python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed."
}

& $python -m PyInstaller --noconfirm $specPath
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed."
}

Write-Host ""
Write-Host "Build completed."
Write-Host "Executable folder: $distDir\CryptoSafeManager"
