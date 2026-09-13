$ErrorActionPreference = "Stop"
$releaseRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $releaseRoot
$env:STREAMLIT_BROWSER_GATHER_USAGE_STATS = "false"

function Test-PythonModule([string] $PythonPath, [string] $ModuleName) {
    try {
        & $PythonPath -c "import $ModuleName" 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    }
    catch {
        return $false
    }
}

# Prefer a Python that already has Streamlit, but keep the launcher portable.
$candidates = [System.Collections.Generic.List[string]]::new()
if ($env:CRYPTOAUDIT_PYTHON) {
    $candidates.Add($env:CRYPTOAUDIT_PYTHON)
}
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCommand) {
    $candidates.Add($pythonCommand.Source)
}
$knownPython = "D:\ancoda\python.exe"
if (Test-Path -LiteralPath $knownPython) {
    $candidates.Add($knownPython)
}
$pyCommand = Get-Command py -ErrorAction SilentlyContinue
if ($pyCommand) {
    $candidates.Add($pyCommand.Source)
}

$python = $null
foreach ($candidate in ($candidates | Select-Object -Unique)) {
    if (Test-PythonModule $candidate "streamlit") {
        $python = $candidate
        break
    }
}

if (-not $python) {
    Write-Host "No Python installation with Streamlit was found."
    Write-Host "Install the UI dependencies with:"
    Write-Host "  python -m pip install -r requirements-ai.txt"
    Write-Host "Or set CRYPTOAUDIT_PYTHON to a Python executable that has Streamlit."
    Read-Host "Press Enter to close"
    exit 1
}

& $python -c "import sys; print('Python', sys.version.split()[0]); print(sys.executable)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "The selected Python executable could not run."
    Read-Host "Press Enter to close"
    exit 1
}

Write-Host "CryptoAudit Agent UI: http://localhost:8501"
& $python -m streamlit run (Join-Path $releaseRoot "app.py") --server.headless false --server.address localhost --server.showEmailPrompt false
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    Write-Host "Streamlit exited with code $exitCode"
    Read-Host "Press Enter to close"
}
exit $exitCode
