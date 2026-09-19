param(
    [string]$Node = 'node',
    [string]$Pnpm = 'pnpm',
    [string]$Python = 'python',
    [switch]$SkipInstall
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$root = Split-Path $PSScriptRoot -Parent
$artifacts = Join-Path $root 'artifacts'
New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
$oldAcceptance = $env:DARKVAULT_ACCEPTANCE
$hostProcess = $null
Push-Location $root
try {
    $pythonEnvironment = Join-Path $artifacts 'python-env'
    $pythonExecutable = Join-Path $pythonEnvironment $(if ($IsWindows) { 'Scripts/python.exe' } else { 'bin/python' })
    $newPythonEnvironment = !(Test-Path -LiteralPath $pythonExecutable)
    if ($newPythonEnvironment) { & $Python -m venv $pythonEnvironment }
    if (!$SkipInstall -or $newPythonEnvironment) { & $pythonExecutable -m pip install -e ./clients/python build }
    Push-Location server/DarkVault.Server/Web
    try {
        if (!$SkipInstall) { & $Pnpm install --frozen-lockfile }
        & $Node node_modules/esbuild/bin/esbuild app.js --bundle --format=esm --minify --outfile=../wwwroot/app.js
        & $Node --test protocol.test.js
        if (!$SkipInstall) { & $Node node_modules/@playwright/test/cli.js install chromium }
    } finally { Pop-Location }
    dotnet build DarkVault.sln -c Release --disable-build-servers -m:1 -warnaserror
    dotnet format whitespace DarkVault.sln --no-restore --verify-no-changes
    dotnet build tests/AcceptanceHost/AcceptanceHost.csproj -c Release --disable-build-servers -m:1 -warnaserror
    Push-Location cli
    try {
        if (@(gofmt -l .).Count) { throw 'Run gofmt before verification.' }
        go build -trimpath -o ../artifacts/darkvault.exe .
        go vet ./...
        go mod verify
    } finally { Pop-Location }
    dotnet test DarkVault.sln -c Release --no-build --logger 'trx;LogFilePrefix=tests' --results-directory artifacts/test-results
    $start = @{
        FilePath = 'dotnet'
        ArgumentList = @(('"' + (Join-Path $root 'tests/AcceptanceHost/bin/Release/net10.0/AcceptanceHost.dll') + '"'), ('"' + $root + '"'))
        WorkingDirectory = $root
        PassThru = $true
        RedirectStandardOutput = (Join-Path $artifacts 'acceptance-host.log')
        RedirectStandardError = (Join-Path $artifacts 'acceptance-host-error.log')
    }
    if ($IsWindows) { $start.WindowStyle = 'Hidden' }
    $started = [DateTime]::UtcNow
    $hostProcess = Start-Process @start
    $descriptor = Join-Path $root '.local/acceptance.json'
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        if ($hostProcess.HasExited) { throw 'Acceptance host exited. Inspect artifacts/acceptance-host-error.log.' }
        if ((Test-Path $descriptor) -and (Get-Item $descriptor).LastWriteTimeUtc -ge $started) {
            try { $response = Invoke-WebRequest -Uri 'https://127.0.0.1:18866/health/ready' -SkipCertificateCheck -TimeoutSec 1; if ($response.StatusCode -eq 200) { $ready = $true; break } } catch { }
        }
        Start-Sleep -Milliseconds 250
    }
    if (!$ready) { throw 'Acceptance host did not become ready.' }
    $env:DARKVAULT_ACCEPTANCE = $descriptor
    Push-Location cli
    try { go test ./... } finally { Pop-Location }
    & $pythonExecutable -m build clients/python --outdir artifacts/python
    $pythonConsumer = Join-Path $artifacts 'python-consumer'
    $consumerExecutable = Join-Path $pythonConsumer $(if ($IsWindows) { 'Scripts/python.exe' } else { 'bin/python' })
    if (!(Test-Path -LiteralPath $consumerExecutable)) { & $Python -m venv $pythonConsumer }
    $wheel = Get-ChildItem artifacts/python -File -Filter 'darkvault_client-*.whl' | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if (!$wheel) { throw 'Python wheel was not produced.' }
    & $consumerExecutable -m pip install --force-reinstall $wheel.FullName
    & $consumerExecutable -I -m unittest discover -s clients/python/tests -v
    Push-Location server/DarkVault.Server/Web
    try { & $Node node_modules/@playwright/test/cli.js test } finally { Pop-Location }
    dotnet publish server/DarkVault.Server/DarkVault.Server.csproj -c Release --no-restore -o artifacts/server
    dotnet pack clients/csharp/DarkVault.Client/DarkVault.Client.csproj -c Release --no-restore -o artifacts/packages
    dotnet pack clients/csharp/DarkVault.Extensions.Configuration/DarkVault.Extensions.Configuration.csproj -c Release --no-restore -o artifacts/packages
    Write-Output 'Verification completed, including the Python package. Only temporary test state was used.'
} finally {
    if ($hostProcess -and !$hostProcess.HasExited) { Stop-Process -Id $hostProcess.Id }
    if ($hostProcess -and (Test-Path -LiteralPath $descriptor) -and (Get-Item -LiteralPath $descriptor).LastWriteTimeUtc -ge $started) {
        $testState = Get-Content -LiteralPath $descriptor -Raw | ConvertFrom-Json
        $statePath = [IO.Path]::GetFullPath((Split-Path $testState.tokenFile -Parent))
        $localRoot = [IO.Path]::GetFullPath((Join-Path $root '.local'))
        if ((Split-Path $statePath -Parent) -ne $localRoot -or (Split-Path $statePath -Leaf) -notmatch '^acceptance-[a-f0-9]{32}$') {
            throw 'Unexpected acceptance state path; cleanup refused.'
        }
        if ((Get-Item -LiteralPath $statePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected acceptance state link.' }
        $hostProcess.WaitForExit()
        Remove-Item -LiteralPath $statePath -Recurse -Force
        Remove-Item -LiteralPath $descriptor -Force
    }
    $env:DARKVAULT_ACCEPTANCE = $oldAcceptance
    Pop-Location
}
