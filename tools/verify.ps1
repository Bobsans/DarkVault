param(
    [string]$Node = 'node',
    [string]$Pnpm = 'pnpm',
    [string]$Python = 'python',
    [switch]$SkipInstall,
    [switch]$NativeAot,
    [ValidateSet('linux-x64', 'linux-arm64', 'win-x64', 'win-arm64', 'osx-x64', 'osx-arm64')][string]$Runtime,
    [string]$ReleaseTag
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$root = Split-Path $PSScriptRoot -Parent
$testProjects = @(
    'server/DarkVault.Server.Tests/DarkVault.Server.Tests.csproj',
    'clients/csharp/DarkVault.Client.Tests/DarkVault.Client.Tests.csproj'
)
$productProjects = @(
    'server/DarkVault.Server/DarkVault.Server.csproj',
    'clients/csharp/DarkVault.Client/DarkVault.Client.csproj',
    'clients/csharp/DarkVault.Extensions.Configuration/DarkVault.Extensions.Configuration.csproj'
)
if ($ReleaseTag -and (!$NativeAot -or $ReleaseTag -cnotmatch '^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$')) { throw 'ReleaseTag requires NativeAot and a vMAJOR.MINOR.PATCH tag.' }
if ($NativeAot) {
    $platform = if ($IsWindows) { 'win' } elseif ($IsMacOS) { 'osx' } else { 'linux' }
    $hostRuntime = "$platform-$([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant())"
    if (!$Runtime) { $Runtime = $hostRuntime }
    if ($Runtime -ne $hostRuntime) { throw "Native verification requires a $Runtime host; this host is $hostRuntime." }
}
$artifacts = Join-Path $root 'artifacts'
New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
$oldAcceptance = $env:DARKVAULT_ACCEPTANCE
$oldData, $oldUrls, $oldCertificate = $env:DARKVAULT_DATA, $env:ASPNETCORE_URLS, $env:Kestrel__Certificates__Default__Path
$oldIpQuota, $oldPrincipalQuota = $env:Security__RateLimits__Ip, $env:Security__RateLimits__Principal
$hostProcess = $null
$started = $null
$descriptor = Join-Path $root '.local/acceptance.json'
Push-Location $root
try {
    $pythonEnvironment = Join-Path $artifacts 'python-env'
    $pythonExecutable = Join-Path $pythonEnvironment $(if ($IsWindows) { 'Scripts/python.exe' } else { 'bin/python' })
    $newPythonEnvironment = !(Test-Path -LiteralPath $pythonExecutable)
    if ($newPythonEnvironment) { & $Python -m venv $pythonEnvironment }
    if (!$SkipInstall -or $newPythonEnvironment) { & $pythonExecutable -m pip install -e ./clients/python build }
    Push-Location clients/typescript
    try {
        if (!$SkipInstall) { & $Pnpm install --frozen-lockfile }
        & $Pnpm build
        & $Node --test test/client.test.js
    } finally { Pop-Location }
    Push-Location admin
    try {
        if (!$SkipInstall) { & $Pnpm install --frozen-lockfile }
        & $Pnpm build
        & $Node --test protocol.test.js
        if (!$SkipInstall) { & $Node node_modules/@playwright/test/cli.js install --with-deps chromium }
    } finally { Pop-Location }
    foreach ($project in $testProjects) {
        dotnet build $project -c Release --disable-build-servers -m:1 -warnaserror
    }
    foreach ($project in ($productProjects + $testProjects)) {
        dotnet format whitespace $project --no-restore --verify-no-changes
    }
    dotnet build tests/AcceptanceHost/AcceptanceHost.csproj -c Release --disable-build-servers -m:1 -warnaserror
    if ((Get-FileHash tests/fixtures/jwe.json).Hash -ne (Get-FileHash clients/go/testdata/jwe.json).Hash) { throw 'Go SDK fixture differs from the shared protocol fixture.' }
    Push-Location clients/go
    try {
        if (@(gofmt -l .).Count) { throw 'Run gofmt on the Go SDK before verification.' }
        go vet ./...
        go mod verify
    } finally { Pop-Location }
    Push-Location cli
    try {
        if (@(gofmt -l .).Count) { throw 'Run gofmt before verification.' }
        go build -trimpath -o ../artifacts/darkvault.exe .
        go vet ./...
        go mod verify
    } finally { Pop-Location }
    foreach ($project in $testProjects) {
        $testName = [IO.Path]::GetFileNameWithoutExtension($project)
        dotnet test $project -c Release --no-build --logger "trx;LogFilePrefix=$testName" --results-directory artifacts/test-results
    }
    if ($NativeAot) {
        $versionProperties = @()
        if ($ReleaseTag) {
            $commit = git rev-parse HEAD
            $versionProperties = @("-p:Version=$($ReleaseTag.Substring(1))", "-p:SourceRevisionId=$commit", "-p:RepositoryCommit=$commit")
        }
        $nativeOutput = Join-Path $artifacts "server-aot/$runtime"
        dotnet publish server/DarkVault.Server/DarkVault.Server.csproj -c Release -r $runtime -p:PublishProfile=NativeAot @versionProperties -o $nativeOutput --disable-build-servers -warnaserror
        $nativeServer = Join-Path $nativeOutput $(if ($IsWindows) { 'DarkVault.Server.exe' } else { 'DarkVault.Server' })
        & $nativeServer --version
    }
    $start = @{
        FilePath = 'dotnet'
        ArgumentList = @(('"' + (Join-Path $root 'tests/AcceptanceHost/bin/Release/net10.0/AcceptanceHost.dll') + '"'), ('"' + $root + '"'))
        WorkingDirectory = $root
        PassThru = $true
        RedirectStandardOutput = (Join-Path $artifacts 'acceptance-host.log')
        RedirectStandardError = (Join-Path $artifacts 'acceptance-host-error.log')
    }
    # All SDKs and the browser share one loopback source in this burst workload.
    # Dedicated security tests above verify production quotas and rejection paths.
    $env:Security__RateLimits__Ip = '2000'
    $env:Security__RateLimits__Principal = '2000'
    if ($IsWindows) { $start.WindowStyle = 'Hidden' }
    $started = [DateTime]::UtcNow
    if ($NativeAot) {
        dotnet tests/AcceptanceHost/bin/Release/net10.0/AcceptanceHost.dll $root --prepare
        $prepared = Get-Content -LiteralPath $descriptor -Raw | ConvertFrom-Json
        $env:DARKVAULT_DATA = Split-Path $prepared.tokenFile -Parent
        $env:ASPNETCORE_URLS = $prepared.url
        $env:Kestrel__Certificates__Default__Path = Join-Path $env:DARKVAULT_DATA 'server.pfx'
        $start.FilePath = $nativeServer
        $start.ArgumentList = @('serve')
    }
    $hostProcess = Start-Process @start
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
    if ($NativeAot) { dotnet tests/AcceptanceHost/bin/Release/net10.0/AcceptanceHost.dll $root --check }
    $previousCa = $env:NODE_EXTRA_CA_CERTS
    try {
        $env:NODE_EXTRA_CA_CERTS = (Get-Content -LiteralPath $descriptor -Raw | ConvertFrom-Json).ca
        & $Node --test clients/typescript/test/client.test.js
    } finally { $env:NODE_EXTRA_CA_CERTS = $previousCa }
    Push-Location clients/go
    try { go test -count=1 ./... } finally { Pop-Location }
    Push-Location cli
    try { go test -count=1 ./... } finally { Pop-Location }
    & $pythonExecutable -m build clients/python --outdir artifacts/python
    $pythonConsumer = Join-Path $artifacts 'python-consumer'
    $consumerExecutable = Join-Path $pythonConsumer $(if ($IsWindows) { 'Scripts/python.exe' } else { 'bin/python' })
    if (!(Test-Path -LiteralPath $consumerExecutable)) { & $Python -m venv $pythonConsumer }
    $wheel = Get-ChildItem artifacts/python -File -Filter 'darkvault_client-*.whl' | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if (!$wheel) { throw 'Python wheel was not produced.' }
    & $consumerExecutable -m pip install --force-reinstall $wheel.FullName
    & $consumerExecutable -I -m unittest discover -s clients/python/tests -v
    Push-Location admin
    try { & $Node node_modules/@playwright/test/cli.js test } finally { Pop-Location }
    if ($NativeAot) {
        Stop-Process -Id $hostProcess.Id
        $hostProcess.WaitForExit()
        & $nativeServer verify
        & $nativeServer rotate-data
        & $nativeServer rotate-transport
        & $nativeServer verify
    }
    dotnet publish server/DarkVault.Server/DarkVault.Server.csproj -c Release --no-restore -o artifacts/server
    dotnet pack clients/csharp/DarkVault.Client/DarkVault.Client.csproj -c Release --no-restore -o artifacts/packages
    dotnet pack clients/csharp/DarkVault.Extensions.Configuration/DarkVault.Extensions.Configuration.csproj -c Release --no-restore -o artifacts/packages
    & $Pnpm --dir clients/typescript pack --pack-destination (Join-Path $artifacts 'typescript')
    Write-Output 'Verification completed, including SDK packages. Only temporary test state was used.'
} finally {
    if ($hostProcess -and !$hostProcess.HasExited) { Stop-Process -Id $hostProcess.Id }
    if ($started -and (Test-Path -LiteralPath $descriptor) -and (Get-Item -LiteralPath $descriptor).LastWriteTimeUtc -ge $started) {
        $testState = Get-Content -LiteralPath $descriptor -Raw | ConvertFrom-Json
        $statePath = [IO.Path]::GetFullPath((Split-Path $testState.tokenFile -Parent))
        $localRoot = [IO.Path]::GetFullPath((Join-Path $root '.local'))
        if ((Split-Path $statePath -Parent) -ne $localRoot -or (Split-Path $statePath -Leaf) -notmatch '^acceptance-[a-f0-9]{32}$') {
            throw 'Unexpected acceptance state path; cleanup refused.'
        }
        if ((Get-Item -LiteralPath $statePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected acceptance state link.' }
        if ($hostProcess) { $hostProcess.WaitForExit() }
        Remove-Item -LiteralPath $statePath -Recurse -Force
        Remove-Item -LiteralPath $descriptor -Force
    }
    $env:DARKVAULT_ACCEPTANCE = $oldAcceptance
    $env:DARKVAULT_DATA, $env:ASPNETCORE_URLS, $env:Kestrel__Certificates__Default__Path = $oldData, $oldUrls, $oldCertificate
    $env:Security__RateLimits__Ip, $env:Security__RateLimits__Principal = $oldIpQuota, $oldPrincipalQuota
    Pop-Location
}
