param(
    [switch]$Deb
)
$ErrorActionPreference = "Stop"
$previousGoos = $env:GOOS
$previousGoarch = $env:GOARCH
$previousCgo = $env:CGO_ENABLED
Push-Location $PSScriptRoot
try {
    $env:CGO_ENABLED = "0"
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    New-Item -ItemType Directory -Path "../artifacts/cli" -Force | Out-Null
    & go build -trimpath -ldflags="-s -w" -o "../artifacts/cli/darkvault" .
    if ($LASTEXITCODE -ne 0) { throw "CLI build failed ($LASTEXITCODE)." }
    if ($Deb) {
        & nfpm package --config nfpm.yaml --packager deb --target "../artifacts/cli"
        if ($LASTEXITCODE -ne 0) { throw "Debian packaging failed ($LASTEXITCODE)." }
    }
} finally {
    $env:GOOS = $previousGoos
    $env:GOARCH = $previousGoarch
    $env:CGO_ENABLED = $previousCgo
    Pop-Location
}
