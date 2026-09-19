param(
    [string]$Runtime = "linux-x64"
)
$ErrorActionPreference = "Stop"
$projectPath = Join-Path $PSScriptRoot "DarkVault.Server.csproj"
$outputPath = Join-Path $PSScriptRoot "../../artifacts/server/$Runtime"
& dotnet publish $projectPath -c Release -r $Runtime --self-contained false -o $outputPath --disable-build-servers
if ($LASTEXITCODE -ne 0) { throw "Server publish failed ($LASTEXITCODE)." }
Write-Output "Published to $outputPath. Run bootstrap, then configure the HTTPS reverse proxy. See docs/operations.md."
