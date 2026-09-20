param(
    [Parameter(Mandatory)][string]$Tag
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
if ($Tag -cnotmatch '^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
    throw 'Release tags must use vMAJOR.MINOR.PATCH, for example v1.0.0.'
}
$version = $Tag.Substring(1)
$root = Split-Path $PSScriptRoot -Parent
$commit = git -C $root rev-parse HEAD
$dirty = [bool]@(git -C $root status --porcelain)
if ($env:GITHUB_ACTIONS -eq 'true') {
    if ($env:GITHUB_REF -ne "refs/tags/$Tag" -or $dirty) { throw 'Release requires a clean checkout of the requested tag.' }
    if ((git -C $root rev-parse "$Tag^{commit}") -ne $commit) { throw 'Tag does not match the checkout.' }
}
$major = [int]$version.Split('.')[0]
$goModule = (Select-String -LiteralPath (Join-Path $root 'clients/go/go.mod') -Pattern '^module (.+)$').Matches[0].Groups[1].Value
if ($major -ge 2 -and !$goModule.EndsWith("/v$major")) { throw "Go SDK module path must end with /v$major for this major release." }
$output = Join-Path $root "artifacts/releases/$Tag"
if (Test-Path -LiteralPath $output) { throw "Release output already exists: $output" }
$assets = Join-Path $output 'assets'
New-Item -ItemType Directory -Path $assets -Force | Out-Null
$metadata = @{ version = $version; commit = $commit; dirty = $dirty; protocolVersion = 1 } | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $assets 'release.json'), $metadata + "`n", [Text.UTF8Encoding]::new($false))
$pythonProject = Join-Path $root 'clients/python/pyproject.toml'
$originalPythonProject = [IO.File]::ReadAllBytes($pythonProject)
$typescriptProject = Join-Path $root 'clients/typescript/package.json'
$originalTypescriptProject = [IO.File]::ReadAllBytes($typescriptProject)
$oldGoos, $oldGoarch, $oldCgo = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
Push-Location $root
try {
    foreach ($runtime in @('linux-x64', 'linux-arm64', 'win-x64', 'win-arm64', 'osx-x64', 'osx-arm64')) {
        $platform, $architecture = $runtime.Split('-')
        $server = Join-Path $output "server/$runtime"
        dotnet publish server/DarkVault.Server/DarkVault.Server.csproj -c Release -r $runtime --self-contained true -p:Version=$version -p:SourceRevisionId=$commit -p:RepositoryCommit=$commit -o $server --disable-build-servers -warnaserror
        if ([Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $server 'DarkVault.Server.dll')).ProductVersion -ne "$version+$commit") { throw "Wrong server version for $runtime" }
        Copy-Item LICENSE $server
        $serverArchive = Join-Path $assets "darkvault-server-$Tag-$runtime"
        if ($platform -eq 'win') { Compress-Archive -Path "$server/*" -DestinationPath "$serverArchive.zip" }
        else { tar -czf "$serverArchive.tar.gz" -C $server . }

        $env:GOOS = @{ linux = 'linux'; win = 'windows'; osx = 'darwin' }[$platform]
        $env:GOARCH = if ($architecture -eq 'x64') { 'amd64' } else { 'arm64' }
        $env:CGO_ENABLED = '0'
        $cli = Join-Path $output "cli/$runtime"
        New-Item -ItemType Directory -Path $cli -Force | Out-Null
        $binary = if ($platform -eq 'win') { 'darkvault.exe' } else { 'darkvault' }
        Push-Location cli
        try { go build -trimpath -buildvcs=true "-ldflags=-s -w -X github.com/Bobsans/DarkVault/cli/cmd.Version=release:$version+$commit" -o (Join-Path $cli $binary) . }
        finally { Pop-Location }
        Copy-Item LICENSE $cli
        $cliArchive = Join-Path $assets "darkvault-cli-$Tag-$runtime"
        if ($platform -eq 'win') { Compress-Archive -Path "$cli/*" -DestinationPath "$cliArchive.zip" }
        else { tar -czf "$cliArchive.tar.gz" -C $cli . }
    }

    dotnet pack clients/csharp/DarkVault.Client/DarkVault.Client.csproj -c Release -p:Version=$version -p:SourceRevisionId=$commit -p:RepositoryCommit=$commit -o $assets --disable-build-servers -warnaserror
    dotnet pack clients/csharp/DarkVault.Extensions.Configuration/DarkVault.Extensions.Configuration.csproj -c Release -p:Version=$version -p:SourceRevisionId=$commit -p:RepositoryCommit=$commit -o $assets --disable-build-servers -warnaserror
    $pythonText = [Text.Encoding]::UTF8.GetString($originalPythonProject)
    if ([regex]::Matches($pythonText, '(?m)^version = "[^"]+"').Count -ne 1) { throw 'Expected one Python package version.' }
    $pythonText = [regex]::Replace($pythonText, '(?m)^version = "[^"]+"', "version = `"$version`"`nurls = { Source = `"https://github.com/Bobsans/DarkVault/tree/$commit`" }")
    [IO.File]::WriteAllText($pythonProject, $pythonText, [Text.UTF8Encoding]::new($false))
    python -m build clients/python --outdir $assets

    tar -czf (Join-Path $assets "darkvault-go-$Tag.tar.gz") -C clients/go LICENSE README.md go.mod go.sum client.go operations.go client_test.go operations_test.go testdata -C $assets release.json

    pnpm --dir clients/typescript install --frozen-lockfile
    $typescriptPackage = [Text.Encoding]::UTF8.GetString($originalTypescriptProject) | ConvertFrom-Json
    $typescriptPackage.version = $version
    $typescriptPackage | Add-Member -NotePropertyName gitHead -NotePropertyValue $commit -Force
    [IO.File]::WriteAllText($typescriptProject, ($typescriptPackage | ConvertTo-Json -Depth 10) + "`n", [Text.UTF8Encoding]::new($false))
    pnpm --dir clients/typescript pack --pack-destination $assets

    $files = @(Get-ChildItem -LiteralPath $assets -File | Sort-Object Name)
    if ($files.Count -ne 19) { throw "Expected 18 packages and release.json, found $($files.Count)." }
    $checksums = foreach ($file in $files) {
        if (!$file.Length) { throw "Empty release asset: $($file.Name)" }
        '{0}  {1}' -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $file.Name
    }
    [IO.File]::WriteAllText((Join-Path $assets 'SHA256SUMS'), ($checksums -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    python tools/check-release.py $assets $Tag $commit
    Write-Output "Release assets: $assets"
} finally {
    [IO.File]::WriteAllBytes($pythonProject, $originalPythonProject)
    [IO.File]::WriteAllBytes($typescriptProject, $originalTypescriptProject)
    $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $oldGoos, $oldGoarch, $oldCgo
    Pop-Location
}
