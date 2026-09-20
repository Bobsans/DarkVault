param(
    [Parameter(Mandatory)][string]$Tag,
    [Parameter(Mandatory)][ValidateSet('linux-x64', 'linux-arm64', 'win-x64', 'win-arm64', 'osx-x64', 'osx-arm64')][string]$Runtime
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
if ($Tag -cnotmatch '^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') { throw 'Expected vMAJOR.MINOR.PATCH.' }
$root = Split-Path $PSScriptRoot -Parent
$platform = if ($IsWindows) { 'win' } elseif ($IsMacOS) { 'osx' } else { 'linux' }
$hostRuntime = "$platform-$([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant())"
if ($Runtime -ne $hostRuntime) { throw "Package and verify $Runtime on its native host, not $hostRuntime." }
$version = $Tag.Substring(1)
$commit = git -C $root rev-parse HEAD
$dirty = [bool]@(git -C $root status --porcelain)
if ($env:GITHUB_ACTIONS -eq 'true') {
    if ($env:GITHUB_REF -ne "refs/tags/$Tag" -or $dirty -or (git -C $root rev-parse "$Tag^{commit}") -ne $commit) { throw 'Native packaging requires a clean checkout of the requested tag.' }
}
$published = Join-Path $root "artifacts/server-aot/$Runtime"
$binaryName = if ($IsWindows) { 'DarkVault.Server.exe' } else { 'DarkVault.Server' }
$sqliteName = if ($IsWindows) { 'e_sqlite3.dll' } elseif ($IsMacOS) { 'libe_sqlite3.dylib' } else { 'libe_sqlite3.so' }
$binary = Join-Path $published $binaryName
if ((& $binary --version) -cne "$version+$commit") { throw 'Published native server version does not match this tag and commit. Run verify.ps1 -NativeAot -ReleaseTag first.' }
$staging = Join-Path $root "artifacts/native-staging/$Tag/$Runtime"
$assets = Join-Path $root 'artifacts/native-assets'
$extension = if ($IsWindows) { 'zip' } else { 'tar.gz' }
$archive = Join-Path $assets "darkvault-server-$Tag-$Runtime.$extension"
if ((Test-Path -LiteralPath $staging) -or (Test-Path -LiteralPath $archive)) { throw 'Native package output already exists.' }
New-Item -ItemType Directory -Path $staging, $assets -Force | Out-Null
Copy-Item -LiteralPath $binary, (Join-Path $published $sqliteName), (Join-Path $root 'LICENSE') -Destination $staging
Copy-Item -LiteralPath (Join-Path $published 'wwwroot') -Destination $staging -Recurse
if (!$IsWindows) { chmod +x (Join-Path $staging $binaryName) }
$files = [ordered]@{}
foreach ($file in (Get-ChildItem -LiteralPath $staging -Recurse -File | Sort-Object FullName)) {
    $name = [IO.Path]::GetRelativePath($staging, $file.FullName).Replace('\', '/')
    $files[$name] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
$metadata = @{ version = $version; commit = $commit; runtime = $Runtime; compilation = 'native-aot'; dirty = $dirty; files = $files } | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText((Join-Path $staging 'build.json'), $metadata + "`n", [Text.UTF8Encoding]::new($false))
if ($IsWindows) { Compress-Archive -Path "$staging/*" -DestinationPath $archive }
else { tar -czf $archive -C $staging . }
python (Join-Path $root 'tools/check-release.py') --server $archive $Runtime $Tag $commit $dirty.ToString().ToLowerInvariant()
Write-Output "Native server package: $archive"
