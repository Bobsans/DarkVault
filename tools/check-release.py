"""Validate release versions, provenance and checksums before publication."""
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from email.parser import BytesParser
from pathlib import Path


def check(assets: Path, tag: str, commit: str) -> None:
    if not __debug__:
        raise RuntimeError("Release verification requires Python assertions enabled")
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("Invalid release tag")
    version = tag[1:]
    metadata = json.loads((assets / "release.json").read_text())
    assert metadata["version"] == version and metadata["commit"] == commit
    assert metadata["protocolVersion"] == 1 and type(metadata["dirty"]) is bool
    runtimes = ("linux-x64", "linux-arm64", "win-x64", "win-arm64", "osx-x64", "osx-arm64")
    packages = ("DarkVault.Client", "DarkVault.Extensions.Configuration")
    expected = {"release.json", "SHA256SUMS", f"darkvault-go-{tag}.tar.gz",
                f"darkvault-client-{version}.tgz", f"darkvault_client-{version}.tar.gz",
                f"darkvault_client-{version}-py3-none-any.whl"}
    expected.update(f"{package}.{version}.nupkg" for package in packages)
    for runtime in runtimes:
        extension = "zip" if runtime.startswith("win-") else "tar.gz"
        expected.update(f"darkvault-{component}-{tag}-{runtime}.{extension}" for component in ("server", "cli"))
    assert {path.name for path in assets.iterdir()} == expected, "Unexpected release asset set"
    checksums = {}
    for line in (assets / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert name not in checksums, "Duplicate checksum"
        checksums[name] = digest
    assert set(checksums) == expected - {"SHA256SUMS"}
    for name, digest in checksums.items():
        assert hashlib.sha256((assets / name).read_bytes()).hexdigest() == digest, name

    for package in packages:
        with zipfile.ZipFile(assets / f"{package}.{version}.nupkg") as archive:
            document = ET.fromstring(archive.read(f"{package}.nuspec"))
            assert document.find(".//{*}version").text == version, package
            assert document.find(".//{*}repository").get("commit") == commit, package
            for dependency in document.findall(".//{*}dependency"):
                if dependency.get("id") == "DarkVault.Client":
                    assert dependency.get("version") == version, "Mismatched SDK dependency"
    with zipfile.ZipFile(assets / f"darkvault_client-{version}-py3-none-any.whl") as archive:
        python_metadata = archive.read(f"darkvault_client-{version}.dist-info/METADATA")
    with tarfile.open(assets / f"darkvault_client-{version}.tar.gz") as archive:
        source_metadata = archive.extractfile(f"darkvault_client-{version}/PKG-INFO").read()
    for contents in (python_metadata, source_metadata):
        headers = BytesParser().parsebytes(contents)
        assert headers["Version"] == version
        assert f"Source, https://github.com/Bobsans/DarkVault/tree/{commit}" in headers.get_all("Project-URL", [])
    with tarfile.open(assets / f"darkvault-client-{version}.tgz") as archive:
        npm = json.load(archive.extractfile("package/package.json"))
        assert npm["version"] == version and npm["gitHead"] == commit
        assert archive.getmember("package/dist/index.d.ts").size > 0
    with tarfile.open(assets / f"darkvault-go-{tag}.tar.gz") as archive:
        assert json.load(archive.extractfile("release.json")) == metadata

    for runtime in runtimes:
        extension = "zip" if runtime.startswith("win-") else "tar.gz"
        for component in ("server", "cli"):
            path = assets / f"darkvault-{component}-{tag}-{runtime}.{extension}"
            member = "DarkVault.Server.deps.json" if component == "server" else ("darkvault.exe" if runtime.startswith("win-") else "darkvault")
            if extension == "zip":
                with zipfile.ZipFile(path) as archive:
                    data = archive.read(member)
            else:
                with tarfile.open(path) as archive:
                    data = archive.extractfile("./" + member).read()
            if component == "server":
                assert f"DarkVault.Server/{version}" in json.loads(data)["libraries"], runtime
            else:
                assert f"release:{version}+{commit}\0".encode() in data, runtime
                with tempfile.TemporaryDirectory() as directory:
                    binary = Path(directory) / member
                    binary.write_bytes(data)
                    info = subprocess.check_output(["go", "version", "-m", str(binary)], text=True)
                settings = info.replace('"', '').split()
                assert f"vcs.revision={commit}" in settings, runtime
    print(f"Verified {tag}: all 18 packages, commit {commit}, manifest and checksums.")


if __name__ == "__main__":
    check(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
