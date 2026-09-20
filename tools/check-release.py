"""Validate release versions, provenance and checksums before publication."""
import hashlib
import json
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from email.parser import BytesParser
from pathlib import Path

RUNTIMES = ("linux-x64", "linux-arm64", "win-x64", "win-arm64", "osx-x64", "osx-arm64")


def check_server(path: Path, runtime: str, tag: str, commit: str, dirty: bool) -> None:
    if not __debug__:
        raise RuntimeError("Release verification requires Python assertions enabled")
    assert runtime in RUNTIMES
    contents, modes = {}, {}
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    continue
                name = item.filename.removeprefix("./")
                assert name not in contents, "Duplicate archive member"
                contents[name] = archive.read(item)
    else:
        with tarfile.open(path) as archive:
            for item in archive:
                if item.isdir():
                    continue
                assert item.isfile(), "Native archives must not contain links"
                name = item.name.removeprefix("./")
                assert name not in contents, "Duplicate archive member"
                contents[name] = archive.extractfile(item).read()
                modes[name] = item.mode
    binary_name = "DarkVault.Server.exe" if runtime.startswith("win-") else "DarkVault.Server"
    sqlite = "e_sqlite3.dll" if runtime.startswith("win-") else ("libe_sqlite3.dylib" if runtime.startswith("osx-") else "libe_sqlite3.so")
    static = {"wwwroot/index.html", "wwwroot/app.js", "wwwroot/style.css"}
    required = {binary_name, sqlite, "LICENSE", "build.json"} | static
    optional = {name + suffix for name in static for suffix in (".br", ".gz")}
    assert required <= contents.keys(), f"Missing native runtime files: {runtime}"
    assert contents.keys() <= required | optional, f"Unexpected native runtime files: {runtime}"
    assert all(contents.values()), "Empty native runtime file"
    metadata = json.loads(contents["build.json"])
    assert metadata["version"] == tag[1:] and metadata["commit"] == commit
    assert metadata["runtime"] == runtime and metadata["compilation"] == "native-aot"
    assert metadata["dirty"] is dirty
    assert metadata["files"].keys() == contents.keys() - {"build.json"}
    for name, digest in metadata["files"].items():
        assert hashlib.sha256(contents[name]).hexdigest() == digest, name
    binary = contents[binary_name]
    arm = runtime.endswith("arm64")
    if runtime.startswith("win-"):
        assert binary[:2] == b"MZ"
        pe = struct.unpack_from("<I", binary, 0x3C)[0]
        assert binary[pe:pe + 4] == b"PE\0\0"
        assert struct.unpack_from("<H", binary, pe + 4)[0] == (0xAA64 if arm else 0x8664), "Wrong PE architecture"
    elif runtime.startswith("linux-"):
        assert binary[:6] == b"\x7fELF\x02\x01"
        assert struct.unpack_from("<H", binary, 18)[0] == (183 if arm else 62), "Wrong ELF architecture"
    else:
        assert binary[:4] == b"\xcf\xfa\xed\xfe"
        assert struct.unpack_from("<I", binary, 4)[0] == (0x0100000C if arm else 0x01000007), "Wrong Mach-O architecture"
    if not runtime.startswith("win-"):
        assert modes[binary_name] & 0o111, "Server is not executable"


def check_servers(assets: Path, tag: str, commit: str, dirty: bool) -> None:
    if not __debug__:
        raise RuntimeError("Release verification requires Python assertions enabled")
    expected = {f"darkvault-server-{tag}-{runtime}." + ("zip" if runtime.startswith("win-") else "tar.gz") for runtime in RUNTIMES}
    assert {p.name for p in assets.iterdir()} == expected, "Expected exactly six native server archives"
    for runtime in RUNTIMES:
        extension = "zip" if runtime.startswith("win-") else "tar.gz"
        check_server(assets / f"darkvault-server-{tag}-{runtime}.{extension}", runtime, tag, commit, dirty)


def check(assets: Path, tag: str, commit: str) -> None:
    if not __debug__:
        raise RuntimeError("Release verification requires Python assertions enabled")
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("Invalid release tag")
    version = tag[1:]
    metadata = json.loads((assets / "release.json").read_text())
    assert metadata["version"] == version and metadata["commit"] == commit
    assert metadata["protocolVersion"] == 1 and type(metadata["dirty"]) is bool
    runtimes = RUNTIMES
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
            assert document.find(".//{*}id").text == package
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
        assert headers["Name"] == "darkvault-client"
        assert headers["Version"] == version
        assert f"Source, https://github.com/Bobsans/DarkVault/tree/{commit}" in headers.get_all("Project-URL", [])
    with tarfile.open(assets / f"darkvault-client-{version}.tgz") as archive:
        npm = json.load(archive.extractfile("package/package.json"))
        assert npm["name"] == "@darkvault/client"
        assert npm["version"] == version and npm["gitHead"] == commit
        assert archive.getmember("package/dist/index.d.ts").size > 0
    with tarfile.open(assets / f"darkvault-go-{tag}.tar.gz") as archive:
        assert json.load(archive.extractfile("release.json")) == metadata

    for runtime in runtimes:
        extension = "zip" if runtime.startswith("win-") else "tar.gz"
        for component in ("server", "cli"):
            path = assets / f"darkvault-{component}-{tag}-{runtime}.{extension}"
            if component == "server":
                check_server(path, runtime, tag, commit, metadata["dirty"])
                continue
            member = "darkvault.exe" if runtime.startswith("win-") else "darkvault"
            if extension == "zip":
                with zipfile.ZipFile(path) as archive:
                    data = archive.read(member)
            else:
                with tarfile.open(path) as archive:
                    data = archive.extractfile("./" + member).read()
            assert f"release:{version}+{commit}\0".encode() in data, runtime
            with tempfile.TemporaryDirectory() as directory:
                binary = Path(directory) / member
                binary.write_bytes(data)
                info = subprocess.check_output(["go", "version", "-m", str(binary)], text=True)
            settings = info.replace('"', '').split()
            assert f"vcs.revision={commit}" in settings, runtime
    print(f"Verified {tag}: all 18 packages, commit {commit}, manifest and checksums.")


if __name__ == "__main__":
    if sys.argv[1] == "--server":
        assert sys.argv[6] in ("true", "false")
        check_server(Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6] == "true")
    elif sys.argv[1] == "--servers":
        assert sys.argv[5] in ("true", "false")
        check_servers(Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5] == "true")
    else:
        check(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
