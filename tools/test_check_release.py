"""Native archive acceptance/rejection tests; synthetic headers are not runnable builds."""
import hashlib
import io
import json
import runpy
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

checker = runpy.run_path(str(Path(__file__).with_name("check-release.py")))
TAG, COMMIT = "v1.2.3", "a" * 40


def archive(root, runtime, *, actual_runtime=None, change=None, executable=True):
    actual_runtime = actual_runtime or runtime
    binary = bytearray(256)
    arm = actual_runtime.endswith("arm64")
    if actual_runtime.startswith("win-"):
        binary[:2] = b"MZ"
        struct.pack_into("<I", binary, 0x3C, 64)
        binary[64:68] = b"PE\0\0"
        struct.pack_into("<H", binary, 68, 0xAA64 if arm else 0x8664)
    elif actual_runtime.startswith("linux-"):
        binary[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", binary, 18, 183 if arm else 62)
    else:
        binary[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", binary, 4, 0x0100000C if arm else 0x01000007)
    name = "DarkVault.Server.exe" if runtime.startswith("win-") else "DarkVault.Server"
    sqlite = "e_sqlite3.dll" if runtime.startswith("win-") else ("libe_sqlite3.dylib" if runtime.startswith("osx-") else "libe_sqlite3.so")
    files = {name: bytes(binary), sqlite: b"test-library", "LICENSE": b"test-license",
             "wwwroot/index.html": b"<html></html>", "wwwroot/app.js": b"app", "wwwroot/style.css": b"css"}
    metadata = {"version": TAG[1:], "commit": COMMIT, "runtime": runtime, "compilation": "native-aot", "dirty": False,
                "files": {key: hashlib.sha256(value).hexdigest() for key, value in files.items()}}
    if change:
        change(files, metadata)
    files["build.json"] = json.dumps(metadata).encode()
    path = root / f"darkvault-server-{TAG}-{runtime}.{'zip' if runtime.startswith('win-') else 'tar.gz'}"
    if runtime.startswith("win-"):
        with zipfile.ZipFile(path, "w") as output:
            for key, value in files.items():
                output.writestr(key, value)
    else:
        with tarfile.open(path, "w:gz") as output:
            for key, value in files.items():
                entry = tarfile.TarInfo("./" + key)
                entry.size = len(value)
                entry.mode = 0o755 if key == name and executable else 0o644
                output.addfile(entry, io.BytesIO(value))
    return path


class NativeArchives(unittest.TestCase):
    def test_all_six_formats_and_missing_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for runtime in checker["RUNTIMES"]:
                archive(root, runtime)
            checker["check_servers"](root, TAG, COMMIT, False)
            next(root.glob("*win-arm64*")).unlink()
            with self.assertRaises(AssertionError):
                checker["check_servers"](root, TAG, COMMIT, False)

    def test_rejects_wrong_architecture_even_with_matching_manifest(self):
        for runtime in ("win-x64", "linux-x64", "osx-x64"):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as directory:
                path = archive(Path(directory), runtime, actual_runtime=runtime.replace("x64", "arm64"))
                with self.assertRaises(AssertionError):
                    checker["check_server"](path, runtime, TAG, COMMIT, False)

    def test_rejects_mixed_builds_tampering_managed_files_and_missing_spa(self):
        mutations = [
            lambda files, meta: meta.update(commit="b" * 40),
            lambda files, meta: meta.update(version="1.2.4"),
            lambda files, meta: meta.update(dirty=True),
            lambda files, meta: meta.update(runtime="win-arm64"),
            lambda files, meta: meta.update(compilation="self-contained"),
            lambda files, meta: files.update({"wwwroot/app.js": b"tampered"}),
            lambda files, meta: files.update({"DarkVault.Server.dll": b"managed"}),
            lambda files, meta: files.update({"DarkVault.Server.pdb": b"symbols"}),
            lambda files, meta: files.pop("wwwroot/index.html"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                path = archive(Path(directory), "win-x64", change=mutation)
                with self.assertRaises(AssertionError):
                    checker["check_server"](path, "win-x64", TAG, COMMIT, False)

    def test_rejects_lost_unix_execute_permission(self):
        with tempfile.TemporaryDirectory() as directory:
            path = archive(Path(directory), "linux-arm64", executable=False)
            with self.assertRaises(AssertionError):
                checker["check_server"](path, "linux-arm64", TAG, COMMIT, False)


if __name__ == "__main__":
    unittest.main()
