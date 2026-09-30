"""Safe ingestion of untrusted uploads: Zip Slip, links, archive bombs, limits, git URL hardening."""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from securelens.ingest import IngestError, Limits, clone_repository, extract_tar, extract_zip, sanitize_filename


def make_zip(path: Path, entries: dict[str, bytes], *, symlinks: dict[str, str] | None = None,
             compression: int = zipfile.ZIP_DEFLATED) -> Path:
    with zipfile.ZipFile(path, "w", compression=compression) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return path


def make_tar(path: Path, entries: dict[str, bytes], *, links: dict[str, tuple[bytes, str]] | None = None) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for name, (kind, target) in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = target
            tf.addfile(info)
    return path


def test_zip_slip_is_rejected(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "a.zip", {"../../evil.py": b"x"})
    with pytest.raises(IngestError, match="Unsafe path"):
        extract_zip(archive, tmp_path / "out", Limits())
    assert not (tmp_path / "evil.py").exists()


@pytest.mark.parametrize("name", ["/etc/passwd", "C:/Windows/win.ini", "a/../../b.py", "..\\..\\win.py"])
def test_absolute_and_traversal_paths_are_rejected(tmp_path: Path, name: str) -> None:
    archive = make_zip(tmp_path / "a.zip", {name: b"x"})
    with pytest.raises(IngestError):
        extract_zip(archive, tmp_path / "out", Limits())


def test_zip_symlinks_are_skipped(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "a.zip", {"app/main.py": b"print(1)"}, symlinks={"app/link": "/etc/passwd"})
    report = extract_zip(archive, tmp_path / "out", Limits())
    out = tmp_path / "out"
    assert (out / "main.py").read_text() == "print(1)"
    assert not (out / "link").exists() and not (out / "link").is_symlink()
    assert any("symlink" in s for s in report.skipped)


def test_zip_bomb_ratio_is_rejected(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "bomb.zip", {"zeros.txt": b"\0" * (8 * 1024 * 1024)})
    with pytest.raises(IngestError, match="compression ratio"):
        extract_zip(archive, tmp_path / "out", Limits(max_ratio=100))


def test_file_count_and_size_limits(tmp_path: Path) -> None:
    many = make_zip(tmp_path / "many.zip", {f"f{i}.py": b"x" for i in range(6)})
    with pytest.raises(IngestError, match="more than 5 files"):
        extract_zip(many, tmp_path / "out1", Limits(max_files=5))
    big = make_zip(tmp_path / "big.zip", {"big.py": b"a" * 5000}, compression=zipfile.ZIP_STORED)
    with pytest.raises(IngestError, match="size limit"):
        extract_zip(big, tmp_path / "out2", Limits(max_total_bytes=1000))


def test_common_prefix_is_stripped_and_files_are_not_executable(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "a.zip", {"project-main/app.py": b"x", "project-main/pkg/db.py": b"y"})
    report = extract_zip(archive, tmp_path / "out", Limits())
    out = tmp_path / "out"
    assert report.stripped_prefix == "project-main"
    assert (out / "app.py").is_file() and (out / "pkg" / "db.py").is_file()
    for path in (out / "app.py", out / "pkg" / "db.py"):
        assert path.stat().st_mode & 0o111 == 0


def test_invalid_archive(tmp_path: Path) -> None:
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    with pytest.raises(IngestError, match="not a valid ZIP"):
        extract_zip(bad, tmp_path / "out", Limits())


def test_tar_links_and_devices_are_skipped(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", {"src/app.py": b"print(1)"},
                       links={"src/passwd": (tarfile.SYMTYPE, "/etc/passwd"),
                              "src/hard": (tarfile.LNKTYPE, "/etc/shadow")})
    report = extract_tar(archive, tmp_path / "out", Limits())
    out = tmp_path / "out"
    assert (out / "app.py").is_file()
    assert not (out / "passwd").exists() and not (out / "hard").exists()
    assert len(report.skipped) == 2


def test_tar_traversal_is_rejected(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", {"../escape.py": b"x"})
    with pytest.raises(IngestError, match="Unsafe path"):
        extract_tar(archive, tmp_path / "out", Limits())


def test_sanitize_filename() -> None:
    assert sanitize_filename("../../etc/app.py") == "app.py"
    for bad in ("", "..", "we<ird>.py", "a" * 300):
        with pytest.raises(IngestError):
            sanitize_filename(bad)


@pytest.mark.parametrize("url, branch", [
    ("http://github.com/owner/repo", None),
    ("https://evil.example.com/owner/repo", None),
    ("https://user:token@github.com/owner/repo", None),
    ("file:///etc", None),
    ("https://github.com/owner/repo", "--upload-pack=touch /tmp/pwned"),
    ("https://github.com/owner/repo", "main..evil"),
])
def test_clone_rejects_unsafe_urls_and_branches(tmp_path: Path, url: str, branch: str | None) -> None:
    with pytest.raises(IngestError):
        clone_repository(url, branch, tmp_path / "clone", allowed_hosts=["github.com"], timeout=5, limits=Limits())
    assert not (tmp_path / "clone").exists()
