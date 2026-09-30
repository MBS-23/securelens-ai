"""Safe ingestion of untrusted source code: archives, single files and git clones.

Uploaded code is untrusted. Extraction therefore:

* rejects absolute paths, drive letters, ``..`` components and NUL bytes (Zip Slip);
* skips symbolic links, hard links and device entries;
* enforces limits on entry count, total size and per-entry compression ratio,
  and counts the bytes actually written so lying headers cannot bypass them;
* writes files without execute permission and never extracts nested archives;
* strips a single common top-level directory so paths stay stable across
  re-uploads (important for retest fingerprints).

Nothing is ever executed.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

CHUNK = 1024 * 1024
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._ -]{1,200}$")


class IngestError(Exception):
    """Raised when input is rejected; the message is safe to show to users."""


@dataclass
class Limits:
    max_files: int = 20000
    max_total_bytes: int = 250 * 1024 * 1024
    max_file_bytes: int = 50 * 1024 * 1024
    max_ratio: int = 200


@dataclass
class IngestReport:
    files: int = 0
    total_bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    stripped_prefix: str | None = None
    commit: str | None = None


def _clean_member_path(name: str) -> str | None:
    name = name.replace("\\", "/")
    if "\x00" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def _common_prefix(paths: list[str]) -> str | None:
    tops = {p.split("/", 1)[0] for p in paths}
    if len(tops) == 1 and all("/" in p for p in paths):
        return next(iter(tops))
    return None


def _write_limited(src, dest: Path, declared: int, limits: Limits, budget_left: int) -> int:
    allowed = min(limits.max_file_bytes, budget_left)
    written = 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "xb") as out:
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > allowed:
                raise IngestError("Archive exceeds the extracted size limit")
            if declared >= 0 and written > declared + 1024:
                raise IngestError("Archive entry is larger than declared (possible archive bomb)")
            out.write(chunk)
    os.chmod(dest, 0o640)
    return written


def extract_zip(archive: Path, dest: Path, limits: Limits) -> IngestReport:
    report = IngestReport()
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise IngestError("The file is not a valid ZIP archive") from exc
    with zf:
        members = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode and mode not in (stat.S_IFREG,):
                report.skipped.append(f"{info.filename}: not a regular file (symlink or special)")
                continue
            clean = _clean_member_path(info.filename)
            if clean is None:
                raise IngestError(f"Unsafe path in archive: {info.filename[:200]!r}")
            members.append((info, clean))
        if len(members) > limits.max_files:
            raise IngestError(f"Archive contains more than {limits.max_files} files")
        declared_total = sum(i.file_size for i, _ in members)
        if declared_total > limits.max_total_bytes:
            raise IngestError("Archive exceeds the extracted size limit")
        for info, _ in members:
            ratio = info.file_size / max(info.compress_size, 1)
            if info.compress_size and ratio > limits.max_ratio and info.file_size > 1024 * 1024:
                raise IngestError("Archive has a suspicious compression ratio (possible archive bomb)")
        prefix = _common_prefix([c for _, c in members])
        report.stripped_prefix = prefix
        for info, clean in members:
            rel = clean[len(prefix) + 1:] if prefix else clean
            target = dest / rel
            if target.exists():
                report.skipped.append(f"{rel}: duplicate entry")
                continue
            with zf.open(info) as src:
                report.total_bytes += _write_limited(src, target, info.file_size, limits,
                                                     limits.max_total_bytes - report.total_bytes)
            report.files += 1
    return report


def extract_tar(archive: Path, dest: Path, limits: Limits) -> IngestReport:
    report = IngestReport()
    try:
        tf = tarfile.open(archive, mode="r:*")  # noqa: SIM115 - closed by the `with` block below
    except (tarfile.TarError, OSError) as exc:
        raise IngestError("The file is not a valid TAR archive") from exc
    with tf:
        members = []
        count = 0
        for member in tf:
            count += 1
            if count > limits.max_files * 2:
                raise IngestError(f"Archive contains more than {limits.max_files} files")
            if member.isdir():
                continue
            if not member.isfile():
                report.skipped.append(f"{member.name}: not a regular file (link or device)")
                continue
            clean = _clean_member_path(member.name)
            if clean is None:
                raise IngestError(f"Unsafe path in archive: {member.name[:200]!r}")
            members.append((member, clean))
        if len(members) > limits.max_files:
            raise IngestError(f"Archive contains more than {limits.max_files} files")
        if sum(m.size for m, _ in members) > limits.max_total_bytes:
            raise IngestError("Archive exceeds the extracted size limit")
        prefix = _common_prefix([c for _, c in members])
        report.stripped_prefix = prefix
        for member, clean in members:
            rel = clean[len(prefix) + 1:] if prefix else clean
            target = dest / rel
            if target.exists():
                continue
            src = tf.extractfile(member)
            if src is None:
                continue
            with src:
                report.total_bytes += _write_limited(src, target, member.size, limits,
                                                     limits.max_total_bytes - report.total_bytes)
            report.files += 1
    return report


def sanitize_filename(name: str) -> str:
    base = PurePosixPath(name.replace("\\", "/")).name
    if not base or base in {".", ".."} or not _SAFE_NAME.match(base):
        raise IngestError("Invalid file name; use letters, digits, dot, dash, underscore or space")
    return base


def is_archive(filename: str) -> bool:
    lower = filename.lower()
    return lower.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"))


def materialize_upload(upload: Path, original_name: str, dest: Path, limits: Limits) -> IngestReport:
    dest.mkdir(parents=True, exist_ok=True)
    lower = original_name.lower()
    if lower.endswith(".zip"):
        return extract_zip(upload, dest, limits)
    if lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        return extract_tar(upload, dest, limits)
    name = sanitize_filename(original_name)
    size = upload.stat().st_size
    if size > limits.max_file_bytes:
        raise IngestError("File exceeds the size limit")
    shutil.copyfile(upload, dest / name)
    os.chmod(dest / name, 0o640)
    return IngestReport(files=1, total_bytes=size)


def copy_tree(src: Path, dest: Path) -> None:
    """Copy a snapshot (regular files only, no symlinks)."""
    for path in src.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        target = dest / path.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        os.chmod(target, 0o640)


# ------------------------------------------------------------------ git


def clone_repository(url: str, branch: str | None, dest: Path, *, allowed_hosts: list[str], timeout: int,
                     limits: Limits, token: str | None = None) -> IngestReport:
    """Shallow-clone an allow-listed HTTPS repository with hardened git settings."""
    parts = urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in {h.lower() for h in allowed_hosts}:
        raise IngestError("Repository URL is not allowed")
    if parts.username or parts.password:
        raise IngestError("Repository URL must not contain credentials")
    if branch is not None and (branch.startswith("-") or ".." in branch or not re.match(r"^[A-Za-z0-9._/-]+$", branch)):
        raise IngestError("Invalid branch name")
    git = shutil.which("git")
    if git is None:
        raise IngestError("git is not available on this worker")
    with tempfile.TemporaryDirectory(prefix="securelens-git-") as home:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": home,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
        for var in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "GIT_SSL_CAINFO"):
            if var in os.environ:
                env[var] = os.environ[var]
        cmd = [git, "-c", "core.symlinks=false", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
               "-c", "protocol.ext.allow=never", "-c", "transfer.fsckObjects=true", "-c", "submodule.recurse=false"]
        if token:
            # Passed as a header for this one command; never written into the URL or config files.
            import base64

            basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
            cmd += ["-c", f"http.extraHeader=Authorization: Basic {basic}"]
        cmd += ["clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules"]
        if branch:
            cmd += ["--branch", branch]
        cmd += ["--", url, str(dest)]
        try:
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout, check=False,
                                  stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(dest, ignore_errors=True)
            raise IngestError("git clone timed out") from exc
        if proc.returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            detail = (proc.stderr or "").strip().splitlines()[-1:] or ["unknown error"]
            safe = detail[0].replace(token, "***") if token else detail[0]
            raise IngestError(f"git clone failed: {safe[:300]}")
        commit = subprocess.run([git, "-C", str(dest), "rev-parse", "HEAD"], env=env, capture_output=True, text=True,
                                timeout=30, check=False).stdout.strip() or None
    shutil.rmtree(dest / ".git", ignore_errors=True)
    report = IngestReport(commit=commit)
    for path in dest.rglob("*"):
        if path.is_symlink():
            path.unlink()
            report.skipped.append(f"{path.relative_to(dest)}: symbolic link removed")
            continue
        if path.is_file():
            report.files += 1
            report.total_bytes += path.stat().st_size
            if report.files > limits.max_files or report.total_bytes > limits.max_total_bytes:
                shutil.rmtree(dest, ignore_errors=True)
                raise IngestError("Repository exceeds the size or file-count limit")
            os.chmod(path, 0o640)
    return report
