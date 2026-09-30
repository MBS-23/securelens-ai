"""Builds the file inventory of a source tree, safely.

* Symbolic links are never followed (a repository could point them at /etc).
* Files above the size limit, binaries and nested archives are recorded but
  not analysed.
* The total number of files is capped.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
from pathlib import Path

from securelens.findings.model import FileRecord
from securelens.scanners.base import ScanOptions, SourceFile

LANGUAGE_BY_EXTENSION = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx",
    ".php": "php", ".phtml": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".php7": "php", ".phps": "php",
    ".java": "java", ".cs": "csharp", ".go": "go",
    ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c++": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".h": "cpp",
    # Tier 2: recognised for inventory and secret scanning; SAST plugins are on the roadmap.
    ".rb": "ruby", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift", ".rs": "rust", ".dart": "dart",
    ".scala": "scala",
}
SAST_LANGUAGES = frozenset({"python", "javascript", "typescript", "tsx", "php", "java", "csharp", "go", "c", "cpp"})
TIER2_LANGUAGES = frozenset({"ruby", "kotlin", "swift", "rust", "dart", "scala"})
ARCHIVE_EXTENSIONS = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".ear", ".whl",
                      ".egg", ".apk", ".nupkg")
BINARY_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".pdf", ".woff", ".woff2", ".ttf",
                     ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wav", ".so", ".dll", ".exe", ".dylib", ".bin",
                     ".class", ".pyc", ".pyo", ".o", ".a", ".sqlite", ".db", ".pt", ".pth", ".onnx", ".safetensors",
                     ".h5", ".pkl", ".npy", ".npz", ".parquet")


def detect_language(path: str, head: bytes) -> str | None:
    ext = os.path.splitext(path)[1].lower()
    if ext in LANGUAGE_BY_EXTENSION:
        return LANGUAGE_BY_EXTENSION[ext]
    if ext == ".inc" and head.lstrip().startswith(b"<?php"):
        return "php"
    if head.startswith(b"#!"):
        first = head.split(b"\n", 1)[0]
        if b"python" in first:
            return "python"
        if b"node" in first:
            return "javascript"
        if b"php" in first:
            return "php"
    return None


def is_binary(head: bytes) -> bool:
    if b"\x00" in head:
        return True
    if not head:
        return False
    control = sum(1 for b in head if b < 9 or (13 < b < 32))
    return control / len(head) > 0.3


class Excluder:
    def __init__(self, patterns: list[str]) -> None:
        self.dir_names = {p.rstrip("/") for p in patterns if p.endswith("/") and "/" not in p.rstrip("/")}
        self.dir_paths = [p.rstrip("/") for p in patterns if p.endswith("/") and "/" in p.rstrip("/")]
        self.globs = [p for p in patterns if not p.endswith("/")]

    def excluded_dir(self, rel_dir: str, name: str) -> bool:
        if name in self.dir_names:
            return True
        return any(rel_dir == p or rel_dir.startswith(p + "/") or fnmatch.fnmatch(rel_dir, p) for p in self.dir_paths)

    def excluded_file(self, rel_path: str) -> bool:
        base = rel_path.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(base, g) or fnmatch.fnmatch(rel_path, g) for g in self.globs)


def build_inventory(root: Path, options: ScanOptions) -> tuple[list[SourceFile], list[FileRecord], list[str]]:
    root = root.resolve()
    files: list[SourceFile] = []
    records: list[FileRecord] = []
    errors: list[str] = []
    excluder = Excluder(options.excludes())
    max_bytes = options.max_file_kb * 1024
    count = 0

    if root.is_file():
        entries = [(root.parent, [], [root.name])]
    else:
        entries = os.walk(root, followlinks=False)

    for dirpath, dirnames, filenames in entries:
        base = Path(dirpath)
        rel_dir = base.relative_to(root.parent if root.is_file() else root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        kept = []
        for d in sorted(dirnames):
            full = base / d
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if full.is_symlink():
                records.append(FileRecord(path=rel, status="EXCLUDED", detail="symbolic link (not followed)"))
            elif not excluder.excluded_dir(rel, d):
                kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            full = base / name
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if full.is_symlink():
                records.append(FileRecord(path=rel, status="EXCLUDED", detail="symbolic link (not followed)"))
                continue
            if excluder.excluded_file(rel):
                records.append(FileRecord(path=rel, status="EXCLUDED", detail="matches exclude pattern"))
                continue
            if count >= options.max_files:
                errors.append(f"file limit of {options.max_files} reached; remaining files were not analysed")
                return files, records, errors
            count += 1
            try:
                size = full.stat().st_size
            except OSError as exc:
                records.append(FileRecord(path=rel, status="PARSE_ERROR", detail=f"unreadable: {exc.strerror}"))
                continue
            lower = name.lower()
            if lower.endswith(ARCHIVE_EXTENSIONS):
                records.append(FileRecord(path=rel, size_bytes=size, status="SKIPPED_BINARY",
                                          detail="nested archive (not extracted)"))
                continue
            if lower.endswith(BINARY_EXTENSIONS):
                records.append(FileRecord(path=rel, size_bytes=size, status="SKIPPED_BINARY",
                                          detail="binary file type"))
                continue
            if size > max_bytes:
                records.append(FileRecord(path=rel, size_bytes=size, status="SKIPPED_SIZE",
                                          detail=f"larger than {options.max_file_kb} KB"))
                continue
            try:
                data = full.read_bytes()
            except OSError as exc:
                records.append(FileRecord(path=rel, size_bytes=size, status="PARSE_ERROR",
                                          detail=f"unreadable: {exc.strerror}"))
                continue
            head = data[:8192]
            if is_binary(head):
                records.append(FileRecord(path=rel, size_bytes=size, status="SKIPPED_BINARY", detail="binary content"))
                continue
            language = detect_language(rel, head)
            line_count = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
            # Text is read again on demand; holding every file in memory would not scale.
            source = SourceFile(path=rel, abs_path=full, language=language, size=size,
                                sha256=hashlib.sha256(data).hexdigest(), line_count=line_count)
            files.append(source)
            records.append(FileRecord(path=rel, language=language, size_bytes=size, line_count=source.line_count,
                                      sha256=source.sha256, status="ANALYZED"))
    return files, records, errors
