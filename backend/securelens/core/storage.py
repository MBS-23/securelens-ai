"""Filesystem storage for uploads and source snapshots.

Layout under ``SECURELENS_STORAGE_DIR``::

    uploads/<upload-id>          raw uploaded archive or file, as received
    snapshots/<snapshot-id>/     extracted, validated source tree

Every path is derived from server-generated identifiers; user-supplied names
never become directory components.
"""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path
from typing import BinaryIO

from securelens.core.config import get_settings
from securelens.core.errors import AppError

CHUNK = 1024 * 1024


def root() -> Path:
    path = get_settings().storage_dir.resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def uploads_dir() -> Path:
    path = root() / "uploads"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def snapshots_dir() -> Path:
    path = root() / "snapshots"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def snapshot_path(snapshot_id: uuid.UUID) -> Path:
    return snapshots_dir() / snapshot_id.hex


def upload_path(key: str) -> Path:
    if not key or "/" in key or "\\" in key or key.startswith("."):
        raise AppError("Invalid upload key", code="invalid_upload")
    return uploads_dir() / key


def save_stream(stream: BinaryIO, max_bytes: int) -> tuple[str, int]:
    """Copy an upload to disk, enforcing the size limit while streaming."""
    key = uuid.uuid4().hex
    target = upload_path(key)
    total = 0
    try:
        with open(target, "xb") as out:
            os.chmod(target, 0o600)
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise AppError(f"Upload exceeds the limit of {max_bytes // (1024 * 1024)} MB",
                                   code="payload_too_large", status_code=413)
                out.write(chunk)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    if total == 0:
        target.unlink(missing_ok=True)
        raise AppError("The uploaded file is empty", code="empty_upload", status_code=422)
    return key, total


def safe_join(base: Path, relative: str) -> Path:
    """Join a repository-relative path to ``base`` and refuse anything that escapes it."""
    if not relative or relative.startswith(("/", "\\")) or "\x00" in relative:
        raise AppError("Invalid path", code="invalid_path", status_code=400)
    candidate = (base / relative).resolve()
    base_resolved = base.resolve()
    if candidate != base_resolved and base_resolved not in candidate.parents:
        raise AppError("Invalid path", code="invalid_path", status_code=400)
    return candidate


def remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
