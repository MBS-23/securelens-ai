"""Runs source analysis in an isolated child process with resource limits.

The worker never parses untrusted code in its own process. Each analysis runs
in ``python -m securelens.worker.sandbox_entry`` with:

* RLIMIT_AS / RLIMIT_CPU / RLIMIT_FSIZE / RLIMIT_NOFILE / RLIMIT_CORE limits,
* a wall-clock timeout that kills the whole process group,
* an environment stripped of every secret (no database URL, keys or tokens),
* an empty temporary working directory.

In containers the worker additionally runs as an unprivileged user with a
read-only root filesystem (see docker-compose.yml). This is defence in depth;
analysis only parses code and never executes it.
"""

from __future__ import annotations

import contextlib
import json
import os
import resource
import signal
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from securelens.findings.model import ScanResult
from securelens.scanners.base import ScanOptions


class SandboxError(Exception):
    pass


@dataclass
class SandboxLimits:
    timeout_seconds: int = 900
    memory_mb: int = 2048
    max_output_mb: int = 512
    max_open_files: int = 1024


def _options_to_dict(options: ScanOptions) -> dict:
    data = asdict(options)
    data["scanners"] = sorted(options.scanners)
    data["offline_db"] = str(options.offline_db) if options.offline_db else None
    data["secret_hash_key"] = options.secret_hash_key.hex()
    return data


def options_from_dict(data: dict) -> ScanOptions:
    data = dict(data)
    data["scanners"] = set(data.get("scanners", []))
    data["offline_db"] = Path(data["offline_db"]) if data.get("offline_db") else None
    data["secret_hash_key"] = bytes.fromhex(data.get("secret_hash_key", ""))
    return ScanOptions(**data)


def _preexec(limits: SandboxLimits):
    def apply() -> None:  # pragma: no cover - runs in the child
        os.setsid()
        memory = limits.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CPU, (limits.timeout_seconds, limits.timeout_seconds + 5))
        size = limits.max_output_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
        resource.setrlimit(resource.RLIMIT_NOFILE, (limits.max_open_files, limits.max_open_files))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def _child_env(home: str) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}
    if os.environ.get("VIRTUAL_ENV"):
        env["VIRTUAL_ENV"] = os.environ["VIRTUAL_ENV"]
    # PYTHONPATH lets an uninstalled checkout import the package; never secrets.
    package_root = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = package_root
    return env


def run_isolated(root: Path, options: ScanOptions, target: str, limits: SandboxLimits) -> ScanResult:
    with tempfile.TemporaryDirectory(prefix="securelens-sandbox-") as work:
        spec_path = Path(work) / "spec.json"
        out_path = Path(work) / "result.json"
        spec_path.write_text(json.dumps({"root": str(root), "target": target, "options": _options_to_dict(options),
                                         "output": str(out_path)}))
        cmd = [sys.executable, "-B", "-m", "securelens.worker.sandbox_entry", str(spec_path)]
        proc = subprocess.Popen(cmd, cwd=work, env=_child_env(work), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=_preexec(limits))
        try:
            _, stderr = proc.communicate(timeout=limits.timeout_seconds + 30)
        except subprocess.TimeoutExpired as exc:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise SandboxError(f"analysis exceeded the {limits.timeout_seconds}s time limit") from exc
        if proc.returncode != 0:
            reason = "resource limit reached" if proc.returncode < 0 else "analysis process failed"
            tail = (stderr or b"").decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
            raise SandboxError(f"{reason} (exit {proc.returncode}) {tail[0][:300]}".strip())
        try:
            return ScanResult.model_validate_json(out_path.read_text("utf-8"))
        except (OSError, ValueError) as exc:
            raise SandboxError("analysis produced invalid output") from exc
