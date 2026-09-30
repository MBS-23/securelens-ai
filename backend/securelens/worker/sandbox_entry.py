"""Entry point of the isolated analysis process (see ``sandbox.py``).

Reads a job spec, runs the offline part of the Application Security Engine
(inventory, SAST, secrets, dependency inventory, installed external tools) and
writes the ScanResult as JSON. It has no database access and no credentials.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from securelens.scanners.engine import analyze
from securelens.worker.sandbox import options_from_dict


def main(argv: list[str]) -> int:
    sys.setrecursionlimit(20000)
    spec = json.loads(Path(argv[1]).read_text("utf-8"))
    options = options_from_dict(spec["options"])
    result = analyze(Path(spec["root"]), options, target=spec["target"])
    Path(spec["output"]).write_text(result.model_dump_json(), encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
