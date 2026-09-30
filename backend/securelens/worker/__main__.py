"""``securelens-worker`` — processes queued scans and other background jobs."""

from __future__ import annotations

import argparse
import logging
import os
import socket

from securelens.core import database


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securelens-worker", description="Run SecureLens background jobs.")
    parser.add_argument("--once", action="store_true", help="process the queued jobs, then exit")
    parser.add_argument("--max-jobs", type=int, default=100, help="with --once: stop after N jobs")
    parser.add_argument("--kinds", help="comma-separated job kinds to process (default: all)")
    parser.add_argument("--no-sandbox", action="store_true",
                        help="analyse in-process (development only; production always uses the sandbox)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=os.environ.get("SECURELENS_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    from securelens.core.config import get_settings
    from securelens.worker.runner import process_available_jobs, run_forever

    settings = get_settings()
    if args.no_sandbox and settings.environment == "production":
        parser.error("--no-sandbox is not allowed in production")
    database.configure()
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    kinds = {k.strip().upper() for k in args.kinds.split(",")} if args.kinds else None
    if args.once:
        count = process_available_jobs(worker_id, max_jobs=args.max_jobs, sandbox=not args.no_sandbox, kinds=kinds)
        logging.getLogger("securelens.worker").info("processed %d job(s)", count)
        return 0
    run_forever(worker_id, sandbox=not args.no_sandbox, kinds=kinds)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
