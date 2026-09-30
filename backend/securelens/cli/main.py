"""The ``securelens`` command.

    securelens init [PATH] [--ci github|gitlab]   create .securelens.yml (and a CI workflow)
    securelens scan [PATH] [options]              scan source code
    securelens findings [--show ID]               list findings of the last scan / explain one
    securelens report --format FORMAT             render the last scan as JSON, SARIF, HTML or Markdown
    securelens retest [PATH] --baseline FILE      rescan and compare with an earlier report
    securelens push --server URL --project ID     upload a report to a SecureLens server
    securelens version

Exit codes: 0 success (security gate passed) · 1 security gate failed ·
2 usage or configuration error · 3 the scan could not be completed.

The CLI analyses code in-process: it parses source files and never executes
them. The server additionally isolates analysis in a sandboxed worker.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from securelens.cli import output
from securelens.cli.config import DEFAULT_CONFIG_TEXT, ConfigError, LoadedConfig
from securelens.cli.config import load as load_config
from securelens.cli.templates import GITHUB_WORKFLOW, GITLAB_CI
from securelens.enums import RetestResultKind, Severity
from securelens.findings import retest as retest_engine
from securelens.findings.gate import GatePolicy
from securelens.findings.model import ScanResult
from securelens.reporting import EXTENSIONS, build_context, render
from securelens.reporting.context import apply_gate_and_risk, gate_items
from securelens.scanners.base import ScanOptions
from securelens.version import TOOL_NAME, __version__

EXIT_OK, EXIT_GATE_FAILED, EXIT_USAGE, EXIT_ERROR = 0, 1, 2, 3
STATE_DIR = Path(".securelens")
LAST_SCAN = STATE_DIR / "last-scan.json"
MAX_REPORT_BYTES = 256 * 1024 * 1024
DEFAULT_SECRET_HASH_KEY = b"securelens-cli-secret-fingerprint-v1"
_RESULT_ORDER = {"REGRESSION": 0, "NEW": 1, "STILL_OPEN": 2, "NOT_TESTED": 3, "NOT_REPRODUCED": 4, "RESOLVED": 5}
_EXTERNAL_TOOLS = ("bandit", "semgrep", "gitleaks")


class UsageError(Exception):
    pass


# ------------------------------------------------------------------ helpers


def _csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _secret_hash_key() -> bytes:
    key = os.environ.get("SECURELENS_SECRET_HASH_KEY", "")
    return key.encode("utf-8") if key else DEFAULT_SECRET_HASH_KEY


def _write(path: str | Path, text: str) -> None:
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _load_report(path: str | Path) -> ScanResult:
    source = Path(path)
    if not source.is_file():
        raise UsageError(f"report not found: {source} (run `securelens scan` first, or pass --input)")
    if source.stat().st_size > MAX_REPORT_BYTES:
        raise UsageError(f"{source} is too large to be a SecureLens report")
    try:
        return ScanResult.model_validate_json(source.read_text("utf-8"))
    except ValueError as exc:
        raise UsageError(f"{source} is not a SecureLens JSON report") from exc


def _scan_options(cfg: LoadedConfig, args: argparse.Namespace) -> ScanOptions:
    data = cfg.data
    scanners = set(_csv(args.scanners)) if args.scanners else set(data.scan.scanners)
    unknown = scanners - {"sast", "secrets", "dependencies"}
    if unknown or not scanners:
        raise UsageError("--scanners takes a comma-separated list of: sast, secrets, dependencies")
    external = {} if (args.no_external or data.scan.external == "off") else dict.fromkeys(_EXTERNAL_TOOLS, "auto")
    source = args.vuln_source or data.dependencies.source
    offline: Path | None = None
    if args.offline_db:
        offline = Path(args.offline_db)
    elif data.dependencies.offline_db:
        offline = Path(data.dependencies.offline_db)
        if not offline.is_absolute() and cfg.path is not None:
            offline = cfg.path.parent / offline
    if source == "offline":
        if offline is None:
            raise UsageError("an offline advisory directory is required: --offline-db DIR or dependencies.offline_db")
        if not offline.is_dir():
            raise UsageError(f"offline advisory directory not found: {offline}")
    return ScanOptions(scanners=scanners, external=external, exclude=[*data.scan.exclude, *args.exclude],
                       max_file_kb=data.scan.max_file_kb, vulnerability_source=source, offline_db=offline,
                       secret_hash_key=_secret_hash_key())


def _gate_policy(cfg: LoadedConfig, args: argparse.Namespace) -> GatePolicy:
    policy = cfg.gate_policy()
    if args.fail_on is not None:
        values = [v.upper() for v in _csv(args.fail_on)]
        if values == ["NONE"]:
            values = []
        bad = [v for v in values if v not in Severity.__members__]
        if bad:
            raise UsageError("--fail-on takes severities (critical,high,medium,low,info) or 'none'")
        policy.fail_on = values
    if args.min_confidence:
        policy.min_confidence = args.min_confidence.upper()
    if args.include_ai_suggested:
        policy.include_ai_suggested = True
    if args.max_findings is not None:
        policy.max_findings = args.max_findings
    return policy


def _target_name(root: Path) -> str:
    resolved = root.resolve()
    return resolved.name or str(resolved)


def _retest_items(report: retest_engine.RetestReport) -> list[dict[str, Any]]:
    items = []
    for item in report.items:
        f = item.current or item.baseline
        assert f is not None
        loc = f.location
        items.append({
            "result": item.result.value,
            "match": item.match.value,
            "severity": f.severity.value,
            "id": (item.baseline.public_id if item.baseline else None) or f.public_id or "",
            "title": f.title,
            "location": f"{loc.path}:{loc.start_line}" if loc and loc.start_line else (loc.path if loc else ""),
            "notes": item.notes,
        })
    items.sort(key=lambda i: (_RESULT_ORDER.get(i["result"], 9), i["location"]))
    return items


def _run(args: argparse.Namespace, *, baseline_path: str | None) -> tuple[ScanResult, dict[str, Any] | None, float]:
    """Scan, optionally compare with a baseline, and evaluate the gate."""
    from securelens.scanners.engine import run_scan  # imported lazily: keeps `securelens version` instant

    root = Path(args.path)
    if not root.exists():
        raise UsageError(f"path not found: {root}")
    cfg = load_config(args.config, root)
    options = _scan_options(cfg, args)
    policy = _gate_policy(cfg, args)
    baseline = _load_report(baseline_path) if baseline_path else None

    started = time.monotonic()
    result = run_scan(root, options, target=_target_name(root))
    elapsed = time.monotonic() - started

    if baseline is None:
        apply_gate_and_risk(result, policy)
        return result, None, elapsed

    history_resolved = set(baseline.history.get("resolved_fingerprints", []) or [])
    report = retest_engine.compare(
        baseline.findings, result.findings, analyzed_paths=result.analyzed_paths(),
        scanners_ran={s.scanner for s in result.scanners if s.status == "ran"},
        resolved_history=history_resolved)
    regressions = sum(1 for i in report.items if i.result == RetestResultKind.REGRESSION)
    introduced = {i.current.fingerprint for i in report.items
                  if i.current is not None and i.result in (RetestResultKind.NEW, RetestResultKind.REGRESSION)}
    apply_gate_and_risk(result, policy)
    # With a baseline, only issues introduced since the baseline block the gate.
    from securelens.findings.gate import evaluate

    gate = evaluate(gate_items([f for f in result.findings if f.fingerprint in introduced]), policy,
                    regressions=regressions)
    result.gate = {**gate.as_dict(), "mode": "new-since-baseline"}
    resolved_now = {i.baseline.fingerprint for i in report.items
                    if i.baseline is not None and i.result == RetestResultKind.RESOLVED}
    current = {f.fingerprint for f in result.findings}
    summary = report.summary(blocking_new=len(gate.blocking))
    result.history = {
        "baseline": {"target": baseline.target, "finished_at": baseline.finished_at,
                     "findings": len(baseline.findings)},
        "retest": summary,
        "retest_items": _retest_items(report)[:5000],
        "resolved_fingerprints": sorted((history_resolved | resolved_now) - current)[:5000],
    }
    return result, summary, elapsed


def _write_outputs(result: ScanResult, args: argparse.Namespace, cfg_formats: list[str] | None = None) -> list[str]:
    written = []
    for fmt, attr in (("json", "json_out"), ("sarif", "sarif_out"), ("html", "html_out"),
                      ("markdown", "markdown_out")):
        target = getattr(args, attr, None)
        if target:
            _write(target, render(result, fmt))
            written.append(target)
    if getattr(args, "report_dir", None):
        for fmt in cfg_formats or ["json", "sarif", "html"]:
            target = Path(args.report_dir) / f"securelens-report.{EXTENSIONS[fmt]}"
            _write(target, render(result, fmt))
            written.append(str(target))
    if not getattr(args, "no_save", False):
        STATE_DIR.mkdir(mode=0o700, exist_ok=True)
        _write(LAST_SCAN, render(result, "json"))
        written.append(str(LAST_SCAN))
    return written


def _emit(result: ScanResult, args: argparse.Namespace, printer: output.Printer, elapsed: float | None,
          table: str = "findings") -> None:
    if args.format == "table":
        ctx = build_context(result)
        target = open(args.output, "w", encoding="utf-8") if args.output else None  # noqa: SIM115
        try:
            p = output.Printer(target, color=False) if target else printer
            if not args.quiet:
                p.scan_header(ctx, elapsed)
            if table == "retest":
                p.retest_table((result.history or {}).get("retest_items", []))
            else:
                p.findings_table(ctx["findings"])
            p.scan_footer(ctx)
        finally:
            if target:
                target.close()
        return
    text = render(result, args.format)
    if args.output:
        _write(args.output, text)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


# ----------------------------------------------------------------- commands


def cmd_version(args: argparse.Namespace, printer: output.Printer) -> int:
    if args.json:
        printer.line(json.dumps({"name": TOOL_NAME, "version": __version__}))
    else:
        printer.line(f"{TOOL_NAME} {__version__}")
    return EXIT_OK


def cmd_init(args: argparse.Namespace, printer: output.Printer) -> int:
    root = Path(args.path)
    if not root.is_dir():
        raise UsageError(f"not a directory: {root}")
    files = {root / ".securelens.yml": DEFAULT_CONFIG_TEXT}
    if args.ci == "github":
        files[root / ".github" / "workflows" / "securelens.yml"] = GITHUB_WORKFLOW
    elif args.ci == "gitlab":
        files[root / "securelens.gitlab-ci.yml"] = GITLAB_CI
    existing = [str(p) for p in files if p.exists()]
    if existing and not args.force:
        raise UsageError(f"already exists: {', '.join(existing)} (use --force to overwrite)")
    for path, text in files.items():
        _write(path, text)
        printer.line(f"created {path}")
    printer.line("Next: securelens scan " + (str(root) if str(root) != "." else "."))
    return EXIT_OK


def cmd_scan(args: argparse.Namespace, printer: output.Printer) -> int:
    result, _, elapsed = _run(args, baseline_path=args.baseline)
    cfg = load_config(args.config, Path(args.path))
    written = _write_outputs(result, args, cfg.data.report.formats)
    _emit(result, args, printer, elapsed)
    if args.format == "table" and not args.quiet and not args.output:
        if written:
            printer.line(printer.dim("Saved: " + ", ".join(written)))
        if result.findings:
            printer.line(printer.dim(f"Explain a finding: securelens findings --show {result.findings[0].public_id}"))
    failed = (result.gate or {}).get("status") == "FAIL"
    return EXIT_GATE_FAILED if failed and not args.no_fail else EXIT_OK


def cmd_retest(args: argparse.Namespace, printer: output.Printer) -> int:
    result, summary, elapsed = _run(args, baseline_path=args.baseline)
    _write_outputs(result, args)
    _emit(result, args, printer, elapsed, table="retest")
    assert summary is not None
    failed = summary["regression_check"] == "FAIL"
    return EXIT_GATE_FAILED if failed and not args.no_fail else EXIT_OK


def cmd_findings(args: argparse.Namespace, printer: output.Printer) -> int:
    result = _load_report(args.input)
    ctx = build_context(result)
    findings = ctx["findings"]
    if args.show:
        match = next((f for f in findings if f["id"].upper() == args.show.upper()), None)
        if match is None:
            raise UsageError(f"no finding with ID {args.show} in {args.input}")
        if args.json:
            printer.line(json.dumps(match, indent=2))
        else:
            printer.finding_detail(match)
        return EXIT_OK
    if args.severity:
        wanted = {s.upper() for s in _csv(args.severity)}
        findings = [f for f in findings if f["severity"] in wanted]
    if args.source:
        wanted = {s.upper() for s in _csv(args.source)}
        findings = [f for f in findings if f["source_kind"] in wanted]
    if args.json:
        printer.line(json.dumps(findings, indent=2))
        return EXIT_OK
    printer.findings_table(findings)
    printer.line(printer.dim(f"\n{len(findings)} of {len(ctx['findings'])} findings from {args.input} "
                             f"(scanned {result.finished_at})"))
    return EXIT_OK


def cmd_report(args: argparse.Namespace, printer: output.Printer) -> int:
    result = _load_report(args.input)
    text = render(result, args.format)
    if args.output:
        _write(args.output, text)
        printer.line(f"wrote {args.output}")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    return EXIT_OK


def _server_url(raw: str | None) -> str:
    if not raw:
        raise UsageError("--server (or SECURELENS_SERVER) is required")
    parts = urlsplit(raw.rstrip("/"))
    local = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise UsageError("--server must be an http(s) URL")
    if parts.scheme == "http" and not local:
        raise UsageError("--server must use https (http is allowed only for localhost)")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise UsageError("--server must not contain credentials, a query or a fragment")
    return raw.rstrip("/")


def cmd_push(args: argparse.Namespace, printer: output.Printer) -> int:
    import httpx

    server = _server_url(args.server or os.environ.get("SECURELENS_SERVER"))
    key = os.environ.get("SECURELENS_API_KEY", "")
    if not key.startswith("slk_"):
        raise UsageError("set SECURELENS_API_KEY to an API key created in SecureLens (Settings → API keys)")
    result = _load_report(args.input)
    body = {
        "repository_name": args.repository or result.target or "ci",
        "commit": args.commit or os.environ.get("GITHUB_SHA") or os.environ.get("CI_COMMIT_SHA"),
        "branch": args.branch or os.environ.get("GITHUB_REF_NAME") or os.environ.get("CI_COMMIT_REF_NAME"),
        "report": json.loads(render(result, "json")),
    }
    url = f"{server}/api/v1/projects/{args.project}/scans/import"
    try:
        response = httpx.post(url, json=body, headers={"Authorization": f"Bearer {key}"}, timeout=120.0)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"could not reach {server}: {type(exc).__name__}") from exc
    if response.status_code >= 400:
        try:
            message = response.json().get("error", {}).get("message", response.reason_phrase)
        except ValueError:
            message = response.reason_phrase
        raise RuntimeError(f"server rejected the report ({response.status_code}): {message}")
    scan = response.json()
    printer.line(f"Uploaded: scan {scan.get('id')} · gate {scan.get('gate_status')} · "
                 f"risk index {scan.get('risk_index')}")
    return EXIT_OK


# ------------------------------------------------------------------- parser


def _add_scan_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("path", nargs="?", default=".", help="directory or file to scan (default: .)")
    p.add_argument("-c", "--config", help="configuration file (default: .securelens.yml in PATH or the cwd)")
    p.add_argument("--scanners", help="comma-separated: sast,secrets,dependencies")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude paths (repeatable)")
    p.add_argument("--no-external", action="store_true", help="do not run Bandit/Semgrep/Gitleaks even if installed")
    p.add_argument("--vuln-source", choices=["osv", "offline", "none"], help="dependency advisory source")
    p.add_argument("--offline-db", metavar="DIR", help="directory of OSV JSON advisories")
    p.add_argument("--fail-on", metavar="SEVERITIES", help="e.g. critical,high — or none")
    p.add_argument("--min-confidence", choices=["confirmed", "high", "medium", "low"])
    p.add_argument("--include-ai-suggested", action="store_true", help="let AI-suggested findings fail the gate")
    p.add_argument("--max-findings", type=int, metavar="N", help="fail when more than N findings are open")
    p.add_argument("-o", "--output", metavar="FILE", help="write the --format output to FILE")
    p.add_argument("--json-out", metavar="FILE")
    p.add_argument("--sarif-out", metavar="FILE")
    p.add_argument("--html-out", metavar="FILE")
    p.add_argument("--markdown-out", metavar="FILE")
    p.add_argument("--no-save", action="store_true", help=f"do not write {LAST_SCAN}")
    p.add_argument("--no-fail", action="store_true", help="always exit 0 when the scan completes")
    p.add_argument("-q", "--quiet", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securelens", description=f"{TOOL_NAME} — application and AI security "
                                     "testing from the command line.",
                                     epilog="Exit codes: 0 gate passed · 1 gate failed · 2 usage error · "
                                            "3 scan error")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    # Also accepted after the command (`securelens scan . --no-color`).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("version", parents=[common], help="print the version")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("init", parents=[common], help="create .securelens.yml and optionally a CI workflow")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--ci", choices=["github", "gitlab"], help="also write a CI pipeline")
    p.add_argument("--force", action="store_true", help="overwrite existing files")

    p = sub.add_parser("scan", parents=[common], help="scan source code")
    _add_scan_options(p)
    p.add_argument("--format", choices=["table", "json", "sarif", "html", "markdown"], default="table")
    p.add_argument("--baseline", metavar="REPORT", help="earlier JSON report: only new issues fail the gate")
    p.add_argument("--report-dir", metavar="DIR", help="write the formats listed in the config into DIR")

    p = sub.add_parser("findings", parents=[common], help="list findings of a report, or explain one")
    p.add_argument("--input", default=str(LAST_SCAN), metavar="REPORT")
    p.add_argument("--severity", help="comma-separated severities")
    p.add_argument("--source", help="comma-separated: SAST,SECRET,DEPENDENCY,AI_CODE")
    p.add_argument("--show", metavar="ID", help="explain one finding, e.g. SL-003")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("report", parents=[common], help="render a saved report as JSON, SARIF, HTML or Markdown")
    p.add_argument("--input", default=str(LAST_SCAN), metavar="REPORT")
    p.add_argument("--format", choices=["json", "sarif", "html", "markdown"], required=True)
    p.add_argument("-o", "--output", metavar="FILE")

    p = sub.add_parser("retest", parents=[common], help="rescan and compare with an earlier report")
    _add_scan_options(p)
    p.add_argument("--baseline", required=True, metavar="REPORT", help="earlier JSON report")
    p.add_argument("--format", choices=["table", "json", "html", "markdown"], default="table")

    p = sub.add_parser("push", parents=[common], help="upload a JSON report to a SecureLens server")
    p.add_argument("--server", help="server URL (or SECURELENS_SERVER)")
    p.add_argument("--project", required=True, help="project ID")
    p.add_argument("--input", default=str(LAST_SCAN), metavar="REPORT")
    p.add_argument("--repository", help="repository name shown in SecureLens")
    p.add_argument("--commit")
    p.add_argument("--branch")
    return parser


COMMANDS = {"version": cmd_version, "init": cmd_init, "scan": cmd_scan, "findings": cmd_findings,
            "report": cmd_report, "retest": cmd_retest, "push": cmd_push}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits 2 on usage errors, 0 on --help
        return int(exc.code or 0)
    printer = output.Printer(sys.stdout, color=output.color_enabled(sys.stdout, args.no_color))
    try:
        return COMMANDS[args.command](args, printer)
    except (UsageError, ConfigError) as exc:
        print(f"securelens: {output.clean(exc)}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("securelens: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        if os.environ.get("SECURELENS_DEBUG"):
            raise
        print(f"securelens: error: {output.clean(exc)}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
