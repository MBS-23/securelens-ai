"""Report rendering: JSON, SARIF 2.1.0, HTML and Markdown from one ScanResult.

The HTML report is a single self-contained file: no scripts, no external
resources, a restrictive Content-Security-Policy, and every value escaped by
Jinja2's autoescaping — scanned code is untrusted and ends up in the report.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined
from markupsafe import Markup, escape

from securelens.findings.model import ScanResult
from securelens.reporting import context as report_context
from securelens.reporting import markdown as markdown_renderer
from securelens.reporting import sarif as sarif_renderer

FORMATS = ("json", "sarif", "html", "markdown")
CONTENT_TYPES = {
    "json": "application/json",
    "sarif": "application/sarif+json",
    "html": "text/html; charset=utf-8",
    "markdown": "text/markdown; charset=utf-8",
}
EXTENSIONS = {"json": "json", "sarif": "sarif", "html": "html", "markdown": "md"}
SOURCE_LABELS = {"SAST": "Code", "SECRET": "Secrets", "DEPENDENCY": "Dependencies", "AI_CODE": "AI app code",
                 "LLM_TEST": "LLM tests"}
EXPAND_DETAILS_UP_TO = 30


@lru_cache(maxsize=1)
def _env() -> Environment:
    env = Environment(loader=PackageLoader("securelens.reporting", "templates"), autoescape=True,
                      undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
    env.filters["wbr"] = _wbr
    return env


def _wbr(value: object) -> Markup:
    """Escape, then allow line breaks after path separators."""
    return Markup(str(escape(str(value))).replace("/", "/<wbr>"))  # noqa: S704 - input escaped first


def build_context(result: ScanResult, **kwargs: Any) -> dict[str, Any]:
    return report_context.build(result, **kwargs)


def render_html(result: ScanResult, **kwargs: Any) -> str:
    ctx = build_context(result, **kwargs)
    return _env().get_template("report.html.j2").render(
        **ctx, severities=report_context.SEVERITIES, source_labels=SOURCE_LABELS,
        expand=len(ctx["findings"]) <= EXPAND_DETAILS_UP_TO)


def render_markdown(result: ScanResult, *, max_findings: int = 25, **kwargs: Any) -> str:
    return markdown_renderer.render(build_context(result, **kwargs), max_findings=max_findings)


def render_sarif(result: ScanResult) -> str:
    return json.dumps(sarif_renderer.render(result), indent=2)


def render_json(result: ScanResult, **kwargs: Any) -> str:
    """The ScanResult (the format ``securelens push`` and the server import accept) plus report sections."""
    data = result.model_dump(mode="json")
    ctx = build_context(result, **kwargs)
    data["report"] = {"generated_at": ctx["meta"]["generated_at"], "scope": ctx["scope"],
                      "methodology": ctx["methodology"], "limitations": ctx["limitations"],
                      "summary": ctx["summary"]}
    return json.dumps(data, indent=2)


def render(result: ScanResult, fmt: str, **kwargs: Any) -> str:
    if fmt == "json":
        return render_json(result, **kwargs)
    if fmt == "sarif":
        return render_sarif(result)
    if fmt == "html":
        return render_html(result, **kwargs)
    if fmt == "markdown":
        return render_markdown(result, **kwargs)
    raise ValueError(f"unknown report format: {fmt}")
