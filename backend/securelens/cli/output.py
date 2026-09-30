"""Terminal rendering for the CLI (tables, finding details, retest results).

Colour is used only on a terminal and honours ``NO_COLOR`` / ``FORCE_COLOR``.
Scanned code is untrusted, so control characters are stripped from anything
printed: a file name or snippet must not be able to rewrite the terminal.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from typing import Any, TextIO

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")

_SEVERITY_STYLE = {"CRITICAL": "1;97;41", "HIGH": "1;31", "MEDIUM": "33", "LOW": "34", "INFO": "2"}
_RESULT_STYLE = {"RESOLVED": "32", "STILL_OPEN": "33", "NEW": "1;31", "REGRESSION": "1;97;41",
                 "NOT_TESTED": "2", "NOT_REPRODUCED": "2"}


def clean(value: Any) -> str:
    """Remove terminal control sequences and bidi overrides from untrusted text."""
    return _CONTROL.sub("", str(value if value is not None else ""))


def color_enabled(stream: TextIO, disabled: bool) -> bool:
    if disabled or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class Printer:
    def __init__(self, stream: TextIO | None = None, *, color: bool = False) -> None:
        self.stream = stream or sys.stdout
        self.color = color
        self.width = max(80, min(shutil.get_terminal_size((120, 40)).columns, 200))

    def style(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color and code else text

    def bold(self, text: str) -> str:
        return self.style(text, "1")

    def dim(self, text: str) -> str:
        return self.style(text, "2")

    def severity(self, sev: str, width: int = 8) -> str:
        return self.style(sev.ljust(width), _SEVERITY_STYLE.get(sev, ""))

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)

    # ------------------------------------------------------------- scan

    def scan_header(self, ctx: dict[str, Any], elapsed: float | None) -> None:
        meta, scope = ctx["meta"], ctx["scope"]
        self.line(self.bold(f"{meta['tool']} {meta['tool_version']}") + f" — scanned {clean(scope['target'])}")
        languages = ", ".join(lang["name"] for lang in scope["languages"]) or "none recognised"
        took = f" · {elapsed:.1f}s" if elapsed is not None else ""
        self.line(self.dim(f"{scope['files_analyzed']} of {scope['files_total']} files · "
                           f"{scope['lines_analyzed']} lines · {languages}{took}"))
        parts = []
        for s in scope["scanners"]:
            mark = "✓" if s["status"] == "ran" else "–"
            parts.append(f"{s['label']} {mark}" + ("" if s["status"] == "ran" else f" ({s['status']})"))
        self.line(self.dim("Scanners: " + " · ".join(parts)))
        self.line()

    def findings_table(self, findings: list[dict[str, Any]]) -> None:
        if not findings:
            self.line("No findings were reported by the scanners that ran.")
            return
        id_w = max(6, *(len(f["id"]) for f in findings))
        loc_w = min(40, max(8, *(len(clean(f["location"])) for f in findings)))
        fixed = id_w + 2 + 10 + 11 + loc_w + 2
        title_w = max(20, self.width - fixed)
        self.line(self.bold(f"{'ID'.ljust(id_w)}  {'SEVERITY':<10}{'CONFIDENCE':<11}{'LOCATION'.ljust(loc_w)}  "
                            "FINDING"))
        for f in findings:
            loc = clean(f["location"])
            if len(loc) > loc_w:
                loc = "…" + loc[-(loc_w - 1):]
            title = clean(f["title"])
            if len(title) > title_w:
                title = title[:title_w - 1] + "…"
            self.line(f"{f['id'].ljust(id_w)}  {self.severity(f['severity'], 10)}{f['confidence']:<11}"
                      f"{loc.ljust(loc_w)}  {title}")

    def scan_footer(self, ctx: dict[str, Any]) -> None:
        sev = ctx["summary"]["by_severity"]
        total = ctx["summary"]["total"]
        self.line()
        counts = " · ".join(f"{sev[s]} {s.lower()}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
        self.line(self.bold(f"{total} finding{'s' if total != 1 else ''}") + f": {counts}")
        risk = ctx.get("risk")
        if risk and risk.get("index") is not None:
            self.line(f"SecureLens Risk Index: {risk['index']}/100 "
                      + self.dim("(SecureLens-specific prioritisation aid, not CVSS)"))
        retest = ctx.get("retest")
        if retest:
            self.line(f"Compared with baseline: {retest['resolved']} resolved · {retest['still_open']} still open · "
                      f"{retest['new']} new · {retest['regressions']} regressions · "
                      f"{retest['not_tested']} not tested")
        gate = ctx.get("gate")
        if gate:
            if gate["status"] == "PASS":
                self.line("Security gate: " + self.style("PASS", "1;32"))
            else:
                self.line("Security gate: " + self.style("FAIL", "1;31") + " — " + "; ".join(gate["reasons"]))

    # ---------------------------------------------------------- details

    def finding_detail(self, f: dict[str, Any]) -> None:
        self.line(self.bold(f["id"]) + "  " + self.severity(f["severity"]).rstrip() + "  "
                  + self.bold(clean(f["title"])))
        where = clean(f["location"]) + (f" (in {clean(f['function'])})" if f.get("function") else "")
        self.line(f"Location: {where}")
        facts = [f"Confidence {f['confidence']}", f"Exploitability {f['exploitability'].replace('_', ' ').lower()}",
                 f"Verification {f['verification'].replace('_', ' ')}"]
        if f["cwe"]:
            facts.append(", ".join(f["cwe"]))
        if f["owasp"]:
            facts.append(", ".join(f["owasp"]))
        self.line(self.dim(" · ".join(facts)))
        if f.get("snippet"):
            self.line()
            self.line(f"  {f['line'] or ''} | {clean(f['snippet'])}")
        self.line()
        self.line(self.bold("Why SecureLens detected this"))
        for step in f["steps"]:
            self.line(f"  {step['number']}. {clean(step['title'])}")
            if step.get("detail"):
                self.line(self.dim(f"     {clean(step['detail'])}"))
            if step.get("code"):
                self.line(f"       {clean(step['code'])}")
        for heading, key in (("What is wrong", "description"), ("Impact", "impact"),
                             ("How to fix it", "recommendation")):
            if f.get(key):
                self.line()
                self.line(self.bold(heading))
                self.line(f"  {clean(f[key])}")
        if f.get("remediation"):
            self.line()
            for row in clean_block(f["remediation"]):
                self.line(f"  {row}")
        if f.get("references"):
            self.line()
            self.line(self.bold("References"))
            for ref in f["references"]:
                self.line(f"  {clean(ref)}")

    # ----------------------------------------------------------- retest

    def retest_table(self, items: list[dict[str, Any]]) -> None:
        if not items:
            self.line("Nothing to compare: neither scan reported findings.")
            return
        self.line(self.bold(f"{'RESULT':<15}{'SEVERITY':<10}{'LOCATION':<36}FINDING"))
        for item in items:
            loc = clean(item["location"])
            if len(loc) > 34:
                loc = "…" + loc[-33:]
            title = clean(item["title"])
            room = max(20, self.width - 61)
            if len(title) > room:
                title = title[:room - 1] + "…"
            self.line(self.style(f"{item['result']:<15}", _RESULT_STYLE.get(item["result"], ""))
                      + self.severity(item["severity"], 10) + f"{loc:<36}{title}")
            if item.get("notes") and item["result"] in ("NOT_TESTED", "NOT_REPRODUCED", "REGRESSION"):
                self.line(self.dim(f"{'':15}{clean(item['notes'])}"))


def clean_block(text: str) -> list[str]:
    return [clean(line) for line in str(text).splitlines()]
