"""The SecureLens SAST scanner: parse → IR → taint engine → unified findings."""

from __future__ import annotations

import time

from securelens.enums import Engine, SourceKind
from securelens.findings import catalog
from securelens.findings.model import Evidence, Finding, Location, ScannerRun
from securelens.scanners.base import ScanContext, ScannerResult
from securelens.scanners.sast import ir
from securelens.scanners.sast.generic_frontend import GenericFrontend
from securelens.scanners.sast.javascript_frontend import JavaScriptFrontend
from securelens.scanners.sast.php_frontend import PHPFrontend
from securelens.scanners.sast.python_frontend import PythonFrontend
from securelens.scanners.sast.rules import load_pack
from securelens.scanners.sast.taint import RawFinding, TaintEngine

SCANNER_NAME = "securelens-sast"
# Languages analysed together (so cross-file calls resolve): JS/TS share a family, as do C and C++.
FAMILIES = {"python": "python", "javascript": "js", "typescript": "js", "tsx": "js", "php": "php",
            "java": "java", "csharp": "csharp", "go": "go", "c": "c", "cpp": "c"}


def _frontend(language: str):
    if language == "python":
        return PythonFrontend()
    if language in {"javascript", "typescript", "tsx"}:
        return JavaScriptFrontend(language)
    if language == "php":
        return PHPFrontend()
    if language in {"java", "csharp", "go", "c", "cpp"}:
        return GenericFrontend(language)
    raise ValueError(language)


class SastScanner:
    name = SCANNER_NAME

    def available(self) -> tuple[bool, str | None]:
        return True, None

    def scan(self, ctx: ScanContext) -> ScannerResult:
        started = time.monotonic()
        families: dict[str, list[ir.Module]] = {}
        parse_errors: dict[str, str] = {}
        errors: list[str] = []
        languages: set[str] = set()
        for source in ctx.files:
            if source.language not in FAMILIES:
                continue
            try:
                module = _frontend(source.language).parse(source.path, source.read())
            except Exception as exc:  # pragma: no cover - a parser crash must not stop the scan
                parse_errors[source.path] = f"parser failure: {type(exc).__name__}"
                continue
            if module.parse_errors:
                total_lines = max(1, len(module.lines))
                if source.language == "python" or module.parse_errors > total_lines // 2:
                    parse_errors[source.path] = "syntax errors prevented analysis"
                    if source.language == "python":
                        continue
                else:
                    parse_errors[source.path] = f"{module.parse_errors} syntax error(s); analysed the rest"
            languages.add(source.language)
            families.setdefault(FAMILIES[source.language], []).append(module)

        findings: list[Finding] = []
        budget = max(30.0, ctx.options.time_budget_seconds * 0.6)
        for modules in families.values():
            packs = {m.language: load_pack(m.language) for m in modules}
            engine = TaintEngine(modules, packs, time_budget_seconds=budget / max(1, len(families)))
            raw = engine.run()
            errors.extend(engine.errors)
            lines = {m.path: m.lines for m in modules}
            findings.extend(convert(r, lines) for r in raw)
        run = ScannerRun(scanner=self.name, status="ran", findings=len(findings),
                         duration_ms=int((time.monotonic() - started) * 1000), languages=sorted(languages),
                         detail=None if languages else "no supported source files")
        return ScannerResult(run=run, findings=findings, errors=errors, parse_errors=parse_errors)


def _line(lines: dict[str, list[str]], path: str, line: int) -> str:
    src = lines.get(path) or []
    return src[line - 1].strip()[:300] if 0 < line <= len(src) else ""


def convert(raw: RawFinding, lines: dict[str, list[str]]) -> Finding:
    vc = catalog.get(raw.vuln_class)
    base = catalog.get(raw.base_class) if raw.base_class and raw.base_class != raw.vuln_class and catalog.known(
        raw.base_class) else None
    cwe = list(dict.fromkeys([*raw.cwe, *(base.cwe if base else ()), *vc.cwe]))
    owasp = list(dict.fromkeys([*vc.owasp, *(base.owasp if base else ())]))
    title = raw.title or vc.name
    if base is not None and raw.vuln_class == "llm_output_handling":
        title = f"LLM output reaches a {base.name} sink"
    elif base is not None and raw.vuln_class == "unsafe_tool_input":
        title = f"LLM tool argument reaches a {base.name} sink"
    elif base is not None and raw.vuln_class == "rag_prompt_injection":
        title = "Retrieved content placed in LLM system instructions"
    elif raw.origin_unknown:
        # No source was traced, so the title must not claim the input is untrusted.
        title = f"Possible {vc.name}: value of untraced origin reaches {raw.sink}"

    location = Location(path=raw.path, start_line=raw.line, end_line=raw.end_line or raw.line,
                        start_col=raw.col + 1 if raw.col is not None else None, function=raw.function,
                        snippet=raw.snippet or _line(lines, raw.path, raw.line))
    evidence: list[Evidence] = []
    if raw.sources:
        src = raw.sources[0]
        evidence.append(Evidence(
            kind="dataflow",
            source=SCANNER_NAME,
            summary=f"Untrusted data from {src.label} ({src.path}:{src.line}) reaches {raw.sink}.",
            location=location,
            data={
                "sources": [{"label": s.label, "kind": s.kind, "path": s.path, "line": s.line, "code": s.code}
                            for s in raw.sources],
                "steps": [{"path": st.path, "line": st.line, "note": st.note, "code": _line(lines, st.path, st.line)}
                          for st in raw.steps],
                "sink": raw.sink,
            },
        ))
    elif raw.kind == "taint":
        evidence.append(Evidence(
            kind="dataflow",
            source=SCANNER_NAME,
            summary=raw.message,
            location=location,
            data={"steps": [{"path": st.path, "line": st.line, "note": st.note,
                             "code": _line(lines, st.path, st.line)} for st in raw.steps],
                  "sink": raw.sink, "origin": "unknown" if raw.origin_unknown else "state"},
        ))
    else:
        evidence.append(Evidence(kind="pattern", source=SCANNER_NAME, summary=raw.message, location=location,
                                 data={"rule": raw.rule_id}))

    remediation = vc.secure_pattern(raw.language)
    if base is not None:
        remediation = f"{vc.remediation}\n\n{base.secure_pattern(raw.language)}"
    return Finding(
        rule_id=raw.rule_id,
        engine=vc.engine,
        source_kind=SourceKind.AI_CODE if vc.engine == Engine.AISEC else SourceKind.SAST,
        vuln_class=raw.vuln_class,
        title=title,
        category=vc.name if base is None else f"{vc.name} ({base.name})",
        severity=raw.severity,
        confidence=raw.confidence,
        exploitability=raw.exploitability,
        cwe=cwe,
        owasp=owasp,
        location=location,
        evidence=evidence,
        description=f"{raw.message} {vc.description}".strip(),
        impact=vc.impact if base is None else f"{vc.impact} {base.impact}",
        recommendation=vc.recommendation,
        remediation=remediation,
        references=list(dict.fromkeys([*vc.references, *(base.references if base else ())])),
        scanners=[SCANNER_NAME],
        tags=[raw.language, raw.kind],
        correlation={"base_class": raw.base_class} if base is not None else {},
    )
