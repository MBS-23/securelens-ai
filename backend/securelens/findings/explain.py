"""Deterministic finding explanations ("Why did SecureLens detect this?").

Built only from the evidence the scanners recorded and the reviewed catalog —
no AI involved — so every step can be traced to something real. Learning Mode
renders these steps; Professional Mode shows the raw evidence.
"""

from __future__ import annotations

from typing import Any

from securelens.findings import catalog

_LANGUAGE_BY_EXT = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
                    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".php": "php", ".java": "java",
                    ".cs": "csharp", ".go": "go", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp"}


def _sentence(text: str) -> str:
    """Upper-case only the first letter; identifiers later in the text keep their case."""
    return text[:1].upper() + text[1:]


def language_of(path: str | None) -> str | None:
    if not path or "." not in path:
        return None
    return _LANGUAGE_BY_EXT.get(path[path.rfind("."):].lower())


def explain(*, vuln_class: str, title: str, severity: str, confidence: str, exploitability: str,
            evidence: list[dict[str, Any]], file_path: str | None, line: int | None) -> dict[str, Any]:
    vc = catalog.get(vuln_class) if catalog.known(vuln_class) else None
    steps: list[dict[str, str]] = []
    flow = next((e for e in evidence if e.get("kind") == "dataflow"), None)
    secret = next((e for e in evidence if e.get("kind") == "secret"), None)
    dependency = next((e for e in evidence if e.get("kind") == "dependency"), None)
    criteria = [e for e in evidence if e.get("kind") == "criterion"]

    if flow is not None:
        data = flow.get("data") or {}
        sources = data.get("sources") or []
        path_steps = data.get("steps") or []
        if sources or data.get("origin") == "unknown":
            if sources:
                src = sources[0]
                steps.append({"title": "Untrusted input enters the program",
                              "detail": f"{src.get('label', 'Untrusted input')} at {src.get('path')}:{src.get('line')}",
                              "code": src.get("code") or ""})
                middle = path_steps[1:-1]
            else:
                steps.append({"title": "A value of unknown origin",
                              "detail": "The value is built dynamically, but it could not be traced back to its "
                                        "source, so SecureLens cannot prove an attacker controls it. This is why "
                                        "the confidence is lower."})
                middle = path_steps[:-1]
            for step in middle:
                steps.append({"title": _sentence(step.get("note", "")) or "Data flows onward",
                              "detail": f"{step.get('path')}:{step.get('line')}", "code": step.get("code") or ""})
            steps.append({"title": "It reaches a dangerous operation",
                          "detail": f"{data.get('sink', 'a sensitive sink')} at {file_path}:{line}", "code": ""})
            steps.append({"title": "No sanitizer on the way",
                          "detail": "No validation, encoding or parameterization that SecureLens recognizes for "
                                    "this vulnerability class was applied along this path."})
        else:
            # State tracking (for example a pointer that was freed and then used again).
            for step in path_steps:
                steps.append({"title": step.get("note", "") or "Program state changes",
                              "detail": f"{step.get('path')}:{step.get('line')}", "code": step.get("code") or ""})
    elif secret is not None:
        data = secret.get("data") or {}
        steps.append({"title": "A credential-shaped value is in the code",
                      "detail": f"{data.get('secret_type', 'Secret')} {data.get('masked', '')} at {file_path}:{line}"})
        steps.append({"title": "It matches a known format",
                      "detail": f"Detector '{data.get('detector')}'" + (f", entropy {data.get('entropy')}"
                                                                        if data.get("entropy") else "")})
        steps.append({"title": "Anyone with the code can use it",
                      "detail": "Source, history, forks and build artifacts all carry the value. Rotate it first."})
    elif dependency is not None:
        data = dependency.get("data") or {}
        steps.append({"title": "The project depends on this package",
                      "detail": f"{data.get('name')}@{data.get('version')} ({data.get('ecosystem')}) in "
                                f"{data.get('manifest')}"})
        steps.append({"title": "A published advisory covers this version",
                      "detail": f"{data.get('advisory_id')}: affected "
                                f"{', '.join(data.get('affected_ranges') or []) or 'see advisory'}"})
        fixed = data.get("fixed_versions") or []
        steps.append({"title": "Upgrade path", "detail": f"Fixed in {', '.join(fixed)}" if fixed
                      else "No fixed version is published yet"})
    elif criteria:
        for c in criteria:
            steps.append({"title": c.get("summary", "Evaluation criterion"),
                          "detail": str((c.get("data") or {}).get("detail", ""))})
    else:
        pattern = next((e for e in evidence if e.get("kind") in {"pattern", "scanner_output"}), None)
        steps.append({"title": "A risky construct was found",
                      "detail": (pattern or {}).get("summary") or title})
        steps.append({"title": "Why it matters", "detail": vc.impact if vc else ""})

    steps.append({"title": f"Potential {vc.name if vc else vuln_class}",
                  "detail": f"Severity {severity}, confidence {confidence}, "
                            f"exploitability {exploitability.replace('_', ' ').lower()}."})

    language = language_of(file_path)
    example = None
    if vc is not None:
        key = {"typescript": "javascript"}.get(language or "", language or "")
        raw = vc.examples.get(key) or next(iter(vc.examples.values()), None) if vc.examples else None
        if raw:
            example = {"language": key if key in vc.examples else next(iter(vc.examples)),
                       "insecure": raw.get("vulnerable", ""), "secure": raw.get("secure", "")}
    return {
        "steps": [{"number": i + 1, **s} for i, s in enumerate(steps)],
        "root_cause": vc.description if vc else "",
        "impact": vc.impact if vc else "",
        "prevention": vc.recommendation if vc else "",
        "example": example,
        "language": language,
        "basis": "Derived from the recorded scanner evidence and the SecureLens vulnerability catalog; no AI.",
    }
