"""Retest comparison: baseline findings vs a new scan.

    RESOLVED        the affected file was analysed again by the same scanner and the issue is gone
    STILL_OPEN      the issue is still present (matched by fingerprint, or fuzzily after an edit)
    REGRESSION      an issue that had been resolved before is back
    NOT_REPRODUCED  the issue is gone but so is the affected file, so the absence proves no fix
    NOT_TESTED      the file was not part of this scan, or the scanner that found it did not run
    NEW             present now, not in the baseline

A vulnerability is never considered resolved because a patch was suggested —
only a new scan (or an explicit human status change) resolves it.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from securelens.enums import MatchMethod, RetestResultKind, SourceKind
from securelens.findings.fingerprint import normalise_code
from securelens.findings.model import Finding

FUZZY_LINE_WINDOW = 15
FUZZY_SIMILARITY = 0.6


@dataclass
class RetestItem:
    result: RetestResultKind
    match: MatchMethod
    baseline: Finding | None = None
    current: Finding | None = None
    notes: str = ""


@dataclass
class RetestReport:
    items: list[RetestItem] = field(default_factory=list)

    def summary(self, blocking_new: int = 0) -> dict:
        counts = {k.value: 0 for k in RetestResultKind}
        for item in self.items:
            counts[item.result.value] += 1
        previous = sum(counts[k] for k in ("RESOLVED", "STILL_OPEN", "NOT_REPRODUCED", "NOT_TESTED"))
        regression_check = "FAIL" if counts["REGRESSION"] or blocking_new else "PASS"
        return {
            "previous_findings": previous,
            "resolved": counts["RESOLVED"],
            "still_open": counts["STILL_OPEN"],
            "not_reproduced": counts["NOT_REPRODUCED"],
            "not_tested": counts["NOT_TESTED"],
            "new": counts["NEW"],
            "regressions": counts["REGRESSION"],
            "remaining": counts["STILL_OPEN"] + counts["NOT_TESTED"],
            "regression_check": regression_check,
        }


def _scanner_ran(finding: Finding, scanners_ran: set[str]) -> bool:
    if finding.source_kind == SourceKind.DEPENDENCY:
        return bool({"dependency-advisories"} & scanners_ran)
    return any(s.split(":")[0] in scanners_ran for s in finding.scanners)


def _fuzzy_match(base: Finding, candidates: list[Finding]) -> Finding | None:
    bl = base.location
    if bl is None:
        return None
    best, best_score = None, 0.0
    for cand in candidates:
        cl = cand.location
        if cl is None or cand.vuln_class != base.vuln_class or cl.path != bl.path:
            continue
        if base.source_kind != cand.source_kind:
            continue
        same_function = bool(bl.function) and bl.function == cl.function
        near = (bl.start_line is not None and cl.start_line is not None
                and abs(bl.start_line - cl.start_line) <= FUZZY_LINE_WINDOW)
        similarity = difflib.SequenceMatcher(None, normalise_code(bl.snippet), normalise_code(cl.snippet)).ratio()
        score = (similarity + (0.5 if same_function else 0) + (0.3 if near else 0)
                 + (0.2 if cand.rule_id == base.rule_id else 0))
        if (same_function or near) and similarity >= FUZZY_SIMILARITY and score > best_score:
            best, best_score = cand, score
    return best


def compare(baseline: list[Finding], current: list[Finding], *, analyzed_paths: set[str], scanners_ran: set[str],
            resolved_history: set[str] | None = None, partial: bool = False) -> RetestReport:
    report = RetestReport()
    resolved_history = resolved_history or set()
    by_fp = {f.fingerprint: f for f in current}
    unmatched_current = dict(by_fp)
    pending: list[Finding] = []
    for base in baseline:
        match = by_fp.get(base.fingerprint)
        if match is not None and base.fingerprint in unmatched_current:
            unmatched_current.pop(base.fingerprint)
            report.items.append(RetestItem(RetestResultKind.STILL_OPEN, MatchMethod.FINGERPRINT, base, match,
                                           "Same issue found again at the same code."))
        else:
            pending.append(base)
    for base in pending:
        candidate = _fuzzy_match(base, list(unmatched_current.values()))
        if candidate is not None:
            unmatched_current.pop(candidate.fingerprint)
            report.items.append(RetestItem(RetestResultKind.STILL_OPEN, MatchMethod.FUZZY, base, candidate,
                                           "The code around the issue changed, but the same issue is still present "
                                           "in the same function."))
            continue
        path = base.location.path if base.location else None
        if path is not None and path not in analyzed_paths:
            if partial:
                report.items.append(RetestItem(RetestResultKind.NOT_TESTED, MatchMethod.NONE, base, None,
                                               f"{path} was not part of this scan."))
            else:
                report.items.append(RetestItem(RetestResultKind.NOT_REPRODUCED, MatchMethod.NONE, base, None,
                                               f"{path} is no longer present, so the absence of the finding does not "
                                               "demonstrate a fix."))
            continue
        if not _scanner_ran(base, scanners_ran):
            report.items.append(RetestItem(RetestResultKind.NOT_TESTED, MatchMethod.NONE, base, None,
                                           f"The scanner that reported it ({', '.join(base.scanners)}) did not run."))
            continue
        report.items.append(RetestItem(RetestResultKind.RESOLVED, MatchMethod.NONE, base, None,
                                       "The file was analysed again and the issue is no longer detected."))
    for fp, cur in unmatched_current.items():
        if fp in resolved_history:
            report.items.append(RetestItem(RetestResultKind.REGRESSION, MatchMethod.FINGERPRINT, None, cur,
                                           "This issue was resolved earlier and has reappeared."))
        else:
            report.items.append(RetestItem(RetestResultKind.NEW, MatchMethod.NONE, None, cur,
                                           "Not present in the baseline scan."))
    return report
