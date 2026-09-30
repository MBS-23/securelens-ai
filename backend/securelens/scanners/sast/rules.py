"""Loading and compiling SAST rule packs.

A rule pack is a YAML file per language (``rules/<language>.yml``). It declares:

* ``entry_points`` — functions whose parameters are attacker- or model-controlled
  (web route handlers, LLM tool functions, MCP tools);
* ``sources`` — expressions that produce untrusted data;
* ``sanitizers`` — calls that neutralise data for some vulnerability classes;
* ``sinks`` — operations that are dangerous with untrusted data (taint rules);
* ``checks`` — structural API-misuse rules that need no data flow.

Name patterns are dotted paths. ``*.execute`` matches any receiver followed by
``execute``; ``*`` inside a segment is a glob (``*hash*``); a trailing ``()``
denotes a call; ``[KEY]`` a subscript with a constant key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any

import yaml

from securelens.enums import Confidence, Severity


def _compile(pattern: str, prefix_mode: bool) -> re.Pattern[str]:
    if pattern == "**":
        return re.compile(r"^.+$")
    body = ""
    rest = pattern
    if rest.startswith("*."):
        body = r"(?:[^\s]+\.)"
        rest = rest[2:]
    out = []
    for ch in rest:
        if ch == "*":
            out.append(r"[^.\[\]()]*")
        else:
            out.append(re.escape(ch))
    body += "".join(out)
    if prefix_mode:
        return re.compile(rf"^{body}(?:[.\[(].*)?$")
    return re.compile(rf"^{body}$")


@dataclass(frozen=True)
class NamePatterns:
    raw: tuple[str, ...]
    exact: tuple[re.Pattern[str], ...]
    prefix: tuple[re.Pattern[str], ...]

    @classmethod
    def of(cls, patterns: list[str] | tuple[str, ...] | None) -> NamePatterns:
        pats = tuple(patterns or ())
        return cls(
            raw=pats,
            exact=tuple(_compile(p, prefix_mode=False) for p in pats),
            prefix=tuple(_compile(p, prefix_mode=True) for p in pats),
        )

    def matches(self, name: str | None) -> bool:
        return bool(name) and any(p.match(name) for p in self.exact)  # type: ignore[arg-type]

    def matches_prefix(self, name: str | None) -> bool:
        return bool(name) and any(p.match(name) for p in self.prefix)  # type: ignore[arg-type]

    def __bool__(self) -> bool:
        return bool(self.raw)


@dataclass(frozen=True)
class EntryPointRule:
    kind: str  # http_route | llm_tool
    label: str
    decorators: NamePatterns
    registrations: NamePatterns  # calls that register a handler: app.get(path, handler)
    exclude_params: frozenset[str]
    exclude_annotations: NamePatterns
    handler_arg: int | None  # which argument of a registration call is the handler (None = last)
    source_kind: str
    require_path_slash: bool
    names: frozenset[str] = frozenset()  # entry functions identified by name (main)


@dataclass(frozen=True)
class SourceRule:
    id: str
    kind: str
    label: str
    patterns: NamePatterns  # prefix-matched against attribute chains and calls
    # Calls that write untrusted data into their arguments (fgets(buf, ...), scanf("%s", buf)).
    taints_args: tuple[int, ...] = ()


@dataclass(frozen=True)
class SanitizerRule:
    patterns: NamePatterns
    classes: frozenset[str]  # "*" = all
    # Only sanitises when argument N is one of these names/constants
    # (e.g. filter_var(..., FILTER_VALIDATE_INT)).
    arg_names: dict[int, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class SinkRule:
    id: str
    vuln_class: str
    title: str
    message: str
    severity: Severity
    callees: NamePatterns
    assigns: NamePatterns
    args: tuple[int, ...]
    all_args: bool
    kwargs: tuple[str, ...]
    object_props: tuple[str, ...]
    when_option: dict[str, Any]
    unknown_origin: str  # dynamic | nonliteral | never
    unknown_origin_confidence: Confidence
    source_kinds: frozenset[str]  # empty = any
    remap: dict[str, str]  # source kind -> vuln class override
    unless_function_mentions: NamePatterns
    special: str | None  # role_message
    confidence: Confidence | None
    cwe: tuple[str, ...]
    new_only: bool
    strings_only: bool
    derived: str  # report | medium | skip — taint that only passed through unmodelled calls


@dataclass(frozen=True)
class CheckRule:
    id: str
    vuln_class: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    exploitability: str
    kind: str  # call | assign | decorator | compare | attribute
    callees: NamePatterns
    targets: NamePatterns
    option_equals: dict[str, Any]
    option_contains: dict[str, Any]
    option_absent_or_not_in: dict[str, list[str]]
    option_literal: dict[str, int]
    arg_equals: dict[int, list[str]]
    arg_contains: dict[int, list[str]]
    arg_nonliteral: tuple[int, ...]
    arg_attr: dict[int, list[str]]
    min_args: int
    max_args: int | None
    assigned_name_regex: re.Pattern[str] | None
    context_regex: re.Pattern[str] | None
    context_severity: Severity | None
    context_cwe: tuple[str, ...]
    value_equals: list[Any]
    value_literal_min_len: int | None
    name_regex: re.Pattern[str] | None
    receiver_origin: NamePatterns
    path_regex: re.Pattern[str] | None
    cwe: tuple[str, ...]
    new_only: bool
    unless_function_mentions: NamePatterns = field(default_factory=lambda: NamePatterns.of([]))
    arg_binop: dict[int, list[str]] = field(default_factory=dict)
    then_callees: NamePatterns = field(default_factory=lambda: NamePatterns.of([]))
    same_arg: int = 0
    arg_literal: dict[int, int] = field(default_factory=dict)


@dataclass
class RulePack:
    language: str
    entry_points: list[EntryPointRule] = field(default_factory=list)
    sources: list[SourceRule] = field(default_factory=list)
    sanitizers: list[SanitizerRule] = field(default_factory=list)
    sinks: list[SinkRule] = field(default_factory=list)
    checks: list[CheckRule] = field(default_factory=list)
    tagged_template_sanitizes: frozenset[str] = frozenset()
    memory_model: bool = False  # track freed pointers (C/C++)
    # Source kinds reported at HIGH confidence in this language (argv/stdin in C programs).
    high_confidence_kinds: frozenset[str] = frozenset()
    writes_arg0: frozenset[str] = frozenset()

    def rule_ids(self) -> list[str]:
        return [s.id for s in self.sinks] + [c.id for c in self.checks]


def _regex(value: str | None) -> re.Pattern[str] | None:
    return re.compile(value) if value else None


def _sev(value: str | None, default: Severity = Severity.MEDIUM) -> Severity:
    return Severity(value.upper()) if value else default


def _conf(value: str | None, default: Confidence | None = None) -> Confidence | None:
    return Confidence(value.upper()) if value else default


def parse_pack(data: dict[str, Any]) -> RulePack:
    pack = RulePack(language=data["language"])
    for ep in data.get("entry_points", []):
        pack.entry_points.append(EntryPointRule(
            kind=ep["kind"],
            label=ep.get("label", ep["kind"]),
            decorators=NamePatterns.of(ep.get("decorators")),
            registrations=NamePatterns.of(ep.get("registrations")),
            exclude_params=frozenset(ep.get("exclude_params", [])),
            exclude_annotations=NamePatterns.of(ep.get("exclude_annotations")),
            handler_arg=ep.get("handler_arg"),
            source_kind=ep.get("source_kind", "http"),
            require_path_slash=bool(ep.get("require_path_slash", True)),
            names=frozenset(ep.get("names", [])),
        ))
    for src in data.get("sources", []):
        pack.sources.append(SourceRule(id=src["id"], kind=src.get("kind", "http"), label=src.get("label", src["id"]),
                                       patterns=NamePatterns.of(src["match"]),
                                       taints_args=tuple(src.get("taints_args", []))))
    for san in data.get("sanitizers", []):
        pack.sanitizers.append(SanitizerRule(
            patterns=NamePatterns.of(san["match"]),
            classes=frozenset(san.get("classes", ["*"])),
            arg_names={int(k): tuple(v) for k, v in san.get("arg_names", {}).items()},
        ))
    for sink in data.get("sinks", []):
        pack.sinks.append(SinkRule(
            id=sink["id"],
            vuln_class=sink["vuln_class"],
            title=sink.get("title", ""),
            message=sink.get("message", ""),
            severity=_sev(sink.get("severity")),
            callees=NamePatterns.of(sink.get("match")),
            assigns=NamePatterns.of(sink.get("assign")),
            args=tuple(sink.get("args", [0] if sink.get("match") else [])),
            all_args=bool(sink.get("all_args", False)),
            kwargs=tuple(sink.get("kwargs", [])),
            object_props=tuple(sink.get("object_props", [])),
            when_option=dict(sink.get("when_option", {})),
            unknown_origin=sink.get("unknown_origin", "never"),
            unknown_origin_confidence=_conf(sink.get("unknown_origin_confidence"), Confidence.MEDIUM)
            or Confidence.MEDIUM,
            source_kinds=frozenset(sink.get("source_kinds", [])),
            remap=dict(sink.get("remap", {})),
            unless_function_mentions=NamePatterns.of(sink.get("unless_function_mentions")),
            special=sink.get("special"),
            confidence=_conf(sink.get("confidence")),
            cwe=tuple(sink.get("cwe", [])),
            new_only=bool(sink.get("new_only", False)),
            strings_only=bool(sink.get("strings_only", False)),
            derived=sink.get("derived", "medium"),
        ))
    for chk in data.get("checks", []):
        pack.checks.append(CheckRule(
            id=chk["id"],
            vuln_class=chk["vuln_class"],
            title=chk.get("title", ""),
            message=chk.get("message", ""),
            severity=_sev(chk.get("severity")),
            confidence=_conf(chk.get("confidence"), Confidence.MEDIUM) or Confidence.MEDIUM,
            exploitability=chk.get("exploitability", "THEORETICAL"),
            kind=chk.get("kind", "call"),
            callees=NamePatterns.of(chk.get("match")),
            targets=NamePatterns.of(chk.get("target")),
            option_equals=dict(chk.get("option_equals", {})),
            option_contains=dict(chk.get("option_contains", {})),
            option_absent_or_not_in={k: list(v) for k, v in chk.get("option_absent_or_not_in", {}).items()},
            option_literal={k: int(v) for k, v in chk.get("option_literal", {}).items()},
            arg_equals={int(k): [str(x).lower() for x in v] for k, v in chk.get("arg_equals", {}).items()},
            arg_contains={int(k): [str(x).lower() for x in v] for k, v in chk.get("arg_contains", {}).items()},
            arg_nonliteral=tuple(chk.get("arg_nonliteral", [])),
            arg_attr={int(k): list(v) for k, v in chk.get("arg_attr", {}).items()},
            min_args=int(chk.get("min_args", 0)),
            max_args=chk.get("max_args"),
            assigned_name_regex=_regex(chk.get("assigned_name_regex")),
            context_regex=_regex(chk.get("context_regex")),
            context_severity=_sev(chk["context_severity"]) if chk.get("context_severity") else None,
            context_cwe=tuple(chk.get("context_cwe", [])),
            value_equals=list(chk.get("value_equals", [])),
            value_literal_min_len=chk.get("value_literal_min_len"),
            name_regex=_regex(chk.get("name_regex")),
            receiver_origin=NamePatterns.of(chk.get("receiver_origin")),
            path_regex=_regex(chk.get("path_regex")),
            cwe=tuple(chk.get("cwe", [])),
            new_only=bool(chk.get("new_only", False)),
            unless_function_mentions=NamePatterns.of(chk.get("unless_function_mentions")),
            arg_binop={int(k): list(v) for k, v in chk.get("arg_binop", {}).items()},
            then_callees=NamePatterns.of(chk.get("then")),
            same_arg=int(chk.get("same_arg", 0)),
            arg_literal={int(k): int(v) for k, v in chk.get("arg_literal", {}).items()},
        ))
    pack.memory_model = bool(data.get("memory_model", False))
    pack.high_confidence_kinds = frozenset(data.get("high_confidence_kinds", []))
    pack.writes_arg0 = frozenset(data.get("writes_arg0", []))
    pack.tagged_template_sanitizes = frozenset(data.get("tagged_template_sanitizes", []))
    return pack


@lru_cache(maxsize=16)
def load_pack(language: str) -> RulePack:
    """Load the built-in pack for a language (TypeScript shares JavaScript's)."""
    name = {"typescript": "javascript", "tsx": "javascript", "cpp": "c"}.get(language, language)
    text = resources.files("securelens.scanners.sast").joinpath("rules", f"{name}.yml").read_text("utf-8")
    pack = parse_pack(yaml.safe_load(text))
    pack.language = language
    return pack


def available_languages() -> list[str]:
    return ["python", "javascript", "typescript", "php", "java", "csharp", "go", "c", "cpp"]
