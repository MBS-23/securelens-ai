"""Summary-based, inter-procedural taint analysis over the SecureLens IR.

How it works
------------
1. **Index** every function across all parsed files and resolve imports
   (Python dotted modules, JavaScript relative modules, PHP's global function
   namespace).
2. **Entry points**: functions whose parameters are attacker- or
   model-controlled (route handlers, LLM tools) are identified from the rule
   pack's decorators and registration calls.
3. **Summaries** (fixed point, ≤3 rounds): each function is analysed with its
   parameters as symbolic taint. The summary records which parameters reach
   which sinks and which flow to the return value.
4. **Report**: every function is analysed again with real sources. At call
   sites, summaries are applied, so ``view()`` passing ``request.args`` into
   ``get_user()`` that concatenates it into SQL is reported at the SQL sink
   with the full path.

Confidence is evidence-based: a proven flow from an untrusted source is HIGH;
a dangerous sink fed by a dynamically built value of unknown origin is MEDIUM
or LOW; a pattern alone never becomes CONFIRMED.
"""

from __future__ import annotations

import logging
import posixpath
import re
import time
from dataclasses import dataclass, field, replace

from securelens.enums import Confidence, Exploitability, Severity
from securelens.scanners.sast import ir
from securelens.scanners.sast.rules import CheckRule, EntryPointRule, RulePack, SinkRule

log = logging.getLogger(__name__)

MAX_STEPS = 12
MAX_SUMMARY_ROUNDS = 3
MUTATING_METHODS = frozenset({"append", "extend", "insert", "add", "update", "push", "unshift", "set", "put",
                              "setdefault", "appendleft", "write", "writelines", "concat"})
FORMAT_CALLS = frozenset({"format", "sprintf", "vsprintf", "printf", "format_map", "join", "Sprintf", "Sprint",
                          "Sprintln", "Format", "Errorf", "snprintf", "formatted", "Join"})
ACCESSOR_METHODS = frozenset({"get", "getlist", "pop", "at", "item", "first", "last", "find", "findIndex", "has",
                              "includes", "indexOf", "contains", "count", "index", "setdefault"})
# Calls that transform strings (or build paths/URLs) without changing whether the
# data is attacker-controlled. Taint passes through them undiminished.
FREE_CALLEES = frozenset({"free", "cfree", "g_free", "kfree", "delete", "delete[]", "OPENSSL_free"})
STRING_TRANSFORMS = frozenset({
    "[]byte", "string", "[]rune", "String.valueOf", "valueOf", "toCharArray", "getBytes", "ToString", "Trim",
    "Sprintf", "Sprint", "Sprintln", "Format", "formatted", "Errorf", "snprintf", "sprintf",
    "ToLower", "ToUpper", "Substring", "Replace", "Split", "Join", "Format", "Concat", "c_str", "data", "substr",
    "append", "Sprint", "Sprintln", "strings.TrimSpace", "TrimSpace", "strings.ToLower", "ToLower", "Trim",
    "str", "String", "repr", "format", "sprintf", "vsprintf", "format_map", "join", "concat", "strip", "lstrip",
    "rstrip", "trim", "trimStart", "trimEnd", "lower", "upper", "toLowerCase", "toUpperCase", "casefold", "title",
    "capitalize", "replace", "replaceAll", "split", "rsplit", "splitlines", "slice", "substring", "substr",
    "encode", "decode", "toString", "valueOf", "padStart", "padEnd", "normalize", "get", "getlist", "pop",
    "decodeURIComponent", "decodeURI", "unescape", "atob", "btoa", "fromCharCode", "stringify", "dumps", "loads",
    "parse", "JSON.parse", "JSON.stringify", "json", "text", "read", "readline", "strtolower", "strtoupper",
    "trim", "ltrim", "rtrim", "substr", "str_replace", "implode", "explode", "urldecode", "rawurldecode",
    "base64_decode", "json_decode", "json_encode", "sprintf", "vsprintf", "nl2br", "ucfirst", "join", "path.join",
    "join", "resolve", "normpath", "abspath", "realpath", "expanduser", "urljoin", "URL", "Buffer.from", "from",
    "values", "items", "keys", "copy", "dict", "list", "tuple", "set", "sorted", "reversed", "Array.from", "map",
    "filter", "find", "first", "last", "at", "array_merge", "array_values", "array_map", "iter", "next",
    "URLSearchParams", "URL", "querystring.parse", "qs.parse", "parse_qs", "parse_qsl", "urlparse", "urlsplit",
    "Markup", "escape_string",
})
TRUSTED_SOURCE_KINDS_HIGH = frozenset({"http", "llm_output", "llm_tool_input", "retrieval"})
# Classes a strictly typed scalar (int, UUID, bool...) cannot carry a payload for.
INJECTION_CLASSES = frozenset({
    "sql_injection", "command_injection", "code_injection", "xss", "path_traversal", "ssrf", "template_injection",
    "open_redirect", "file_inclusion", "prompt_injection", "rag_prompt_injection", "llm_output_handling",
    "unsafe_tool_input", "insecure_deserialization", "unsafe_file_handling", "nosql_injection", "xxe",
})
SAFE_SCALAR_TYPES = frozenset({"int", "float", "bool", "uuid", "uuid.uuid", "datetime", "date", "decimal",
                               "positiveint", "nonnegativeint", "conint", "strictint", "strictbool", "number",
                               "boolean", "bigint"})
_FLASK_CONVERTER = re.compile(r"<(int|float|uuid|path|string|any)(?:\([^)]*\))?:(\w+)>")


# --------------------------------------------------------------------------
# Taint values
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceHit:
    source_id: str
    kind: str
    label: str
    path: str
    line: int
    code: str


@dataclass(frozen=True)
class Step:
    path: str
    line: int
    note: str


def _cap_steps(steps: tuple[Step, ...]) -> tuple[Step, ...]:
    if len(steps) <= MAX_STEPS:
        return steps
    return steps[:4] + steps[-(MAX_STEPS - 4):]


@dataclass(frozen=True)
class Taint:
    sources: frozenset[SourceHit] = frozenset()
    params: frozenset[int] = frozenset()
    sanitized: frozenset[str] = frozenset()
    steps: tuple[Step, ...] = ()
    # True when the data only reached this point through calls whose behaviour
    # is not modelled (library functions). Such flows are reported with lower
    # confidence, or not at all for sinks where that would mostly be noise.
    derived: bool = False

    def with_step(self, step: Step) -> Taint:
        if self.steps and self.steps[-1] == step:
            return self
        return replace(self, steps=_cap_steps(self.steps + (step,)))

    def sanitize(self, classes: frozenset[str]) -> Taint:
        return replace(self, sanitized=self.sanitized | classes)

    def safe_for(self, vuln_class: str) -> bool:
        return "*" in self.sanitized or vuln_class in self.sanitized


def merge_taint(a: Taint | None, b: Taint | None) -> Taint | None:
    if a is None:
        return b
    if b is None:
        return a
    steps = a.steps if (a.sources and not b.sources) or len(a.steps) >= len(b.steps) else b.steps
    return Taint(
        sources=a.sources | b.sources,
        params=a.params | b.params,
        sanitized=a.sanitized & b.sanitized,
        steps=steps,
        derived=a.derived and b.derived,
    )


@dataclass
class Val:
    taint: Taint | None = None
    dynamic: bool = False
    const: str | None = None
    origin: str | None = None
    func: ir.Function | None = None
    markup: bool = False  # built from string parts that contain HTML tags
    freed_at: int | None = None  # C/C++: line where this pointer was freed
    scalar: bool = False  # proven number/bool (literal or output of a full sanitizer)


CLEAN = Val()


def join_vals(a: Val | None, b: Val | None) -> Val:
    if a is None:
        return b or CLEAN
    if b is None:
        return a
    return Val(
        taint=merge_taint(a.taint, b.taint),
        dynamic=a.dynamic or b.dynamic,
        const=a.const if a.const == b.const else None,
        origin=a.origin if a.origin == b.origin else None,
        func=a.func if a.func is b.func else None,
        markup=a.markup or b.markup,
        freed_at=a.freed_at or b.freed_at,
        scalar=a.scalar and b.scalar,
    )


def join_envs(a: dict[str, Val], b: dict[str, Val]) -> dict[str, Val]:
    out = dict(a)
    for key, val in b.items():
        out[key] = join_vals(out.get(key), val) if key in out else val
    for key in a:
        if key not in b:
            # Present on one path only: keep it, but its constant value is no longer certain.
            v = out[key]
            out[key] = Val(taint=v.taint, dynamic=v.dynamic, const=None, origin=v.origin, func=v.func,
                           freed_at=v.freed_at)
    return out


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass
class RawFinding:
    rule_id: str
    vuln_class: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    exploitability: Exploitability
    path: str
    line: int
    col: int
    end_line: int
    function: str | None
    snippet: str
    kind: str  # taint | check
    sink: str = ""
    sources: list[SourceHit] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    cwe: tuple[str, ...] = ()
    source_kind: str | None = None
    language: str = ""
    base_class: str = ""  # the sink's own class when vuln_class was remapped (e.g. LLM output -> SQL sink)

    def key(self) -> tuple:
        return (self.rule_id, self.path, self.line, self.col, self.vuln_class)


@dataclass
class SinkHit:
    rule: SinkRule
    params: frozenset[int]
    path: str
    line: int
    col: int
    end_line: int
    function: str | None
    snippet: str
    sink: str
    steps: tuple[Step, ...]
    sanitized: frozenset[str]

    def signature(self) -> tuple:
        return (self.rule.id, self.path, self.line, self.col, self.params)


@dataclass
class Summary:
    ret_params: frozenset[int] = frozenset()
    ret_sources: frozenset[SourceHit] = frozenset()
    ret_dynamic: bool = False
    sink_hits: list[SinkHit] = field(default_factory=list)

    def signature(self) -> tuple:
        return (self.ret_params, len(self.ret_sources), self.ret_dynamic,
                frozenset(h.signature() for h in self.sink_hits))


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


class TaintEngine:
    def __init__(self, modules: list[ir.Module], packs: dict[str, RulePack], time_budget_seconds: float = 300.0):
        self.modules = modules
        self.packs = packs
        self.time_budget = time_budget_seconds
        self.summaries: dict[int, Summary] = {}
        self.entries: dict[int, tuple[EntryPointRule, str]] = {}
        self.findings: dict[tuple, RawFinding] = {}
        self.errors: list[str] = []
        self._by_module: dict[int, dict[str, ir.Function]] = {}
        self._py_modules: dict[str, list[ir.Module]] = {}
        self._js_modules: dict[str, ir.Module] = {}
        self._php_functions: dict[str, ir.Function] = {}
        self._php_methods: dict[str, ir.Function] = {}
        self._module_consts: dict[int, dict[str, Val]] = {}
        self._func_module: dict[int, ir.Module] = {}

    # ------------------------------------------------------------------ run

    def run(self) -> list[RawFinding]:
        started = time.monotonic()
        self._index()
        self._detect_entry_points()
        for _ in range(MAX_SUMMARY_ROUNDS):
            changed = False
            for module in self.modules:
                for func in module.functions:
                    before = self.summaries.get(id(func))
                    summary = self._analyze(module, func, mode="summary")
                    if summary is None:
                        continue
                    if before is None or before.signature() != summary.signature():
                        changed = True
                    self.summaries[id(func)] = summary
            if not changed or time.monotonic() - started > self.time_budget:
                break
        for module in self.modules:
            self._analyze(module, module.toplevel, mode="report")
            for func in module.functions:
                if time.monotonic() - started > self.time_budget * 2:
                    self.errors.append("analysis time budget exhausted; results may be incomplete")
                    break
                self._analyze(module, func, mode="report")
        return self._finalize()

    def _finalize(self) -> list[RawFinding]:
        # A proven flow supersedes an unknown-origin report at the same sink.
        proven = {(f.rule_id, f.path, f.line) for f in self.findings.values() if f.sources}
        out = [f for f in self.findings.values() if f.sources or (f.rule_id, f.path, f.line) not in proven]
        out.sort(key=lambda f: (f.path, f.line, f.rule_id))
        return out

    # ---------------------------------------------------------------- index

    def _index(self) -> None:
        for module in self.modules:
            table: dict[str, ir.Function] = {}
            for func in module.functions:
                table.setdefault(func.qualname, func)
                if not func.class_name:
                    table.setdefault(func.name, func)
                self._func_module[id(func)] = module
                if module.language == "php":
                    if func.class_name:
                        self._php_methods.setdefault(f"{func.class_name}.{func.name}".lower(), func)
                    else:
                        self._php_functions.setdefault(func.name.lower(), func)
            self._by_module[id(module)] = table
            self._func_module[id(module.toplevel)] = module
            if module.language == "python":
                dotted = module.path[:-3] if module.path.endswith(".py") else module.path
                if dotted.endswith("/__init__"):
                    dotted = dotted[: -len("/__init__")]
                parts = [p for p in dotted.split("/") if p]
                for i in range(len(parts)):
                    self._py_modules.setdefault(".".join(parts[i:]), []).append(module)
            elif module.language in {"javascript", "typescript", "tsx"}:
                base = module.path.rsplit(".", 1)[0]
                self._js_modules[base] = module
                if base.endswith("/index"):
                    self._js_modules.setdefault(base[: -len("/index")], module)
            self._module_consts[id(module)] = self._module_constants(module)

    def _module_constants(self, module: ir.Module) -> dict[str, Val]:
        consts: dict[str, Val] = {}
        for stmt in module.toplevel.body:
            if isinstance(stmt, ir.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ir.Name):
                value = ir.string_value(stmt.value)
                if value is not None:
                    consts[stmt.targets[0].id] = Val(const=value)
                elif isinstance(stmt.value, ir.Const):
                    consts[stmt.targets[0].id] = Val(const=str(stmt.value.value))
        return consts

    # --------------------------------------------------------- entry points

    def _detect_entry_points(self) -> None:
        for module in self.modules:
            pack = self.packs.get(module.language)
            if pack is None or not pack.entry_points:
                continue
            for func in module.functions:
                for rule in pack.entry_points:
                    if rule.names and func.name in rule.names and not func.class_name or (
                            rule.names and func.name in rule.names and module.language in {"java", "csharp"}):
                        self.entries[id(func)] = (rule, func.name)
                        func.entry_kind, func.entry_detail = rule.kind, func.name
                for dec in func.decorators:
                    name = ir.qualname(dec.func if isinstance(dec, ir.Call) else dec, module.imports)
                    for rule in pack.entry_points:
                        if rule.decorators and rule.decorators.matches(name):
                            self.entries[id(func)] = (rule, name or "")
                            func.entry_kind, func.entry_detail = rule.kind, name
            for func in [module.toplevel, *module.functions]:
                for stmt in ir.walk_stmts(func.body):
                    for expr in ir.stmt_exprs(stmt):
                        for node in ir.walk_exprs(expr):
                            if isinstance(node, ir.Call):
                                self._registration(module, pack, node)
                    if isinstance(stmt, ir.FunctionDef) and stmt.func is not None:
                        self._scan_nested_for_registrations(module, pack, stmt.func)

    def _scan_nested_for_registrations(self, module: ir.Module, pack: RulePack, func: ir.Function) -> None:
        for stmt in ir.walk_stmts(func.body):
            for expr in ir.stmt_exprs(stmt):
                for node in ir.walk_exprs(expr):
                    if isinstance(node, ir.Call):
                        self._registration(module, pack, node)

    def _registration(self, module: ir.Module, pack: RulePack, call: ir.Call) -> None:
        name = ir.qualname(call.func, module.imports)
        for rule in pack.entry_points:
            if not rule.registrations or not rule.registrations.matches(name):
                continue
            handlers: list[ir.Function] = []
            if rule.kind == "http_route":
                if len(call.args) < 2:
                    continue
                first = call.args[0]
                path_like = isinstance(first, ir.Str) and (first.value.startswith("/") or not rule.require_path_slash)
                if not path_like:
                    continue
                candidates = call.args[1:] if rule.handler_arg is None else call.args[rule.handler_arg:rule.handler_arg + 1]
            else:
                candidates = list(call.args)
                for arg in call.args:
                    if isinstance(arg, ir.DictLit):
                        for key, value in zip(arg.keys, arg.values, strict=False):
                            if isinstance(key, ir.Str) and key.value in {"execute", "handler", "run", "func",
                                                                         "callback", "fn"}:
                                candidates.append(value)
            for arg in candidates:
                if isinstance(arg, ir.FuncExpr) and arg.func is not None:
                    handlers.append(arg.func)
                elif isinstance(arg, ir.Name):
                    target = self._by_module[id(module)].get(arg.id)
                    if target is None and arg.id in module.imports:
                        target = self._resolve_alias(module, module.imports[arg.id])
                    if target is not None:
                        handlers.append(target)
                elif isinstance(arg, ir.Attr) and isinstance(arg.value, ir.Name):
                    alias = module.imports.get(arg.value.id)
                    if alias:
                        target = (self._resolve_js_export(module, alias[3:].partition("#")[0], arg.attr)
                                  if alias.startswith("js:") else self._resolve_alias(module, f"{alias}.{arg.attr}"))
                        if target is not None:
                            handlers.append(target)
            for handler in handlers:
                self.entries[id(handler)] = (rule, name or "")
                handler.entry_kind, handler.entry_detail = rule.kind, name

    # ------------------------------------------------------------ resolution

    def resolve_call(self, module: ir.Module, func: ir.Function, call: ir.Call) -> tuple[ir.Function | None, bool]:
        """Find the project function a call refers to. Returns (function, bound_method)."""
        callee = call.func
        table = self._by_module[id(module)]
        lang = module.language
        if isinstance(callee, ir.Name):
            name = callee.id
            if lang == "php":
                target = self._php_functions.get(name.lower())
                return target, False
            local = table.get(name)
            if local is not None and not local.class_name:
                return local, False
            alias = module.imports.get(name)
            if alias:
                return self._resolve_alias(module, alias), False
            return None, False
        if isinstance(callee, ir.Attr) and isinstance(callee.value, ir.Name):
            recv = callee.value.id
            if recv in {"self", "cls", "this", "$this", "self_", "static"} and func.class_name:
                if lang == "php":
                    return self._php_methods.get(f"{func.class_name}.{callee.attr}".lower()), True
                target = table.get(f"{func.class_name}.{callee.attr}")
                return target, True
            if lang == "php":
                return self._php_methods.get(f"{recv}.{callee.attr}".lower()), False
            alias = module.imports.get(recv)
            if alias:
                if alias.startswith("js:"):
                    return self._resolve_js_export(module, alias[3:], callee.attr), False
                return self._resolve_alias(module, f"{alias}.{callee.attr}"), False
        return None, False

    def _resolve_alias(self, module: ir.Module, alias: str) -> ir.Function | None:
        if alias.startswith("js:"):
            spec, _, export = alias[3:].partition("#")
            return self._resolve_js_export(module, spec, export or "default")
        if module.language == "python" and "." in alias:
            mod_name, _, func_name = alias.rpartition(".")
            candidates = self._py_modules.get(mod_name, [])
            best = self._closest(module, candidates)
            if best is not None:
                target = self._by_module[id(best)].get(func_name)
                if target is not None and not target.class_name:
                    return target
        return None

    def _closest(self, module: ir.Module, candidates: list[ir.Module]) -> ir.Module | None:
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        def shared(m: ir.Module) -> int:
            return len(posixpath.commonprefix([m.path, module.path]))
        return max(candidates, key=shared)

    def _resolve_js_export(self, module: ir.Module, spec: str, export: str) -> ir.Function | None:
        if not spec.startswith("."):
            return None
        base = posixpath.normpath(posixpath.join(posixpath.dirname(module.path), spec))
        base = base.rsplit(".", 1)[0] if base.endswith((".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")) else base
        target_module = self._js_modules.get(base)
        if target_module is None:
            return None
        qual = target_module.exports.get(export) or (export if export != "default" else None)
        if qual is None:
            return None
        return self._by_module[id(target_module)].get(qual)

    # -------------------------------------------------------------- analysis

    def _analyze(self, module: ir.Module, func: ir.Function, mode: str) -> Summary | None:
        pack = self.packs.get(module.language)
        if pack is None:
            return None
        ctx = _FunctionContext(self, module, pack, func, mode)
        try:
            ctx.run()
        except RecursionError:
            self.errors.append(f"{module.path}: expression nesting too deep in {func.qualname}")
            return None
        except Exception as exc:  # pragma: no cover - defensive: one function must not sink a scan
            log.exception("analysis failed for %s:%s", module.path, func.qualname)
            self.errors.append(f"{module.path}: analysis error in {func.qualname}: {type(exc).__name__}")
            return None
        return ctx.summary

    def report(self, finding: RawFinding) -> None:
        key = finding.key()
        existing = self.findings.get(key)
        rank = {Confidence.CONFIRMED: 3, Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}
        if existing is None or rank[finding.confidence] > rank[existing.confidence]:
            self.findings[key] = finding
        elif existing is not None and finding.sources:
            merged = {(s.path, s.line, s.source_id): s for s in existing.sources + finding.sources}
            existing.sources = list(merged.values())[:10]


class _FunctionContext:
    def __init__(self, engine: TaintEngine, module: ir.Module, pack: RulePack, func: ir.Function, mode: str,
                 env: dict[str, Val] | None = None, parent: _FunctionContext | None = None) -> None:
        self.engine = engine
        self.module = module
        self.pack = pack
        self.func = func
        self.mode = mode
        self.parent = parent
        self.env: dict[str, Val] = dict(env) if env is not None else {}
        self.summary = parent.summary if parent is not None else Summary()
        self.ret = Val()
        self._assign_targets: list[str] = []
        self._mentions: set[str] | None = None
        self.depth = parent.depth + 1 if parent else 0
        self._sequence: dict[str, dict[str, int]] = {}

    # --------------------------------------------------------------- setup

    @property
    def owner(self) -> ir.Function:
        ctx = self
        while ctx.parent is not None:
            ctx = ctx.parent
        return ctx.func

    def _line_text(self, line: int) -> str:
        if 0 < line <= len(self.module.lines):
            return self.module.lines[line - 1].strip()[:300]
        return ""

    def run(self, callback_taint: Taint | None = None) -> None:
        entry = self.engine.entries.get(id(self.func))
        for param in self.func.params:
            if param.name in {"self", "cls", "this", "$this"}:
                continue
            if entry is not None and self.mode == "report" or (entry is not None and self.parent is not None):
                rule, detail = entry
                annotation = param.annotation or ""
                if param.name in rule.exclude_params or (annotation and rule.exclude_annotations.matches(
                        annotation.split("[")[0].strip())):
                    self.env[param.name] = CLEAN
                    continue
                hit = SourceHit(source_id=f"entry.{rule.kind}", kind=rule.source_kind,
                                label=f"{rule.label} '{param.name.lstrip('$')}'", path=self.module.path,
                                line=self.func.line, code=self._line_text(self.func.line))
                sanitized = INJECTION_CLASSES if self._typed_scalar(param) else frozenset()
                self.env[param.name] = Val(taint=Taint(sources=frozenset({hit}), sanitized=sanitized, steps=(
                    Step(self.module.path, self.func.line, f"{rule.label} '{param.name.lstrip('$')}' "
                         f"({detail or rule.kind})"),)))
            elif self.parent is not None:
                self.env[param.name] = Val(taint=callback_taint) if callback_taint else CLEAN
            else:
                self.env[param.name] = Val(taint=Taint(
                    params=frozenset({param.index}),
                    steps=(Step(self.module.path, self.func.line, f"parameter '{param.name.lstrip('$')}' of "
                                f"{self.func.qualname}()"),)))
        if self.mode == "report" and self.parent is None:
            self._decorator_checks()
        self.block(self.func.body)
        if self.parent is None:
            taint = self.ret.taint
            self.summary.ret_params = taint.params if taint else frozenset()
            self.summary.ret_sources = taint.sources if taint else frozenset()
            self.summary.ret_dynamic = self.ret.dynamic

    def _typed_scalar(self, param: ir.Param) -> bool:
        # Only Python frameworks (FastAPI/pydantic, Flask converters) enforce
        # parameter types at runtime; TypeScript annotations do not.
        if self.module.language != "python":
            return False
        annotation = (param.annotation or "").split("[")[0].strip().lower()
        if annotation in SAFE_SCALAR_TYPES:
            return True
        for dec in self.func.decorators:
            if isinstance(dec, ir.Call) and dec.args and isinstance(dec.args[0], ir.Str):
                for converter, name in _FLASK_CONVERTER.findall(dec.args[0].value):
                    if name == param.name and converter in {"int", "float", "uuid"}:
                        return True
        return False

    # ---------------------------------------------------------- statements

    def block(self, stmts: list[ir.Stmt]) -> None:
        for stmt in stmts:
            self.stmt(stmt)

    def stmt(self, stmt: ir.Stmt) -> None:
        if isinstance(stmt, ir.Assign):
            self._assign_targets = [n for n in (ir.qualname(t) for t in stmt.targets) if n]
            value = self.eval(stmt.value)
            for target in stmt.targets:
                self.assign(target, value, stmt)
            self._assign_targets = []
        elif isinstance(stmt, ir.ExprStmt):
            self.eval(stmt.expr)
        elif isinstance(stmt, ir.Return):
            value = self.eval(stmt.value)
            self._route_return_sink(stmt, value)
            if value.taint is not None:
                value = Val(taint=value.taint.with_step(Step(self.module.path, stmt.line, "returned")),
                            dynamic=value.dynamic, const=value.const)
            self.ret = join_vals(self.ret, value)
        elif isinstance(stmt, ir.If):
            self.eval(stmt.test)
            before = dict(self.env)
            self.block(stmt.body)
            after_body = self.env
            self.env = dict(before)
            self.block(stmt.orelse)
            self.env = join_envs(after_body, self.env)
        elif isinstance(stmt, ir.Loop):
            before = dict(self.env)
            self.block(stmt.header)
            self.block(stmt.body)
            self.block(stmt.header)
            self.block(stmt.body)
            self.env = join_envs(before, self.env)
        elif isinstance(stmt, ir.Try):
            before = dict(self.env)
            self.block(stmt.body)
            merged = join_envs(before, self.env)
            for handler in stmt.handlers:
                self.env = dict(merged)
                self.block(handler)
                merged = join_envs(merged, self.env)
            self.env = merged
            self.block(stmt.final)
        elif isinstance(stmt, ir.FunctionDef) and stmt.func is not None:
            self.env[stmt.func.name] = Val(func=stmt.func)
            self.nested(stmt.func)

    def assign(self, target: ir.Expr, value: Val, stmt: ir.Assign) -> None:
        if self.pack.memory_model and isinstance(target, ir.Attr | ir.Subscript):
            self._check_freed_use(target.value, stmt.line, "write through")
        if isinstance(target, ir.Subscript):
            self._subscript_sink(target)
        name = ir.qualname(target)
        self._assign_checks(target, name, value, stmt)
        self._assign_sinks(target, value, stmt)
        if name is None:
            return
        if value.taint is not None:
            value = Val(taint=value.taint.with_step(Step(self.module.path, stmt.line,
                                                         f"assigned to {name.lstrip('$')}")),
                        dynamic=value.dynamic, const=value.const, origin=value.origin, func=value.func)
        if isinstance(target, ir.Subscript):
            # Writing into a container taints the container.
            base = ir.qualname(target.value)
            if base:
                self.env[base] = join_vals(self.env.get(base), Val(taint=value.taint, dynamic=value.dynamic))
            return
        if stmt.augmented and name in self.env:
            value = join_vals(self.env[name], value) if value.taint is None else value
        self.env[name] = value

    # --------------------------------------------------------- expressions

    def lookup(self, name: str) -> Val | None:
        if name in self.env:
            return self.env[name]
        return self.engine._module_consts[id(self.module)].get(name)

    def eval(self, expr: ir.Expr | None) -> Val:
        if expr is None:
            return CLEAN
        if isinstance(expr, ir.Str):
            return Val(const=expr.value)
        if isinstance(expr, ir.Const):
            return Val(const=None if expr.value is None else str(expr.value), scalar=True)
        if isinstance(expr, ir.Name):
            found = self.lookup(expr.id)
            if found is not None:
                return found
            hit = self.source(expr, ir.qualname(expr, self.module.imports), expr.id)
            return Val(taint=Taint(sources=frozenset({hit}), steps=(self._src_step(hit),))) if hit else CLEAN
        if isinstance(expr, ir.Attr):
            if self.pack.memory_model:
                self._check_freed_use(expr.value, expr.line, "dereference of")
            raw = ir.qualname(expr)
            if raw and raw in self.env:
                return self.env[raw]
            full = ir.qualname(expr, self.module.imports)
            self._attribute_checks(expr, full)
            hit = self.source(expr, full, raw)
            if hit:
                return Val(taint=Taint(sources=frozenset({hit}), steps=(self._src_step(hit),)))
            base = self.eval(expr.value)
            return Val(taint=base.taint, origin=base.origin)
        if isinstance(expr, ir.Subscript):
            if self.pack.memory_model:
                self._check_freed_use(expr.value, expr.line, "indexing into")
            raw = ir.qualname(expr)
            if raw and raw in self.env:
                self._subscript_sink(expr)
                return self.env[raw]
            hit = self.source(expr, ir.qualname(expr, self.module.imports), raw)
            if hit:
                return Val(taint=Taint(sources=frozenset({hit}), steps=(self._src_step(hit),)))
            base = self.eval(expr.value)
            self._subscript_sink(expr)
            return Val(taint=base.taint)
        if isinstance(expr, ir.Call):
            return self.call(expr)
        if isinstance(expr, ir.Concat):
            vals = [self.eval(p) for p in expr.parts]
            taint = None
            for v in vals:
                taint = merge_taint(taint, v.taint)
            dynamic = any(v.const is None and not v.scalar for v in vals) or (
                expr.kind == "percent" and vals[-1].const is None and not vals[-1].scalar)
            const = "".join(v.const for v in vals) if all(v.const is not None for v in vals) else None  # type: ignore[misc]
            if taint is not None and dynamic:
                taint = taint.with_step(Step(self.module.path, expr.line, "combined into a string"))
            markup = any(v.markup or (v.const is not None and "<" in v.const and ">" in v.const) for v in vals)
            return Val(taint=taint, dynamic=dynamic, const=const, markup=markup)
        if isinstance(expr, ir.DictLit):
            vals = [self.eval(v) for v in expr.values]
            for k in expr.keys:
                self.eval(k)
            self._role_message_sink_dict(expr, vals)
            taint = None
            for v in vals:
                taint = merge_taint(taint, v.taint)
            return Val(taint=taint)
        if isinstance(expr, ir.ListLit):
            vals = [self.eval(v) for v in expr.items]
            self._role_message_sink_list(expr, vals)
            taint = None
            for v in vals:
                taint = merge_taint(taint, v.taint)
            return Val(taint=taint, dynamic=any(v.dynamic for v in vals))
        if isinstance(expr, ir.Compare):
            left = self.eval(expr.left)
            rights = [self.eval(c) for c in expr.comparators]
            self._compare_checks(expr, left, rights)
            return CLEAN
        if isinstance(expr, ir.FuncExpr) and expr.func is not None:
            self.nested(expr.func)
            return Val(func=expr.func)
        if isinstance(expr, ir.Other):
            vals = [self.eval(c) for c in expr.children]
            taint = None
            for v in vals:
                taint = merge_taint(taint, v.taint)
            dynamic = any(v.dynamic for v in vals) if expr.kind in {"ternary", "boolop"} else False
            return Val(taint=taint, dynamic=dynamic)
        return CLEAN

    def nested(self, func: ir.Function, callback_taint: Taint | None = None) -> None:
        if self.depth > 6:
            return
        child = _FunctionContext(self.engine, self.module, self.pack, func, self.mode, env=self.env, parent=self)
        child.run(callback_taint=callback_taint)

    # ---------------------------------------------------------------- calls

    def call(self, call: ir.Call) -> Val:
        callee = ir.qualname(call.func, self.module.imports) or ""
        raw_callee = ir.qualname(call.func) or ""
        callees = _callee_variants(callee, raw_callee)
        receiver = self.eval(call.func.value) if isinstance(call.func, ir.Attr) else CLEAN
        func_args: list[tuple[int, ir.Function]] = []
        arg_vals: list[Val] = []
        for i, arg in enumerate(call.args):
            if isinstance(arg, ir.FuncExpr) and arg.func is not None:
                func_args.append((i, arg.func))
                arg_vals.append(Val(func=arg.func))
            else:
                arg_vals.append(self.eval(arg))
        kw_vals = {k: self.eval(v) for k, v in call.kwargs.items() if not isinstance(v, ir.FuncExpr)}
        for k, v in call.kwargs.items():
            if isinstance(v, ir.FuncExpr) and v.func is not None:
                func_args.append((-1, v.func))

        if isinstance(call.func, ir.FuncExpr) and call.func.func is not None:
            # Immediately-invoked function literal: go func(){...}(), (function(){...})().
            merged_args = None
            for v in arg_vals:
                merged_args = merge_taint(merged_args, v.taint)
            self.nested(call.func.func, callback_taint=merged_args)
        if callee == "__go__":
            self._goroutine_race(call)
        freed = self._free_call(call, callee)
        if self.pack.memory_model and isinstance(call.func, ir.Attr):
            self._check_freed_use(call.func.value, call.line, "calling a method through")
        if self.pack.memory_model and not freed and callee not in {"sizeof"}:
            for arg in call.args:
                if isinstance(arg, ir.Name):
                    self._check_freed_use(arg, call.line, f"passing to {callee or 'a call'}")
        self.check_sinks(call, callees, arg_vals, kw_vals)
        self._call_checks(call, callees, receiver, arg_vals, kw_vals)
        self._sequence_checks(call, callees)

        # Callbacks run with whatever data the call hands them — through code we
        # do not model, so that data is "derived".
        callback_taint = receiver.taint
        for v in arg_vals:
            if v.func is None:
                callback_taint = merge_taint(callback_taint, v.taint)
        if callback_taint is not None:
            callback_taint = replace(callback_taint, derived=True)
        for _, fn in func_args:
            self.nested(fn, callback_taint=callback_taint)

        rule, hit = self.source_rule(call, *(c + "()" for c in callees))
        if hit:
            tainted = Val(taint=Taint(sources=frozenset({hit}), steps=(self._src_step(hit),)), origin=callee)
            if rule is not None and rule.taints_args:
                for index in rule.taints_args:
                    if index < len(call.args):
                        target = call.args[index]
                        if isinstance(target, ir.Other) and target.children:
                            target = target.children[0]
                        name = ir.qualname(target)
                        if name:
                            self.env[name] = Val(taint=hit and tainted.taint.with_step(Step(
                                self.module.path, call.line, f"{callee}() writes untrusted data into {name}")))
            return tainted

        target, bound = self.engine.resolve_call(self.module, self.owner, call)
        if target is not None and id(target) in self.engine.summaries:
            result = self._apply_summary(call, target, bound, arg_vals, kw_vals)
        else:
            taint = receiver.taint if isinstance(call.func, ir.Attr) else None
            # The method name is known even when the receiver is an expression
            # without a name: ("a" + b).c_str(), "SELECT {}".format(x).
            last = call.func.attr if isinstance(call.func, ir.Attr) else (callee.rsplit(".", 1)[-1] if callee else "")
            if not (isinstance(call.func, ir.Attr) and last in ACCESSOR_METHODS):
                # An accessor's result comes from its receiver, not from the key it is given.
                for v in arg_vals:
                    taint = merge_taint(taint, v.taint)
                for v in kw_vals.values():
                    taint = merge_taint(taint, v.taint)
            dynamic = last in FORMAT_CALLS and any(v.const is None for v in arg_vals)
            if taint is not None and not (last in STRING_TRANSFORMS or callee in STRING_TRANSFORMS):
                taint = replace(taint, derived=True)
            origin = f"new:{callee}" if call.is_new else (callee or None)
            result = Val(taint=taint, dynamic=dynamic, origin=origin)
            if (callee in self.pack.writes_arg0 or last in self.pack.writes_arg0) and call.args:
                # C string/memory functions write their result into the first argument.
                dest = ir.qualname(call.args[0])
                written = None
                for v in arg_vals[1:]:
                    written = merge_taint(written, v.taint)
                if dest and written is not None:
                    self.env[dest] = join_vals(self.env.get(dest), Val(taint=written.with_step(
                        Step(self.module.path, call.line, f"{callee}() copies untrusted data into {dest}")),
                        dynamic=True))
            if last in MUTATING_METHODS and isinstance(call.func, ir.Attr):
                base = ir.qualname(call.func.value)
                if base and any(v.taint for v in arg_vals):
                    merged = None
                    for v in arg_vals:
                        merged = merge_taint(merged, v.taint)
                    self.env[base] = join_vals(self.env.get(base), Val(taint=merged))

        classes = self.sanitizer_classes(callees, call)
        if "__tagged__" in call.kwargs:
            classes |= self.pack.tagged_template_sanitizes
        if classes and result.taint is not None:
            if "*" in classes:
                return Val(origin=callee or None, scalar=True)
            result = Val(taint=result.taint.sanitize(frozenset(classes)), dynamic=False, origin=result.origin)
        elif classes and "*" in classes:
            result = Val(origin=callee or None, scalar=True)
        return result

    def _apply_summary(self, call: ir.Call, target: ir.Function, bound: bool, arg_vals: list[Val],
                       kw_vals: dict[str, Val]) -> Val:
        summary = self.engine.summaries[id(target)]
        params = [p for p in target.params if p.name not in {"self", "cls", "this", "$this"}]
        bound_vals: dict[int, Val] = {}
        positional = [p for p in params if p.kind in {"normal", "destructured"}]
        for i, val in enumerate(arg_vals):
            if i < len(positional):
                bound_vals[positional[i].index] = val
            else:
                vararg = next((p for p in params if p.kind == "vararg"), None)
                if vararg is not None:
                    bound_vals[vararg.index] = join_vals(bound_vals.get(vararg.index), val)
        by_name = {p.name: p for p in params}
        for name, val in kw_vals.items():
            if name in by_name:
                bound_vals[by_name[name].index] = val
        # Destructured parameters share an index; spread the bound value to all of them.
        for p in params:
            if p.kind == "destructured" and p.index not in bound_vals and arg_vals:
                bound_vals[p.index] = arg_vals[0]

        call_step = Step(self.module.path, call.line, f"passed to {target.qualname}()")
        for hit in summary.sink_hits:
            merged: Taint | None = None
            for index in hit.params:
                val = bound_vals.get(index)
                if val is not None:
                    merged = merge_taint(merged, val.taint)
            if merged is None or merged.safe_for(hit.rule.vuln_class):
                continue
            if merged.sources and self.mode == "report":
                self._report_taint(hit.rule, merged, path=hit.path, line=hit.line, col=hit.col,
                                   end_line=hit.end_line, function=hit.function, snippet=hit.snippet,
                                   sink=hit.sink, extra_steps=(call_step, *hit.steps))
            if merged.params:
                new_hit = SinkHit(rule=hit.rule, params=merged.params, path=hit.path, line=hit.line, col=hit.col,
                                  end_line=hit.end_line, function=hit.function, snippet=hit.snippet, sink=hit.sink,
                                  steps=_cap_steps(merged.steps + (call_step,) + hit.steps),
                                  sanitized=merged.sanitized)
                if all(h.signature() != new_hit.signature() for h in self.summary.sink_hits):
                    self.summary.sink_hits.append(new_hit)

        taint: Taint | None = None
        for index in summary.ret_params:
            val = bound_vals.get(index)
            if val is not None:
                taint = merge_taint(taint, val.taint)
        if summary.ret_sources:
            taint = merge_taint(taint, Taint(sources=summary.ret_sources,
                                             steps=(Step(self.module.path, call.line,
                                                         f"returned by {target.qualname}()"),)))
        if taint is not None:
            taint = taint.with_step(Step(self.module.path, call.line, f"returned from {target.qualname}()"))
        return Val(taint=taint, dynamic=summary.ret_dynamic, origin=target.qualname)

    # -------------------------------------------------------------- sources

    def source_rule(self, node: ir.Expr, *names: str | None):
        candidates = [n for n in dict.fromkeys(names) if n]
        if not candidates:
            return None, None
        for rule in self.pack.sources:
            if any(rule.patterns.matches_prefix(n) for n in candidates):
                return rule, SourceHit(source_id=rule.id, kind=rule.kind, label=rule.label, path=self.module.path,
                                       line=node.line, code=self._line_text(node.line))
        return None, None

    def source(self, node: ir.Expr, *names: str | None) -> SourceHit | None:
        return self.source_rule(node, *names)[1]

    def _src_step(self, hit: SourceHit) -> Step:
        return Step(hit.path, hit.line, f"untrusted data from {hit.label}")

    def sanitizer_classes(self, callees: tuple[str, ...], call: ir.Call | None = None) -> set[str]:
        classes: set[str] = set()
        for rule in self.pack.sanitizers:
            if rule.arg_names:
                if call is None or not all(
                        i < len(call.args) and (ir.qualname(call.args[i]) or ir.string_value(call.args[i]) or "")
                        in names for i, names in rule.arg_names.items()):
                    continue
            if any(rule.patterns.matches(c) for c in callees):
                classes |= rule.classes
        return classes

    # ---------------------------------------------------------------- sinks

    def check_sinks(self, call: ir.Call, callees: tuple[str, ...], arg_vals: list[Val],
                    kw_vals: dict[str, Val]) -> None:
        if not callees:
            return
        callee = callees[0]
        for sink in self.pack.sinks:
            if sink.special or not sink.callees or not any(sink.callees.matches(c) for c in callees):
                continue
            if sink.new_only and not call.is_new:
                continue
            if sink.when_option and not all(self._option_equals(call, k, v) for k, v in sink.when_option.items()):
                continue
            indices = range(len(arg_vals)) if sink.all_args else sink.args
            for i in indices:
                if i < len(arg_vals) and arg_vals[i].func is None:
                    if sink.strings_only and _object_like(call.args[i], arg_vals[i]):
                        continue
                    self._evaluate_sink(sink, call, callee, arg_vals[i], f"argument {i + 1} of {callee}()")
            for key in sink.kwargs:
                if key in kw_vals:
                    self._evaluate_sink(sink, call, callee, kw_vals[key], f"'{key}' of {callee}()")
            for prop in sink.object_props:
                for arg in call.args:
                    if isinstance(arg, ir.DictLit):
                        for k, v in zip(arg.keys, arg.values, strict=False):
                            if isinstance(k, ir.Str) and (k.value == prop or prop == "*"):
                                self._evaluate_sink(sink, call, callee, self.eval(v),
                                                    f"'{k.value}' of {callee}()")

    def _assign_sinks(self, target: ir.Expr, value: Val, stmt: ir.Assign) -> None:
        name = ir.qualname(target, self.module.imports)
        if not name:
            return
        for sink in self.pack.sinks:
            if sink.assigns and sink.assigns.matches(name):
                self._evaluate_sink(sink, stmt, name, value, f"assignment to {name}")

    def _role_message_sink_dict(self, expr: ir.DictLit, vals: list[Val]) -> None:
        sinks = [s for s in self.pack.sinks if s.special == "role_message"]
        if not sinks:
            return
        role = content = None
        for key, value, val in zip(expr.keys, expr.values, vals, strict=False):
            if isinstance(key, ir.Str):
                if key.value == "role" and isinstance(value, ir.Str):
                    role = value.value.lower()
                elif key.value in {"content", "text"}:
                    content = val
        if role in {"system", "developer"} and content is not None:
            for sink in sinks:
                self._evaluate_sink(sink, expr, f"{role} message content", content, f"{role} message content")

    def _role_message_sink_list(self, expr: ir.ListLit, vals: list[Val]) -> None:
        if len(expr.items) != 2 or not isinstance(expr.items[0], ir.Str):
            return
        role = expr.items[0].value.lower()
        if role not in {"system", "developer"}:
            return
        for sink in (s for s in self.pack.sinks if s.special == "role_message"):
            self._evaluate_sink(sink, expr, f"{role} message template", vals[1], f"{role} message template")

    # ------------------------------------------------------- memory model

    def _check_freed_use(self, base: ir.Expr | None, line: int, action: str) -> None:
        name = ir.qualname(base) if isinstance(base, ir.Name | ir.Attr) else None
        if not name:
            return
        val = self.env.get(name)
        if val is None or val.freed_at is None or self.mode != "report":
            return
        for sink in (s for s in self.pack.sinks if s.special == "use_after_free"):
            self.engine.report(RawFinding(
                rule_id=sink.id, vuln_class=sink.vuln_class, title=sink.title,
                message=(f"{sink.message or sink.title}: '{name}' was freed on line {val.freed_at} and is used "
                         f"again ({action} it) without being reassigned."),
                severity=sink.severity, confidence=sink.confidence or Confidence.MEDIUM,
                exploitability=Exploitability.LIKELY, path=self.module.path, line=line, col=0, end_line=line,
                function=self.owner.qualname, snippet=self._line_text(line), kind="taint",
                sink=f"use of freed pointer {name}",
                steps=[Step(self.module.path, val.freed_at, f"{name} freed"),
                       Step(self.module.path, line, f"{name} used after free")],
                cwe=sink.cwe, language=self.module.language, base_class=sink.vuln_class,
            ))

    def _free_call(self, call: ir.Call, callee: str) -> bool:
        last = callee.rsplit(".", 1)[-1]
        if not self.pack.memory_model or (callee not in FREE_CALLEES and last not in FREE_CALLEES) or not call.args:
            return False
        name = ir.qualname(call.args[0])
        if not name:
            return True
        previous = self.env.get(name)
        if previous is not None and previous.freed_at is not None and self.mode == "report":
            for sink in (s for s in self.pack.sinks if s.special == "double_free"):
                self.engine.report(RawFinding(
                    rule_id=sink.id, vuln_class=sink.vuln_class, title=sink.title,
                    message=f"{sink.message or sink.title}: '{name}' was already freed on line {previous.freed_at}.",
                    severity=sink.severity, confidence=sink.confidence or Confidence.MEDIUM,
                    exploitability=Exploitability.LIKELY, path=self.module.path, line=call.line, col=call.col,
                    end_line=call.end_line or call.line, function=self.owner.qualname,
                    snippet=self._line_text(call.line), kind="taint", sink=f"second free of {name}",
                    steps=[Step(self.module.path, previous.freed_at, f"{name} freed"),
                           Step(self.module.path, call.line, f"{name} freed again")],
                    cwe=sink.cwe, language=self.module.language, base_class=sink.vuln_class,
                ))
        base = previous or Val()
        self.env[name] = Val(taint=base.taint, origin=base.origin, freed_at=call.line)
        return True

    def _subscript_sink(self, expr: ir.Subscript) -> None:
        sinks = [s for s in self.pack.sinks if s.special == "subscript_index"]
        if not sinks or expr.index is None:
            return
        index_val = self.eval(expr.index)
        if index_val.taint is None:
            return
        for sink in sinks:
            self._evaluate_sink(sink, expr, "array index", index_val, "an array index")

    def _goroutine_race(self, call: ir.Call) -> None:
        """``go func() { counter++ }()`` — a goroutine writing a captured variable without a lock."""
        if self.mode != "report" or not call.args:
            return
        inner = call.args[0]
        if not (isinstance(inner, ir.Call) and isinstance(inner.func, ir.FuncExpr) and inner.func.func):
            return
        func = inner.func.func
        local = {p.name for p in func.params}
        writes: list[tuple[str, int]] = []
        locks = False
        for stmt in ir.walk_stmts(func.body):
            if isinstance(stmt, ir.Assign):
                for target in stmt.targets:
                    name = ir.qualname(target)
                    root = name.split(".")[0].split("[")[0] if name else None
                    if root and stmt.value is not None and isinstance(stmt.value, ir.Other) and stmt.value.kind == "decl":
                        local.add(root)
                    elif root and root not in local and root in self.env:
                        writes.append((root, stmt.line))
            for expr in ir.stmt_exprs(stmt):
                for node in ir.walk_exprs(expr):
                    if isinstance(node, ir.Call):
                        callee = ir.qualname(node.func) or ""
                        if callee.endswith((".Lock", ".RLock", ".Add", ".Store", ".Swap", ".CompareAndSwap")) or \
                                callee.startswith("atomic."):
                            locks = True
        if not writes or locks:
            return
        for chk in (c for c in self.pack.checks if c.kind == "goroutine_capture_write"):
            name, line = writes[0]
            self.engine.report(RawFinding(
                rule_id=chk.id, vuln_class=chk.vuln_class, title=chk.title,
                message=(f"{chk.message or chk.title}: the goroutine started on line {call.line} writes '{name}' "
                         f"(line {line}), which is shared with the enclosing function, without a mutex or atomic."),
                severity=chk.severity, confidence=chk.confidence, exploitability=Exploitability(chk.exploitability),
                path=self.module.path, line=line, col=0, end_line=line, function=self.owner.qualname,
                snippet=self._line_text(line), kind="check", cwe=chk.cwe, language=self.module.language,
            ))

    def _sequence_checks(self, call: ir.Call, callees: tuple[str, ...]) -> None:
        if self.mode != "report":
            return
        for chk in self.pack.checks:
            if chk.kind != "sequence":
                continue
            arg = ir.qualname(call.args[chk.same_arg]) if len(call.args) > chk.same_arg else None
            if not arg:
                continue
            seen = self._sequence.setdefault(chk.id, {})
            if any(chk.callees.matches(c) for c in callees):
                seen[arg] = call.line
            elif arg in seen and any(chk.then_callees.matches(c) for c in callees):
                self._report_check(chk, call)
                del seen[arg]

    def _route_return_sink(self, stmt: ir.Return, value: Val) -> None:
        if not (value.markup and value.dynamic and value.taint is not None):
            return
        entry = self.engine.entries.get(id(self.func))
        if entry is None or entry[0].kind != "http_route":
            return
        for sink in (s for s in self.pack.sinks if s.special == "route_return_html"):
            self._evaluate_sink(sink, stmt, "the HTTP response", value, "the HTML response body")

    def _function_mentions(self, patterns) -> bool:
        if self._mentions is None:
            names: set[str] = set()
            for stmt in ir.walk_stmts(self.owner.body):
                for expr in ir.stmt_exprs(stmt):
                    for node in ir.walk_exprs(expr):
                        qn = ir.qualname(node, self.module.imports)
                        if qn:
                            names.add(qn)
            for dec in self.owner.decorators:
                qn = ir.qualname(dec.func if isinstance(dec, ir.Call) else dec, self.module.imports)
                if qn:
                    names.add(qn)
            for param in self.owner.params:
                names.add(param.name)
            self._mentions = names
        return any(patterns.matches_prefix(n) for n in self._mentions)

    def _evaluate_sink(self, sink: SinkRule, node: ir.Node, callee: str, val: Val, desc: str) -> None:
        taint = val.taint
        if taint is not None and taint.safe_for(sink.vuln_class):
            taint = None
        if sink.unless_function_mentions and self._function_mentions(sink.unless_function_mentions):
            return
        if taint is not None and taint.sources:
            sources = [s for s in taint.sources if not sink.source_kinds or s.kind in sink.source_kinds]
            if sources and taint.derived and sink.derived == "skip":
                return
            if sources:
                if self.mode == "report":
                    self._report_taint(sink, replace(taint, sources=frozenset(sources)), path=self.module.path,
                                       line=node.line, col=node.col, end_line=node.end_line or node.line,
                                       function=self.owner.qualname, snippet=self._line_text(node.line),
                                       sink=desc, extra_steps=(Step(self.module.path, node.line, f"reaches {desc}"),))
                return
        if taint is not None and taint.params:
            hit = SinkHit(rule=sink, params=taint.params, path=self.module.path, line=node.line, col=node.col,
                          end_line=node.end_line or node.line, function=self.owner.qualname,
                          snippet=self._line_text(node.line), sink=desc,
                          steps=_cap_steps(taint.steps + (Step(self.module.path, node.line, f"reaches {desc}"),)),
                          sanitized=taint.sanitized)
            if all(h.signature() != hit.signature() for h in self.summary.sink_hits):
                self.summary.sink_hits.append(hit)
        if self.mode != "report" or sink.unknown_origin == "never" or sink.source_kinds:
            return
        if val.func is not None or (taint is None and val.taint is not None):
            return  # sanitised for this class, or a function reference
        qualifies = (sink.unknown_origin == "dynamic" and val.dynamic) or (
            sink.unknown_origin == "nonliteral" and val.const is None)
        if not qualifies:
            return
        steps = list(taint.steps) if taint is not None else []
        steps.append(Step(self.module.path, node.line, f"reaches {desc}"))
        origin = ("built dynamically from values whose origin could not be traced" if val.dynamic
                  else "a non-constant value whose origin could not be traced")
        self.engine.report(RawFinding(
            rule_id=sink.id, vuln_class=sink.vuln_class, title=sink.title,
            message=f"{sink.message or sink.title}. The value is {origin}.",
            severity=sink.severity, confidence=sink.unknown_origin_confidence,
            exploitability=Exploitability.POSSIBLE, path=self.module.path, line=node.line, col=node.col,
            end_line=node.end_line or node.line, function=self.owner.qualname, snippet=self._line_text(node.line),
            kind="taint", sink=desc, steps=steps, cwe=sink.cwe, language=self.module.language,
        ))

    def _report_taint(self, rule: SinkRule, taint: Taint, *, path: str, line: int, col: int,
                      end_line: int, function: str | None, snippet: str, sink: str,
                      extra_steps: tuple[Step, ...]) -> None:
        sources = sorted(taint.sources, key=lambda s: (s.path, s.line))
        kinds = {s.kind for s in sources}
        source_kind = next((k for k in ("llm_output", "llm_tool_input", "retrieval", "http", "user_input")
                            if k in kinds), sources[0].kind if sources else None)
        high = bool(kinds & (TRUSTED_SOURCE_KINDS_HIGH | self.pack.high_confidence_kinds))
        confidence = rule.confidence or (Confidence.HIGH if high else Confidence.MEDIUM)
        exploitability = Exploitability.PROVEN_DATAFLOW if high else Exploitability.LIKELY
        if taint.derived and rule.derived == "medium":
            confidence = Confidence.MEDIUM if confidence == Confidence.HIGH else confidence
            exploitability = Exploitability.LIKELY
        vuln_class = rule.remap.get(source_kind or "", rule.vuln_class)
        steps = list(_cap_steps(taint.steps + extra_steps))
        labels = ", ".join(dict.fromkeys(s.label for s in sources))
        message = f"{rule.message or rule.title}. Untrusted data from {labels} reaches {sink}."
        self.engine.report(RawFinding(
            rule_id=rule.id, vuln_class=vuln_class, title=rule.title, message=message, severity=rule.severity,
            confidence=confidence, exploitability=exploitability, path=path, line=line, col=col, end_line=end_line,
            function=function, snippet=snippet, kind="taint", sink=sink, sources=sources, steps=steps, cwe=rule.cwe,
            source_kind=source_kind, language=self.module.language, base_class=rule.vuln_class,
        ))

    # ------------------------------------------------------------- checks

    def _option_expr(self, call: ir.Call, key: str) -> ir.Expr | None:
        if key in call.kwargs:
            return call.kwargs[key]
        # Options objects: f(x, {key: v}) and f(x, options={key: v}).
        for arg in [*call.args, *call.kwargs.values()]:
            if isinstance(arg, ir.DictLit):
                for k, v in zip(arg.keys, arg.values, strict=False):
                    if isinstance(k, ir.Str) and k.value == key:
                        return v
        return None

    def _option_equals(self, call: ir.Call, key: str, expected: object) -> bool:
        expr = self._option_expr(call, key)
        return expr is not None and _value_equals(expr, expected, self.lookup)

    def _call_checks(self, call: ir.Call, callees: tuple[str, ...], receiver: Val, arg_vals: list[Val],
                     kw_vals: dict[str, Val]) -> None:
        if self.mode != "report" or not callees:
            return
        for chk in self.pack.checks:
            if chk.kind != "call" or not any(chk.callees.matches(c) for c in callees):
                continue
            if chk.new_only and not call.is_new:
                continue
            if len(call.args) < chk.min_args or (chk.max_args is not None and len(call.args) > chk.max_args):
                continue
            if chk.path_regex and not chk.path_regex.search(self.module.path):
                continue
            if not all(self._option_equals(call, k, v) for k, v in chk.option_equals.items()):
                continue
            if chk.option_contains and not all(
                    (any(_option_contains(a, v) for a in [*call.args, *call.kwargs.values()]) if k == "*"
                     else _option_contains(self._option_expr(call, k), v))
                    for k, v in chk.option_contains.items()):
                continue
            skip = False
            for key, allowed in chk.option_absent_or_not_in.items():
                expr = self._option_expr(call, key)
                if expr is not None:
                    rendered = ir.qualname(expr, self.module.imports) or ir.string_value(expr) or ""
                    if any(rendered == a or rendered.endswith("." + a) for a in allowed):
                        skip = True
            if skip:
                continue
            if chk.option_literal and not all(
                    (lit := ir.string_value(self._option_expr(call, key))) is not None and len(lit) >= min_len
                    and not _placeholder(lit) for key, min_len in chk.option_literal.items()):
                continue
            if chk.arg_equals and not all(i < len(arg_vals) and (arg_vals[i].const or "").lower() in allowed
                                          for i, allowed in chk.arg_equals.items()):
                continue
            if chk.arg_contains and not all(i < len(arg_vals) and any(a in (arg_vals[i].const or "").lower()
                                                                      for a in allowed)
                                            for i, allowed in chk.arg_contains.items()):
                continue
            if chk.arg_nonliteral and not all(i < len(arg_vals) and arg_vals[i].const is None
                                              and arg_vals[i].func is None for i in chk.arg_nonliteral):
                continue
            if chk.arg_attr and not all(
                    i < len(call.args) and any((ir.qualname(call.args[i], self.module.imports) or "").endswith(a)
                                               for a in pats) for i, pats in chk.arg_attr.items()):
                continue
            if chk.assigned_name_regex and not any(chk.assigned_name_regex.search(t) for t in self._assign_targets):
                continue
            if chk.receiver_origin and not chk.receiver_origin.matches_prefix(receiver.origin or ""):
                continue
            if chk.arg_literal and not all(
                    i < len(call.args) and (lit := ir.string_value(call.args[i])) is not None
                    and len(lit) >= min_len and not _placeholder(lit) for i, min_len in chk.arg_literal.items()):
                continue
            if chk.arg_binop and not all(i < len(call.args) and _binop_nonconst(call.args[i], ops)
                                         for i, ops in chk.arg_binop.items()):
                continue
            if chk.unless_function_mentions and self._function_mentions(chk.unless_function_mentions):
                continue
            self._report_check(chk, call, context_texts=self._context_texts(call))

    def _context_texts(self, call: ir.Call) -> list[str]:
        texts = list(self._assign_targets)
        for arg in list(call.args) + list(call.kwargs.values()):
            for node in ir.walk_exprs(arg):
                qn = ir.qualname(node)
                if qn:
                    texts.append(qn)
        return texts

    def _assign_checks(self, target: ir.Expr, name: str | None, value: Val, stmt: ir.Assign) -> None:
        if self.mode != "report" or name is None:
            return
        full = ir.qualname(target, self.module.imports) or name
        for chk in self.pack.checks:
            if chk.kind != "assign" or not (chk.targets.matches(full) or chk.targets.matches(name)):
                continue
            if chk.path_regex and not chk.path_regex.search(self.module.path):
                continue
            ok = False
            if chk.value_equals:
                ok = stmt.value is not None and any(_value_equals(stmt.value, v, self.lookup) for v in chk.value_equals)
            elif chk.value_literal_min_len is not None:
                literal = ir.string_value(stmt.value)
                ok = literal is not None and len(literal) >= chk.value_literal_min_len and not _placeholder(literal)
            else:
                ok = True
            if ok:
                self._report_check(chk, stmt)

    def _decorator_checks(self) -> None:
        for chk in self.pack.checks:
            if chk.kind != "decorator":
                continue
            for dec in self.func.decorators:
                name = ir.qualname(dec.func if isinstance(dec, ir.Call) else dec, self.module.imports)
                if chk.callees.matches(name):
                    self._report_check(chk, self.func)

    def _attribute_checks(self, expr: ir.Attr, full: str | None) -> None:
        if self.mode != "report" or not full:
            return
        for chk in self.pack.checks:
            if chk.kind == "attribute" and chk.callees.matches(full):
                self._report_check(chk, expr)

    def _compare_checks(self, expr: ir.Compare, left: Val, rights: list[Val]) -> None:
        if self.mode != "report":
            return
        operands = [expr.left, *expr.comparators]
        vals = [left, *rights]
        for chk in self.pack.checks:
            if chk.kind != "compare" or chk.name_regex is None:
                continue
            if chk.callees and not any(op in chk.callees.raw for op in expr.ops):
                continue
            named = [i for i, o in enumerate(operands)
                     if (nm := _operand_name(o)) and chk.name_regex.search(nm)]
            if not named:
                continue
            literal = [i for i, (o, v) in enumerate(zip(operands, vals, strict=False))
                       if isinstance(o, ir.Str) and o.value and not _placeholder(o.value)]
            if chk.value_literal_min_len is not None:
                if any(len(operands[i].value) >= chk.value_literal_min_len for i in literal if i not in named):  # type: ignore[union-attr]
                    self._report_check(chk, expr)
            elif chk.min_args == 0:
                self._report_check(chk, expr)

    def _report_check(self, chk: CheckRule, node: ir.Node, context_texts: list[str] | None = None) -> None:
        severity, cwe = chk.severity, chk.cwe
        message = chk.message or chk.title
        if chk.context_regex and context_texts and any(chk.context_regex.search(t) for t in context_texts):
            severity = chk.context_severity or severity
            cwe = tuple(dict.fromkeys(chk.context_cwe + cwe))
            message += " It is applied to what looks like a password or secret."
        self.engine.report(RawFinding(
            rule_id=chk.id, vuln_class=chk.vuln_class, title=chk.title, message=message, severity=severity,
            confidence=chk.confidence, exploitability=Exploitability(chk.exploitability), path=self.module.path,
            line=node.line, col=node.col, end_line=node.end_line or node.line,
            function=self.owner.qualname if self.owner.name != "<module>" else None,
            snippet=self._line_text(node.line), kind="check", cwe=cwe, language=self.module.language,
        ))




def _callee_variants(*names: str) -> tuple[str, ...]:
    """Name forms a rule may use: as written, alias-resolved, without a C++ ``std.``
    prefix, and without a Java/C# package prefix (``javax.crypto.Cipher.getInstance``
    also matches ``Cipher.getInstance``)."""
    out: list[str] = []
    for name in names:
        if not name:
            continue
        out.append(name)
        if name.startswith("std."):
            out.append(name[4:])
        parts = name.split(".")
        if len(parts) > 2 and "(" not in name and not name.startswith(("$", "js:")):
            out.append(".".join(parts[-2:]))
    return tuple(dict.fromkeys(out))


def _binop_nonconst(expr: ir.Expr, ops: list[str]) -> bool:
    """True for ``a * b`` style arithmetic (with at least one non-constant operand)."""
    for node in ir.walk_exprs(expr):
        if isinstance(node, ir.Other) and node.kind.startswith("binop:") and node.kind[6:] in ops:
            if any(not isinstance(c, ir.Const | ir.Str) for c in node.children):
                return True
    return False


def _operand_name(expr: ir.Expr | None) -> str | None:
    """The identifier a comparison operand refers to: ``password`` for
    ``password``, ``user.password``, ``$_POST['password']`` or ``md5($password)``."""
    if isinstance(expr, ir.Subscript) and isinstance(expr.index, ir.Str):
        return expr.index.value
    if isinstance(expr, ir.Attr):
        return expr.attr
    if isinstance(expr, ir.Name):
        return expr.id.lstrip("$")
    if isinstance(expr, ir.Call) and expr.args:
        return _operand_name(expr.args[0])
    return None


def _object_like(expr: ir.Expr, val: Val) -> bool:
    """True when a value is clearly an object rather than a string."""
    if isinstance(expr, ir.DictLit | ir.ListLit):
        return True
    if isinstance(expr, ir.Call) and expr.is_new:
        return True
    return bool(val.origin and val.origin.startswith("new:"))


def _value_equals(expr: ir.Expr, expected: object, lookup) -> bool:
    if isinstance(expr, ir.Name):
        found = lookup(expr.id)
        if found is not None and found.const is not None:
            return str(found.const).lower() == str(expected).lower()
    if isinstance(expected, bool):
        if isinstance(expr, ir.Const):
            return expr.value is expected or (isinstance(expr.value, int) and bool(expr.value) is expected
                                              and not isinstance(expr.value, float) and expr.value in (0, 1))
        if isinstance(expr, ir.Name):
            return expr.id.lower() == str(expected).lower()
        return False
    if isinstance(expr, ir.Str):
        return expr.value.lower() == str(expected).lower()
    if isinstance(expr, ir.Const):
        return str(expr.value).lower() == str(expected).lower()
    if isinstance(expr, ir.Name | ir.Attr):
        qn = ir.qualname(expr) or ""
        return qn.lower() == str(expected).lower() or qn.lower().endswith("." + str(expected).lower())
    return False


def _option_contains(expr: ir.Expr | None, expected: object) -> bool:
    if expr is None:
        return False
    target = str(expected).lower()
    for node in ir.walk_exprs(expr):
        if isinstance(node, ir.Str) and node.value.lower() == target:
            return True
        if isinstance(node, ir.Const) and str(node.value).lower() == target:
            return True
        if isinstance(node, ir.Name | ir.Attr):
            qn = (ir.qualname(node) or "").lower()
            if qn == target or qn.endswith("." + target):
                return True
    return False


_PLACEHOLDER_WORDS = ("changeme", "change-me", "change_me", "example", "placeholder", "your-", "your_", "xxxx",
                      "<", "${", "{{", "todo", "dummy", "sample", "replace", "redacted", "****")


def _placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(w in lowered for w in _PLACEHOLDER_WORDS) or len(set(value)) <= 2
