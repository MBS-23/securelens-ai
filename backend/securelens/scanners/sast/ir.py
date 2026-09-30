"""A small, language-neutral intermediate representation for security analysis.

Each language frontend (Python via ``ast``; JavaScript, TypeScript and PHP via
tree-sitter) lowers source code into these nodes. The taint engine and the
structural checks only ever see this IR, which is what lets one engine and one
rule format serve several languages — and what makes adding Java, C# or Go a
matter of writing a frontend.

The IR is deliberately lossy: it keeps what matters for data-flow and API
misuse (names, calls, assignments, string construction, control flow, function
boundaries) and folds everything else into ``Other``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(eq=False)
class Node:
    line: int
    col: int = 0
    end_line: int = 0


# --------------------------------------------------------------------------
# Expressions
# --------------------------------------------------------------------------


@dataclass(eq=False)
class Name(Node):
    id: str = ""


@dataclass(eq=False)
class Attr(Node):
    value: Expr | None = None
    attr: str = ""


@dataclass(eq=False)
class Subscript(Node):
    value: Expr | None = None
    index: Expr | None = None


@dataclass(eq=False)
class Call(Node):
    func: Expr | None = None
    args: list[Expr] = field(default_factory=list)
    kwargs: dict[str, Expr] = field(default_factory=dict)
    is_new: bool = False
    # PHP language constructs (echo, include, backticks) and similar are
    # lowered to calls with a builtin name and this flag set.
    construct: bool = False


@dataclass(eq=False)
class Str(Node):
    value: str = ""


@dataclass(eq=False)
class Const(Node):
    value: object = None


@dataclass(eq=False)
class Concat(Node):
    """String construction: ``+`` / ``.`` concatenation, f-strings, template
    literals, ``%`` formatting and interpolated PHP strings."""

    parts: list[Expr] = field(default_factory=list)
    kind: str = "concat"


@dataclass(eq=False)
class DictLit(Node):
    keys: list[Expr | None] = field(default_factory=list)
    values: list[Expr] = field(default_factory=list)


@dataclass(eq=False)
class ListLit(Node):
    items: list[Expr] = field(default_factory=list)


@dataclass(eq=False)
class Compare(Node):
    left: Expr | None = None
    ops: list[str] = field(default_factory=list)
    comparators: list[Expr] = field(default_factory=list)


@dataclass(eq=False)
class FuncExpr(Node):
    func: Function | None = None


@dataclass(eq=False)
class Other(Node):
    """Any other expression; taint flows through its children."""

    children: list[Expr] = field(default_factory=list)
    kind: str = ""


Expr = Name | Attr | Subscript | Call | Str | Const | Concat | DictLit | ListLit | Compare | FuncExpr | Other


# --------------------------------------------------------------------------
# Statements
# --------------------------------------------------------------------------


@dataclass(eq=False)
class Assign(Node):
    targets: list[Expr] = field(default_factory=list)
    value: Expr | None = None
    augmented: bool = False


@dataclass(eq=False)
class ExprStmt(Node):
    expr: Expr | None = None
    exits: bool = False  # raise / throw: control does not continue past this statement


@dataclass(eq=False)
class Return(Node):
    value: Expr | None = None


@dataclass(eq=False)
class If(Node):
    test: Expr | None = None
    body: list[Stmt] = field(default_factory=list)
    orelse: list[Stmt] = field(default_factory=list)


@dataclass(eq=False)
class Loop(Node):
    header: list[Stmt] = field(default_factory=list)
    body: list[Stmt] = field(default_factory=list)


@dataclass(eq=False)
class Try(Node):
    body: list[Stmt] = field(default_factory=list)
    handlers: list[list[Stmt]] = field(default_factory=list)
    final: list[Stmt] = field(default_factory=list)


@dataclass(eq=False)
class FunctionDef(Node):
    func: Function | None = None


Stmt = Assign | ExprStmt | Return | If | Loop | Try | FunctionDef


# --------------------------------------------------------------------------
# Functions and modules
# --------------------------------------------------------------------------


@dataclass(eq=False)
class Param:
    name: str
    index: int
    default: Expr | None = None
    annotation: str | None = None
    kind: str = "normal"  # normal | vararg | kwarg | destructured


@dataclass(eq=False)
class Function(Node):
    name: str = "<anonymous>"
    qualname: str = "<anonymous>"
    params: list[Param] = field(default_factory=list)
    body: list[Stmt] = field(default_factory=list)
    decorators: list[Expr] = field(default_factory=list)
    class_name: str | None = None
    is_method: bool = False
    # Set by frontends when the function is a web route handler or an
    # LLM-callable tool, whose parameters are attacker/model controlled.
    entry_kind: str | None = None
    entry_detail: str | None = None
    nested: bool = False


@dataclass(eq=False)
class Module:
    path: str
    language: str
    toplevel: Function
    functions: list[Function] = field(default_factory=list)
    # local alias -> fully qualified target, e.g. {"sp": "subprocess",
    # "run": "subprocess.run", "getUser": "js:./db#getUser"}
    imports: dict[str, str] = field(default_factory=dict)
    # exported name -> local function qualname (JavaScript/TypeScript)
    exports: dict[str, str] = field(default_factory=dict)
    lines: list[str] = field(default_factory=list)
    parse_errors: int = 0

    def snippet(self, line: int, context: int = 0) -> str:
        if not self.lines or line <= 0:
            return ""
        start = max(1, line - context)
        end = min(len(self.lines), line + context)
        return "\n".join(self.lines[start - 1 : end])


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def qualname(expr: Expr | None, aliases: dict[str, str] | None = None) -> str | None:
    """Dotted name of an expression: ``request.args.get``, ``$_GET[id]``,
    ``request.get_json().get``. Import aliases are resolved on the root name."""
    if expr is None:
        return None
    if isinstance(expr, Name):
        if aliases and expr.id in aliases and not aliases[expr.id].startswith(("js:", "py:")):
            return aliases[expr.id]
        return expr.id
    if isinstance(expr, Attr):
        base = qualname(expr.value, aliases)
        return f"{base}.{expr.attr}" if base else None
    if isinstance(expr, Subscript):
        base = qualname(expr.value, aliases)
        if base is None:
            return None
        if isinstance(expr.index, Str):
            return f"{base}[{expr.index.value}]"
        return f"{base}[]"
    if isinstance(expr, Call):
        base = qualname(expr.func, aliases)
        return f"{base}()" if base else None
    return None


def iter_child_exprs(expr: Expr | None):
    """Direct sub-expressions (used for generic taint propagation)."""
    if expr is None:
        return
    if isinstance(expr, Attr):
        yield from ([expr.value] if expr.value is not None else [])
    elif isinstance(expr, Subscript):
        if expr.value is not None:
            yield expr.value
        if expr.index is not None:
            yield expr.index
    elif isinstance(expr, Call):
        if expr.func is not None:
            yield expr.func
        yield from expr.args
        yield from expr.kwargs.values()
    elif isinstance(expr, Concat):
        yield from expr.parts
    elif isinstance(expr, DictLit):
        yield from (k for k in expr.keys if k is not None)
        yield from expr.values
    elif isinstance(expr, ListLit):
        yield from expr.items
    elif isinstance(expr, Compare):
        if expr.left is not None:
            yield expr.left
        yield from expr.comparators
    elif isinstance(expr, Other):
        yield from expr.children


def walk_exprs(expr: Expr | None):
    """Pre-order traversal of an expression tree (does not enter function bodies)."""
    if expr is None:
        return
    stack = [expr]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, FuncExpr):
            continue
        stack.extend(reversed(list(iter_child_exprs(node))))


def walk_stmts(body: list[Stmt]):
    """All statements in a body, recursively (does not enter nested functions)."""
    for stmt in body:
        yield stmt
        if isinstance(stmt, If):
            yield from walk_stmts(stmt.body)
            yield from walk_stmts(stmt.orelse)
        elif isinstance(stmt, Loop):
            yield from walk_stmts(stmt.header)
            yield from walk_stmts(stmt.body)
        elif isinstance(stmt, Try):
            yield from walk_stmts(stmt.body)
            for handler in stmt.handlers:
                yield from walk_stmts(handler)
            yield from walk_stmts(stmt.final)


def stmt_exprs(stmt: Stmt):
    """Top-level expressions held directly by a statement."""
    if isinstance(stmt, Assign):
        yield from stmt.targets
        if stmt.value is not None:
            yield stmt.value
    elif isinstance(stmt, ExprStmt | Return):
        value = stmt.expr if isinstance(stmt, ExprStmt) else stmt.value
        if value is not None:
            yield value
    elif isinstance(stmt, If):
        if stmt.test is not None:
            yield stmt.test


def string_value(expr: Expr | None) -> str | None:
    """Constant string value when statically known."""
    if isinstance(expr, Str):
        return expr.value
    if isinstance(expr, Concat) and expr.kind == "concat":
        pieces = [string_value(p) for p in expr.parts]
        if all(p is not None for p in pieces):
            return "".join(pieces)  # type: ignore[arg-type]
    return None


def const_value(expr: Expr | None) -> object:
    if isinstance(expr, Const):
        return expr.value
    if isinstance(expr, Str):
        return expr.value
    return _MISSING


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover
        return "<missing>"


_MISSING = _Missing()
MISSING = _MISSING
