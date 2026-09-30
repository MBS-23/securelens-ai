"""Python frontend: lowers the standard-library ``ast`` into the SecureLens IR."""

from __future__ import annotations

import ast
import posixpath

from securelens.scanners.sast import ir


class PythonFrontend:
    language = "python"

    def parse(self, path: str, source: str) -> ir.Module:
        lines = source.splitlines()
        toplevel = ir.Function(line=1, name="<module>", qualname="<module>")
        module = ir.Module(path=path, language=self.language, toplevel=toplevel, lines=lines)
        try:
            tree = ast.parse(source, filename=path, type_comments=False)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            module.parse_errors = 1
            return module
        lowerer = _Lowerer(module)
        try:
            toplevel.body = lowerer.module_body(tree.body)
        except RecursionError:
            module.parse_errors = 1
        return module


def _pos(node: ast.AST) -> dict:
    return {
        "line": getattr(node, "lineno", 1) or 1,
        "col": getattr(node, "col_offset", 0) or 0,
        "end_line": getattr(node, "end_lineno", 0) or getattr(node, "lineno", 1) or 1,
    }


class _Lowerer:
    def __init__(self, module: ir.Module) -> None:
        self.module = module
        pkg = posixpath.dirname(module.path)
        self.package_parts = [p for p in pkg.split("/") if p] if pkg else []
        if posixpath.basename(module.path) == "__init__.py":
            self.is_package_init = True
        else:
            self.is_package_init = False

    # ------------------------------------------------------------------ module

    def module_body(self, body: list[ast.stmt]) -> list[ir.Stmt]:
        out: list[ir.Stmt] = []
        for stmt in body:
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                self.module.functions.append(self.function(stmt, class_name=None, nested=False))
            elif isinstance(stmt, ast.ClassDef):
                out.extend(self.class_def(stmt, nested=False))
            else:
                out.extend(self.stmt(stmt))
        return out

    def class_def(self, node: ast.ClassDef, nested: bool) -> list[ir.Stmt]:
        out: list[ir.Stmt] = []
        for base in node.bases:
            out.append(ir.ExprStmt(**_pos(base), expr=self.expr(base)))
        for stmt in node.body:
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                func = self.function(stmt, class_name=node.name, nested=nested)
                if nested:
                    out.append(ir.FunctionDef(**_pos(stmt), func=func))
                else:
                    self.module.functions.append(func)
            elif isinstance(stmt, ast.ClassDef):
                out.extend(self.class_def(stmt, nested=nested))
            else:
                out.extend(self.stmt(stmt))
        return out

    # --------------------------------------------------------------- functions

    def function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, class_name: str | None,
                 nested: bool) -> ir.Function:
        params: list[ir.Param] = []
        args = node.args
        positional = list(args.posonlyargs) + list(args.args)
        defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
        for arg, default in zip(positional, defaults, strict=False):
            params.append(ir.Param(name=arg.arg, index=len(params), default=self.expr(default) if default else None,
                                   annotation=_unparse(arg.annotation)))
        if args.vararg:
            params.append(ir.Param(name=args.vararg.arg, index=len(params), kind="vararg"))
        for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=False):
            params.append(ir.Param(name=arg.arg, index=len(params), default=self.expr(default) if default else None,
                                   annotation=_unparse(arg.annotation)))
        if args.kwarg:
            params.append(ir.Param(name=args.kwarg.arg, index=len(params), kind="kwarg"))
        qual = f"{class_name}.{node.name}" if class_name else node.name
        return ir.Function(
            **_pos(node),
            name=node.name,
            qualname=qual,
            params=params,
            body=self.block(node.body),
            decorators=[self.expr(d) for d in node.decorator_list],
            class_name=class_name,
            is_method=class_name is not None,
            nested=nested,
        )

    # --------------------------------------------------------------- statements

    def block(self, body: list[ast.stmt]) -> list[ir.Stmt]:
        out: list[ir.Stmt] = []
        for stmt in body:
            out.extend(self.stmt(stmt))
        return out

    def stmt(self, node: ast.stmt) -> list[ir.Stmt]:
        pos = _pos(node)
        if isinstance(node, ast.Assign):
            return [ir.Assign(**pos, targets=[self.expr(t) for t in _flatten_targets(node.targets)],
                              value=self.expr(node.value))]
        if isinstance(node, ast.AnnAssign):
            if node.value is None:
                return []
            return [ir.Assign(**pos, targets=[self.expr(node.target)], value=self.expr(node.value))]
        if isinstance(node, ast.AugAssign):
            target = self.expr(node.target)
            value = self.expr(node.value)
            if isinstance(node.op, ast.Add):
                combined: ir.Expr = ir.Concat(**pos, parts=[target, value], kind="concat")
            elif isinstance(node.op, ast.Mod):
                combined = ir.Concat(**pos, parts=[target, value], kind="percent")
            else:
                combined = ir.Other(**pos, children=[target, value], kind="binop")
            return [ir.Assign(**pos, targets=[self.expr(node.target)], value=combined, augmented=True)]
        if isinstance(node, ast.Expr):
            return [ir.ExprStmt(**pos, expr=self.expr(node.value))]
        if isinstance(node, ast.Return):
            return [ir.Return(**pos, value=self.expr(node.value) if node.value else None)]
        if isinstance(node, ast.If):
            return [ir.If(**pos, test=self.expr(node.test), body=self.block(node.body), orelse=self.block(node.orelse))]
        if isinstance(node, ast.For | ast.AsyncFor):
            header = [ir.Assign(**pos, targets=[self.expr(t) for t in _flatten_targets([node.target])],
                                value=ir.Other(**pos, children=[self.expr(node.iter)], kind="iter"))]
            return [ir.Loop(**pos, header=header, body=self.block(node.body) + self.block(node.orelse))]
        if isinstance(node, ast.While):
            return [ir.Loop(**pos, header=[ir.ExprStmt(**pos, expr=self.expr(node.test))],
                            body=self.block(node.body) + self.block(node.orelse))]
        if isinstance(node, ast.With | ast.AsyncWith):
            out: list[ir.Stmt] = []
            for item in node.items:
                ctx = self.expr(item.context_expr)
                if item.optional_vars is not None:
                    out.append(ir.Assign(**pos, targets=[self.expr(t) for t in _flatten_targets([item.optional_vars])],
                                         value=ctx))
                else:
                    out.append(ir.ExprStmt(**pos, expr=ctx))
            return out + self.block(node.body)
        if isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
            handlers = []
            for handler in node.handlers:  # type: ignore[attr-defined]
                hbody = self.block(handler.body)
                if handler.name:
                    hbody.insert(0, ir.Assign(**_pos(handler), targets=[ir.Name(**_pos(handler), id=handler.name)],
                                              value=ir.Other(**_pos(handler), kind="exception")))
                handlers.append(hbody)
            return [ir.Try(**pos, body=self.block(node.body) + self.block(node.orelse),  # type: ignore[attr-defined]
                           handlers=handlers, final=self.block(node.finalbody))]  # type: ignore[attr-defined]
        if isinstance(node, ast.Match):
            return [self._match(node)]
        if isinstance(node, ast.Raise):
            return [ir.ExprStmt(**pos, expr=self.expr(node.exc))] if node.exc else []
        if isinstance(node, ast.Assert):
            children = [self.expr(node.test)] + ([self.expr(node.msg)] if node.msg else [])
            return [ir.ExprStmt(**pos, expr=ir.Other(**pos, children=children, kind="assert"))]
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            return [ir.FunctionDef(**pos, func=self.function(node, class_name=None, nested=True))]
        if isinstance(node, ast.ClassDef):
            return self.class_def(node, nested=True)
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    self.module.imports[alias.asname] = alias.name
                else:
                    root = alias.name.split(".")[0]
                    self.module.imports.setdefault(root, root)
            return []
        if isinstance(node, ast.ImportFrom):
            base = self._resolve_from(node.module, node.level)
            for alias in node.names:
                if alias.name == "*":
                    continue
                target = f"{base}.{alias.name}" if base else alias.name
                self.module.imports[alias.asname or alias.name] = target
            return []
        return []

    def _match(self, node: ast.Match) -> ir.Stmt:
        pos = _pos(node)
        subject = self.expr(node.subject)
        chain: list[ir.Stmt] = []
        for case in reversed(node.cases):
            chain = [ir.If(**_pos(case.pattern), test=subject, body=self.block(case.body), orelse=chain)]
        return chain[0] if chain else ir.ExprStmt(**pos, expr=subject)

    def _resolve_from(self, module: str | None, level: int) -> str:
        if level == 0:
            return module or ""
        parts = list(self.package_parts)
        # ``from . import x`` inside pkg/mod.py refers to pkg; each extra dot goes up.
        drop = level - 1
        if drop:
            parts = parts[:-drop] if drop <= len(parts) else []
        base = ".".join(parts)
        if module:
            return f"{base}.{module}" if base else module
        return base

    # -------------------------------------------------------------- expressions

    def expr(self, node: ast.expr | None) -> ir.Expr:
        if node is None:
            return ir.Const(line=0, value=None)
        pos = _pos(node)
        if isinstance(node, ast.Name):
            return ir.Name(**pos, id=node.id)
        if isinstance(node, ast.Attribute):
            return ir.Attr(**pos, value=self.expr(node.value), attr=node.attr)
        if isinstance(node, ast.Subscript):
            return ir.Subscript(**pos, value=self.expr(node.value), index=self.expr(node.slice))
        if isinstance(node, ast.Call):
            args = [self.expr(a.value if isinstance(a, ast.Starred) else a) for a in node.args]
            kwargs: dict[str, ir.Expr] = {}
            for kw in node.keywords:
                key = kw.arg if kw.arg is not None else f"**{len(kwargs)}"
                kwargs[key] = self.expr(kw.value)
            return ir.Call(**pos, func=self.expr(node.func), args=args, kwargs=kwargs)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return ir.Str(**pos, value=node.value)
            if isinstance(node.value, bytes):
                return ir.Str(**pos, value=node.value.decode("latin-1"))
            return ir.Const(**pos, value=node.value)
        if isinstance(node, ast.JoinedStr):
            parts: list[ir.Expr] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(ir.Str(**_pos(value), value=value.value))
                elif isinstance(value, ast.FormattedValue):
                    parts.append(self.expr(value.value))
                else:
                    parts.append(self.expr(value))
            return ir.Concat(**pos, parts=parts, kind="template")
        if isinstance(node, ast.BinOp):
            left, right = self.expr(node.left), self.expr(node.right)
            if isinstance(node.op, ast.Add):
                parts = []
                for side in (left, right):
                    if isinstance(side, ir.Concat) and side.kind == "concat":
                        parts.extend(side.parts)
                    else:
                        parts.append(side)
                return ir.Concat(**pos, parts=parts, kind="concat")
            if isinstance(node.op, ast.Mod) and isinstance(left, ir.Str | ir.Concat):
                return ir.Concat(**pos, parts=[left, right], kind="percent")
            return ir.Other(**pos, children=[left, right], kind="binop")
        if isinstance(node, ast.Dict):
            return ir.DictLit(**pos, keys=[self.expr(k) if k is not None else None for k in node.keys],
                              values=[self.expr(v) for v in node.values])
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return ir.ListLit(**pos, items=[self.expr(e.value if isinstance(e, ast.Starred) else e) for e in node.elts])
        if isinstance(node, ast.Compare):
            return ir.Compare(**pos, left=self.expr(node.left), ops=[type(o).__name__ for o in node.ops],
                              comparators=[self.expr(c) for c in node.comparators])
        if isinstance(node, ast.Lambda):
            func = ir.Function(**pos, name="<lambda>", qualname="<lambda>", nested=True,
                               params=[ir.Param(name=a.arg, index=i) for i, a in enumerate(node.args.args)],
                               body=[ir.Return(**pos, value=self.expr(node.body))])
            return ir.FuncExpr(**pos, func=func)
        if isinstance(node, ast.Await):
            return self.expr(node.value)
        if isinstance(node, ast.Starred):
            return self.expr(node.value)
        if isinstance(node, ast.IfExp):
            return ir.Other(**pos, children=[self.expr(node.body), self.expr(node.orelse)], kind="ternary")
        if isinstance(node, ast.BoolOp):
            return ir.Other(**pos, children=[self.expr(v) for v in node.values], kind="boolop")
        if isinstance(node, ast.UnaryOp):
            return ir.Other(**pos, children=[self.expr(node.operand)], kind="unary")
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            children = [self.expr(node.elt)] + [self.expr(g.iter) for g in node.generators]
            return ir.Other(**pos, children=children, kind="comprehension")
        if isinstance(node, ast.DictComp):
            children = [self.expr(node.key), self.expr(node.value)] + [self.expr(g.iter) for g in node.generators]
            return ir.Other(**pos, children=children, kind="comprehension")
        if isinstance(node, ast.NamedExpr):
            return self.expr(node.value)
        if isinstance(node, ast.Yield | ast.YieldFrom):
            return ir.Other(**pos, children=[self.expr(node.value)] if node.value else [], kind="yield")
        if isinstance(node, ast.Slice):
            return ir.Other(**pos, children=[self.expr(p) for p in (node.lower, node.upper, node.step) if p], kind="slice")
        if isinstance(node, ast.FormattedValue):
            return self.expr(node.value)
        return ir.Other(**pos, children=[], kind=type(node).__name__)


def _flatten_targets(targets: list[ast.expr]) -> list[ast.expr]:
    out: list[ast.expr] = []
    for target in targets:
        if isinstance(target, ast.Tuple | ast.List):
            out.extend(_flatten_targets(list(target.elts)))
        elif isinstance(target, ast.Starred):
            out.append(target.value)
        else:
            out.append(target)
    return out


def _unparse(node: ast.expr | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node)[:200]
    except Exception:  # pragma: no cover - defensive
        return None
