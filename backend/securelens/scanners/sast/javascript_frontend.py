"""JavaScript / TypeScript / TSX frontend (tree-sitter) lowering to the SecureLens IR."""

from __future__ import annotations

from tree_sitter import Node

from securelens.scanners.sast import ir
from securelens.scanners.sast.treesitter import count_errors, named_children, parse, pos, text, unary_kind

_FUNCTION_TYPES = {"function_declaration", "generator_function_declaration", "function_expression", "function",
                   "arrow_function", "generator_function", "method_definition"}
_TRANSPARENT = {"parenthesized_expression", "await_expression", "as_expression", "satisfies_expression",
                "non_null_expression", "type_assertion", "spread_element", "jsx_expression"}
_COMPARE_OPS = {"==", "===", "!=", "!==", "<", ">", "<=", ">=", "instanceof", "in"}


class JavaScriptFrontend:
    def __init__(self, dialect: str = "javascript") -> None:
        self.language = dialect  # javascript | typescript | tsx

    def parse(self, path: str, source: str) -> ir.Module:
        data = source.encode("utf-8", errors="replace")
        grammar = self.language
        if grammar == "javascript" and path.endswith((".jsx",)):
            grammar = "tsx"
        root = parse(grammar, data)
        lines = source.splitlines()
        toplevel = ir.Function(line=1, name="<module>", qualname="<module>")
        module = ir.Module(path=path, language=self.language, toplevel=toplevel, lines=lines)
        module.parse_errors = count_errors(root)
        lowerer = _Lowerer(module)
        try:
            toplevel.body = lowerer.block(named_children(root), toplevel=True)
        except RecursionError:
            module.parse_errors += 1
        return module


class _Lowerer:
    def __init__(self, module: ir.Module) -> None:
        self.module = module
        self._anon = 0

    # ------------------------------------------------------------ statements

    def block(self, nodes: list[Node], toplevel: bool = False, class_name: str | None = None) -> list[ir.Stmt]:
        out: list[ir.Stmt] = []
        for node in nodes:
            out.extend(self.stmt(node, toplevel))
        return out

    def body_of(self, node: Node | None, toplevel: bool = False) -> list[ir.Stmt]:
        if node is None:
            return []
        if node.type == "statement_block":
            return self.block(named_children(node), toplevel)
        return self.stmt(node, toplevel)

    def stmt(self, node: Node, toplevel: bool) -> list[ir.Stmt]:
        t = node.type
        p = pos(node)
        if t in {"expression_statement"}:
            inner = named_children(node)
            if not inner:
                return []
            return self.expr_stmt(inner[0], toplevel)
        if t in {"lexical_declaration", "variable_declaration"}:
            out: list[ir.Stmt] = []
            for decl in named_children(node):
                if decl.type == "variable_declarator":
                    out.extend(self.declarator(decl, toplevel))
            return out
        if t in {"function_declaration", "generator_function_declaration"}:
            func = self.function(node, name=text(node.child_by_field_name("name")) or None, nested=not toplevel)
            if toplevel:
                self.module.functions.append(func)
                return []
            return [ir.FunctionDef(**p, func=func)]
        if t in {"class_declaration", "class", "abstract_class_declaration"}:
            return self.class_decl(node, toplevel)
        if t == "export_statement":
            return self.export(node, toplevel)
        if t == "import_statement":
            self.import_stmt(node)
            return []
        if t == "return_statement":
            inner = named_children(node)
            return [ir.Return(**p, value=self.expr(inner[0]) if inner else None)]
        if t == "if_statement":
            alt = node.child_by_field_name("alternative")
            orelse: list[ir.Stmt] = []
            if alt is not None:
                inner = list(named_children(alt))
                orelse = self.block(inner) if alt.type == "else_clause" else self.body_of(alt)
            return [ir.If(**p, test=self.expr(node.child_by_field_name("condition")),
                          body=self.body_of(node.child_by_field_name("consequence")), orelse=orelse)]
        if t in {"for_statement"}:
            header: list[ir.Stmt] = []
            for field in ("initializer", "condition", "increment"):
                child = node.child_by_field_name(field)
                if child is not None:
                    header.extend(self.stmt(child, False) if child.type.endswith(("declaration", "statement"))
                                  else [ir.ExprStmt(**pos(child), expr=self.expr(child))])
            return [ir.Loop(**p, header=header, body=self.body_of(node.child_by_field_name("body")))]
        if t == "for_in_statement":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            targets = self.pattern_targets(left) if left is not None else []
            header = [ir.Assign(**p, targets=targets, value=ir.Other(**p, children=[self.expr(right)], kind="iter"))]
            return [ir.Loop(**p, header=header, body=self.body_of(node.child_by_field_name("body")))]
        if t in {"while_statement", "do_statement"}:
            cond = node.child_by_field_name("condition")
            return [ir.Loop(**p, header=[ir.ExprStmt(**p, expr=self.expr(cond))] if cond else [],
                            body=self.body_of(node.child_by_field_name("body")))]
        if t == "try_statement":
            handlers = []
            handler = node.child_by_field_name("handler")
            if handler is not None:
                hbody = self.body_of(handler.child_by_field_name("body"))
                param = handler.child_by_field_name("parameter")
                if param is not None:
                    hbody.insert(0, ir.Assign(**pos(param), targets=self.pattern_targets(param),
                                              value=ir.Other(**pos(param), kind="exception")))
                handlers.append(hbody)
            finalizer = node.child_by_field_name("finalizer")
            final = self.body_of(finalizer.child_by_field_name("body")) if finalizer is not None else []
            return [ir.Try(**p, body=self.body_of(node.child_by_field_name("body")), handlers=handlers, final=final)]
        if t == "switch_statement":
            value = self.expr(node.child_by_field_name("value"))
            body = node.child_by_field_name("body")
            chain: list[ir.Stmt] = []
            cases = named_children(body) if body is not None else []
            for case in reversed(cases):
                stmts = [c for c in named_children(case) if c != case.child_by_field_name("value")]
                chain = [ir.If(**pos(case), test=value, body=self.block(stmts), orelse=chain)]
            return chain or [ir.ExprStmt(**p, expr=value)]
        if t == "throw_statement":
            inner = named_children(node)
            return [ir.ExprStmt(**p, expr=self.expr(inner[0]) if inner else None, exits=True)]
        if t == "statement_block":
            return self.block(named_children(node), toplevel)
        if t == "labeled_statement":
            body = node.child_by_field_name("body")
            return self.stmt(body, toplevel) if body is not None else []
        if t in {"interface_declaration", "type_alias_declaration", "enum_declaration", "comment", "empty_statement",
                 "break_statement", "continue_statement", "debugger_statement", "ambient_declaration",
                 "module", "internal_module", "import_alias"}:
            return []
        # Unknown statement: keep any expressions inside it visible.
        return [ir.ExprStmt(**p, expr=self.expr(node))]

    def expr_stmt(self, node: Node, toplevel: bool) -> list[ir.Stmt]:
        p = pos(node)
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            self.track_exports(left, right)
            value = self.named_function_value(right, left, toplevel)
            return [ir.Assign(**p, targets=self.pattern_targets(left), value=value)]
        if node.type == "augmented_assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op = text(node.child_by_field_name("operator"))
            target = self.expr(left)
            combined: ir.Expr = (ir.Concat(**p, parts=[target, self.expr(right)], kind="concat") if op == "+="
                                 else ir.Other(**p, children=[target, self.expr(right)], kind="binop"))
            return [ir.Assign(**p, targets=[self.expr(left)], value=combined, augmented=True)]
        if node.type == "sequence_expression":
            out: list[ir.Stmt] = []
            for child in named_children(node):
                out.extend(self.expr_stmt(child, toplevel))
            return out
        return [ir.ExprStmt(**p, expr=self.expr(node))]

    def declarator(self, decl: Node, toplevel: bool) -> list[ir.Stmt]:
        name_node = decl.child_by_field_name("name")
        value_node = decl.child_by_field_name("value")
        p = pos(decl)
        if value_node is None:
            return []
        self.track_require(name_node, value_node)
        value = self.named_function_value(value_node, name_node, toplevel)
        return [ir.Assign(**p, targets=self.pattern_targets(name_node), value=value)]

    def named_function_value(self, value_node: Node | None, name_node: Node | None, toplevel: bool) -> ir.Expr:
        """``const f = () => {}`` defines a function named f."""
        if value_node is None:
            return ir.Const(line=0)
        inner = value_node
        while inner.type in {"parenthesized_expression", "as_expression", "satisfies_expression"}:
            kids = named_children(inner)
            if not kids:
                break
            inner = kids[0]
        if inner.type in _FUNCTION_TYPES and name_node is not None and name_node.type in {
                "identifier", "member_expression"}:
            name = text(name_node)
            short = name.rsplit(".", 1)[-1]
            func = self.function(inner, name=short, nested=not toplevel)
            if toplevel:
                func.qualname = short if name_node.type == "identifier" else name
                self.module.functions.append(func)
                return ir.Name(**pos(name_node), id=short)
            return ir.FuncExpr(**pos(inner), func=func)
        return self.expr(value_node)

    def class_decl(self, node: Node, toplevel: bool) -> list[ir.Stmt]:
        name = text(node.child_by_field_name("name")) or f"<class@{node.start_point[0] + 1}>"
        body = node.child_by_field_name("body")
        out: list[ir.Stmt] = []
        if body is None:
            return out
        pending_decorators: list[ir.Expr] = []
        for member in named_children(body):
            if member.type == "decorator":
                pending_decorators.append(self.decorator(member))
                continue
            decorators = pending_decorators + [self.decorator(d) for d in member.children if d.type == "decorator"]
            pending_decorators = []
            if member.type == "method_definition":
                mname = text(member.child_by_field_name("name"))
                func = self.function(member, name=mname, nested=not toplevel, class_name=name)
                func.decorators = decorators
                if toplevel:
                    self.module.functions.append(func)
                else:
                    out.append(ir.FunctionDef(**pos(member), func=func))
            elif member.type in {"field_definition", "public_field_definition"}:
                value = member.child_by_field_name("value")
                fname = text(member.child_by_field_name("property") or member.child_by_field_name("name"))
                if value is not None and value.type in _FUNCTION_TYPES:
                    func = self.function(value, name=fname, nested=not toplevel, class_name=name)
                    func.decorators = decorators
                    if toplevel:
                        self.module.functions.append(func)
                    else:
                        out.append(ir.FunctionDef(**pos(member), func=func))
                elif value is not None:
                    out.append(ir.Assign(**pos(member), targets=[ir.Attr(**pos(member), value=ir.Name(
                        **pos(member), id="this"), attr=fname)], value=self.expr(value)))
        return out

    def decorator(self, node: Node) -> ir.Expr:
        kids = named_children(node)
        return self.expr(kids[0]) if kids else ir.Other(**pos(node))

    # ------------------------------------------------------------- modules

    def import_stmt(self, node: Node) -> None:
        source = node.child_by_field_name("source")
        spec = _string_value(source)
        if not spec:
            return
        relative = spec.startswith(".")
        for clause in named_children(node):
            if clause.type != "import_clause":
                continue
            for part in named_children(clause):
                if part.type == "identifier":
                    self.module.imports[text(part)] = f"js:{spec}#default" if relative else spec
                elif part.type == "namespace_import":
                    ident = next((c for c in named_children(part) if c.type == "identifier"), None)
                    if ident is not None:
                        self.module.imports[text(ident)] = f"js:{spec}" if relative else spec
                elif part.type == "named_imports":
                    for spec_node in named_children(part):
                        if spec_node.type != "import_specifier":
                            continue
                        name = text(spec_node.child_by_field_name("name"))
                        alias = text(spec_node.child_by_field_name("alias")) or name
                        self.module.imports[alias] = f"js:{spec}#{name}" if relative else f"{spec}.{name}"

    def track_require(self, name_node: Node | None, value_node: Node) -> None:
        spec, member = _require_spec(value_node)
        if spec is None or name_node is None:
            return
        relative = spec.startswith(".")
        if name_node.type == "identifier":
            local = text(name_node)
            if member:
                self.module.imports[local] = f"js:{spec}#{member}" if relative else f"{spec}.{member}"
            else:
                self.module.imports[local] = f"js:{spec}" if relative else spec
        elif name_node.type == "object_pattern":
            for prop in named_children(name_node):
                if prop.type == "shorthand_property_identifier_pattern":
                    name = text(prop)
                    self.module.imports[name] = f"js:{spec}#{name}" if relative else f"{spec}.{name}"
                elif prop.type == "pair_pattern":
                    key = text(prop.child_by_field_name("key"))
                    val = prop.child_by_field_name("value")
                    if val is not None and val.type == "identifier":
                        self.module.imports[text(val)] = f"js:{spec}#{key}" if relative else f"{spec}.{key}"

    def export(self, node: Node, toplevel: bool) -> list[ir.Stmt]:
        declaration = node.child_by_field_name("declaration")
        is_default = any(c.type == "default" for c in node.children)
        out: list[ir.Stmt] = []
        if declaration is not None:
            before = len(self.module.functions)
            out = self.stmt(declaration, toplevel)
            for func in self.module.functions[before:]:
                self.module.exports.setdefault(func.name, func.qualname)
                if is_default:
                    self.module.exports["default"] = func.qualname
            if declaration.type in {"lexical_declaration", "variable_declaration"}:
                for decl in named_children(declaration):
                    name = text(decl.child_by_field_name("name"))
                    if name:
                        self.module.exports.setdefault(name, name)
            return out
        value = node.child_by_field_name("value")
        if value is not None and is_default:
            if value.type in _FUNCTION_TYPES:
                func = self.function(value, name="default", nested=False)
                self.module.functions.append(func)
                self.module.exports["default"] = func.qualname
                return []
            if value.type == "identifier":
                self.module.exports["default"] = text(value)
            return [ir.ExprStmt(**pos(value), expr=self.expr(value))]
        for clause in named_children(node):
            if clause.type == "export_clause":
                for spec in named_children(clause):
                    name = text(spec.child_by_field_name("name"))
                    alias = text(spec.child_by_field_name("alias")) or name
                    if name:
                        self.module.exports[alias] = name
        return out

    def track_exports(self, left: Node | None, right: Node | None) -> None:
        if left is None or right is None:
            return
        target = text(left)
        if target == "module.exports":
            if right.type == "object":
                for prop in named_children(right):
                    if prop.type == "shorthand_property_identifier":
                        self.module.exports[text(prop)] = text(prop)
                    elif prop.type == "pair":
                        key = _prop_key(prop.child_by_field_name("key"))
                        val = prop.child_by_field_name("value")
                        if key and val is not None and val.type == "identifier":
                            self.module.exports[key] = text(val)
            elif right.type == "identifier":
                self.module.exports["default"] = text(right)
        elif target.startswith(("module.exports.", "exports.")):
            name = target.rsplit(".", 1)[-1]
            if right.type == "identifier":
                self.module.exports[name] = text(right)
            elif right.type in _FUNCTION_TYPES:
                self.module.exports[name] = target

    # ----------------------------------------------------------- functions

    def function(self, node: Node, name: str | None, nested: bool, class_name: str | None = None) -> ir.Function:
        if not name:
            self._anon += 1
            name = f"<anonymous@{node.start_point[0] + 1}>"
        params: list[ir.Param] = []
        params_node = node.child_by_field_name("parameters")
        single = node.child_by_field_name("parameter")
        if single is not None:
            params.append(ir.Param(name=text(single), index=0))
        elif params_node is not None:
            for child in named_children(params_node):
                self.param(child, params)
        body = node.child_by_field_name("body")
        if body is not None and body.type == "statement_block":
            stmts = self.block(named_children(body))
        elif body is not None:
            stmts = [ir.Return(**pos(body), value=self.expr(body))]
        else:
            stmts = []
        return ir.Function(**pos(node), name=name, qualname=f"{class_name}.{name}" if class_name else name,
                           params=params, body=stmts, class_name=class_name, is_method=class_name is not None,
                           nested=nested)

    def param(self, node: Node, params: list[ir.Param]) -> None:
        index = len({p.index for p in params})
        t = node.type
        annotation = None
        if t in {"required_parameter", "optional_parameter"}:
            type_node = node.child_by_field_name("type")
            annotation = text(type_node).lstrip(":").strip() if type_node is not None else None
            pattern = node.child_by_field_name("pattern")
            if pattern is None:
                return
            node, t = pattern, pattern.type
        if t == "identifier":
            params.append(ir.Param(name=text(node), index=index, annotation=annotation))
        elif t == "assignment_pattern":
            left = node.child_by_field_name("left")
            if left is not None:
                params.append(ir.Param(name=text(left), index=index,
                                       default=self.expr(node.child_by_field_name("right"))))
        elif t == "rest_pattern":
            ident = next((c for c in named_children(node)), None)
            if ident is not None:
                params.append(ir.Param(name=text(ident), index=index, kind="vararg"))
        elif t in {"object_pattern", "array_pattern"}:
            names = _pattern_names(node)
            for name in names:
                params.append(ir.Param(name=name, index=index, kind="destructured", annotation=annotation))
            if not names:
                params.append(ir.Param(name=f"<pattern{index}>", index=index))
        elif t == "this":
            return

    def pattern_targets(self, node: Node | None) -> list[ir.Expr]:
        if node is None:
            return []
        if node.type in {"object_pattern", "array_pattern"}:
            return [ir.Name(**pos(node), id=n) for n in _pattern_names(node)]
        return [self.expr(node)]

    # ---------------------------------------------------------- expressions

    def expr(self, node: Node | None) -> ir.Expr:
        if node is None:
            return ir.Const(line=0)
        t = node.type
        p = pos(node)
        if t in {"identifier", "shorthand_property_identifier", "property_identifier", "private_property_identifier"}:
            return ir.Name(**p, id=text(node))
        if t == "this":
            return ir.Name(**p, id="this")
        if t == "super":
            return ir.Name(**p, id="super")
        if t in _TRANSPARENT:
            kids = [c for c in named_children(node) if not c.type.endswith(("type", "type_annotation"))
                    and c.type not in {"type_identifier", "predefined_type", "generic_type", "object_type"}]
            return self.expr(kids[0]) if kids else ir.Other(**p)
        if t == "member_expression":
            prop = node.child_by_field_name("property")
            return ir.Attr(**p, value=self.expr(node.child_by_field_name("object")), attr=text(prop))
        if t == "subscript_expression":
            index = node.child_by_field_name("index")
            return ir.Subscript(**p, value=self.expr(node.child_by_field_name("object")), index=self.expr(index))
        if t == "call_expression":
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            spec, member = _require_spec(node)
            if spec is not None and not spec.startswith("."):
                return ir.Name(**p, id=f"{spec}.{member}" if member else spec)
            func = self.expr(func_node)
            if args_node is not None and args_node.type == "template_string":
                return ir.Call(**p, func=func, args=[self.expr(args_node)],
                               kwargs={"__tagged__": ir.Const(**p, value=True)})
            args = [self.expr(a) for a in named_children(args_node)] if args_node is not None else []
            return ir.Call(**p, func=func, args=args)
        if t == "new_expression":
            args_node = node.child_by_field_name("arguments")
            args = [self.expr(a) for a in named_children(args_node)] if args_node is not None else []
            return ir.Call(**p, func=self.expr(node.child_by_field_name("constructor")), args=args, is_new=True)
        if t == "string":
            return ir.Str(**p, value=_string_value(node) or "")
        if t == "template_string":
            parts: list[ir.Expr] = []
            for child in named_children(node):
                if child.type == "string_fragment" or child.type == "escape_sequence":
                    parts.append(ir.Str(**pos(child), value=text(child)))
                elif child.type == "template_substitution":
                    inner = named_children(child)
                    if inner:
                        parts.append(self.expr(inner[0]))
            if not parts:
                return ir.Str(**p, value="")
            if all(isinstance(x, ir.Str) for x in parts):
                return ir.Str(**p, value="".join(x.value for x in parts))  # type: ignore[union-attr]
            return ir.Concat(**p, parts=parts, kind="template")
        if t in {"number"}:
            return ir.Const(**p, value=_number(text(node)))
        if t in {"true", "false"}:
            return ir.Const(**p, value=t == "true")
        if t in {"null", "undefined"}:
            return ir.Const(**p, value=None)
        if t == "regex":
            return ir.Str(**p, value=text(node))
        if t == "binary_expression":
            op = text(node.child_by_field_name("operator"))
            left = self.expr(node.child_by_field_name("left"))
            right = self.expr(node.child_by_field_name("right"))
            if op == "+":
                parts = []
                for side in (left, right):
                    if isinstance(side, ir.Concat) and side.kind == "concat":
                        parts.extend(side.parts)
                    else:
                        parts.append(side)
                return ir.Concat(**p, parts=parts, kind="concat")
            if op in _COMPARE_OPS:
                return ir.Compare(**p, left=left, ops=[op], comparators=[right])
            return ir.Other(**p, children=[left, right], kind="boolop" if op in {"&&", "||", "??"} else "binop")
        if t == "ternary_expression":
            return ir.Other(**p, children=[self.expr(node.child_by_field_name("consequence")),
                                           self.expr(node.child_by_field_name("alternative"))], kind="ternary")
        if t in {"unary_expression", "update_expression"}:
            return ir.Other(**p, children=[self.expr(c) for c in named_children(node)], kind=unary_kind(node))
        if t in {"assignment_expression", "augmented_assignment_expression"}:
            return ir.Other(**p, children=[self.expr(node.child_by_field_name("right"))], kind="assign")
        if t == "object":
            keys: list[ir.Expr | None] = []
            values: list[ir.Expr] = []
            for prop in named_children(node):
                if prop.type == "pair":
                    keys.append(ir.Str(**pos(prop), value=_prop_key(prop.child_by_field_name("key")) or ""))
                    values.append(self.expr(prop.child_by_field_name("value")))
                elif prop.type == "shorthand_property_identifier":
                    keys.append(ir.Str(**pos(prop), value=text(prop)))
                    values.append(ir.Name(**pos(prop), id=text(prop)))
                elif prop.type == "method_definition":
                    mname = text(prop.child_by_field_name("name"))
                    keys.append(ir.Str(**pos(prop), value=mname))
                    values.append(ir.FuncExpr(**pos(prop), func=self.function(prop, name=mname, nested=True)))
                elif prop.type == "spread_element":
                    keys.append(None)
                    values.append(self.expr(prop))
            return ir.DictLit(**p, keys=keys, values=values)
        if t == "array":
            return ir.ListLit(**p, items=[self.expr(c) for c in named_children(node)])
        if t in _FUNCTION_TYPES:
            return ir.FuncExpr(**p, func=self.function(node, name=None, nested=True))
        if t in {"jsx_element", "jsx_self_closing_element", "jsx_fragment", "jsx_opening_element"}:
            return self.jsx(node)
        if t == "sequence_expression":
            return ir.Other(**p, children=[self.expr(c) for c in named_children(node)], kind="sequence")
        if t in {"class", "class_declaration"}:
            return ir.Other(**p, kind="class")
        # Fallback: keep children so data flow is not silently dropped.
        return ir.Other(**p, children=[self.expr(c) for c in named_children(node)
                                       if not c.type.endswith(("type", "type_annotation", "type_arguments"))],
                        kind=t)

    def jsx(self, node: Node) -> ir.Expr:
        children: list[ir.Expr] = []
        for child in node.children:
            if child.type == "jsx_attribute":
                kids = named_children(child)
                attr_name = text(kids[0]) if kids else ""
                value = kids[1] if len(kids) > 1 else None
                if value is None:
                    continue
                lowered = self.expr(value)
                if attr_name == "dangerouslySetInnerHTML":
                    marker = ir.Name(**pos(child), id="__jsx_dangerouslySetInnerHTML__")
                    children.append(ir.Call(**pos(child), func=marker,
                                            args=[lowered]))
                elif attr_name in {"href", "src", "action", "formAction"}:
                    children.append(ir.Call(**pos(child), func=ir.Name(**pos(child), id=f"__jsx_url_{attr_name}__"),
                                            args=[lowered]))
                else:
                    children.append(lowered)
            elif child.type in {"jsx_expression", "jsx_element", "jsx_self_closing_element", "jsx_opening_element",
                                "jsx_fragment"}:
                children.append(self.expr(child) if child.type != "jsx_opening_element" else self.jsx(child))
        return ir.Other(**pos(node), children=children, kind="jsx")


# ---------------------------------------------------------------------------


def _string_value(node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type == "string":
        return "".join(text(c) for c in node.children if c.type in {"string_fragment", "escape_sequence"})
    if node.type == "template_string":
        return "".join(text(c) for c in node.children if c.type == "string_fragment")
    return None


def _require_spec(node: Node) -> tuple[str | None, str | None]:
    """``require("x")`` -> ("x", None); ``require("x").y`` -> ("x", "y")."""
    member = None
    current = node
    if current.type == "member_expression":
        member = text(current.child_by_field_name("property"))
        current = current.child_by_field_name("object")
        if current is None:
            return None, None
    while current.type == "await_expression":
        kids = named_children(current)
        if not kids:
            return None, None
        current = kids[0]
    if current.type != "call_expression":
        return None, None
    func = current.child_by_field_name("function")
    if func is None or text(func) != "require":
        return None, None
    args = current.child_by_field_name("arguments")
    kids = named_children(args) if args is not None else []
    if len(kids) != 1:
        return None, None
    return _string_value(kids[0]), member


def _prop_key(node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type in {"string", "template_string"}:
        return _string_value(node)
    if node.type == "computed_property_name":
        kids = named_children(node)
        return _string_value(kids[0]) if kids and kids[0].type == "string" else None
    return text(node)


def _pattern_names(node: Node) -> list[str]:
    names: list[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        t = current.type
        if t in {"shorthand_property_identifier_pattern", "identifier"}:
            names.append(text(current))
        elif t == "pair_pattern":
            value = current.child_by_field_name("value")
            if value is not None:
                stack.append(value)
        elif t == "assignment_pattern":
            left = current.child_by_field_name("left")
            if left is not None:
                stack.append(left)
        elif t in {"object_pattern", "array_pattern", "rest_pattern", "object_assignment_pattern"}:
            stack.extend(reversed(named_children(current)))
    return names


def _number(value: str) -> object:
    try:
        return int(value, 0)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value
