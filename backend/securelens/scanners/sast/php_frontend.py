"""PHP frontend (tree-sitter) lowering to the SecureLens IR.

PHP language constructs are lowered to calls on builtin names so that one
rule format covers them: ``echo``/``print``/``<?= ?>`` become ``echo(...)``,
``include``/``require`` become calls of the same name, backticks become
``shell_exec(...)`` and scalar casts become ``(int)(...)``.
"""

from __future__ import annotations

from tree_sitter import Node

from securelens.scanners.sast import ir
from securelens.scanners.sast.treesitter import count_errors, named_children, parse, pos, text, unary_kind

_COMPARE_OPS = {"==", "===", "!=", "!==", "<>", "<", ">", "<=", ">=", "<=>", "instanceof"}
_INCLUDES = {"include_expression": "include", "include_once_expression": "include_once",
             "require_expression": "require", "require_once_expression": "require_once"}


class PHPFrontend:
    language = "php"

    def parse(self, path: str, source: str) -> ir.Module:
        root = parse("php", source.encode("utf-8", errors="replace"))
        toplevel = ir.Function(line=1, name="<module>", qualname="<module>")
        module = ir.Module(path=path, language="php", toplevel=toplevel, lines=source.splitlines())
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

    # ------------------------------------------------------------ statements

    def block(self, nodes: list[Node], toplevel: bool = False) -> list[ir.Stmt]:
        out: list[ir.Stmt] = []
        short_echo = False
        for node in nodes:
            if node.type == "text_interpolation":
                short_echo = any(c.type == "php_tag" and text(c).startswith("<?=") for c in node.children[-1:])
                continue
            if node.type == "php_tag":
                short_echo = text(node).startswith("<?=")
                continue
            if node.type == "text":
                continue
            if short_echo and node.type == "expression_statement":
                inner = named_children(node)
                if inner:
                    p = pos(node)
                    out.append(ir.ExprStmt(**p, expr=ir.Call(**p, func=ir.Name(**p, id="echo"),
                                                            args=[self.expr(inner[0])], construct=True)))
                short_echo = False
                continue
            short_echo = False
            out.extend(self.stmt(node, toplevel))
        return out

    def body_of(self, node: Node | None) -> list[ir.Stmt]:
        if node is None:
            return []
        if node.type in {"compound_statement", "colon_block"}:
            return self.block(named_children(node))
        return self.stmt(node, False)

    def stmt(self, node: Node, toplevel: bool) -> list[ir.Stmt]:
        t = node.type
        p = pos(node)
        if t == "expression_statement":
            inner = named_children(node)
            if not inner:
                return []
            e = inner[0]
            if e.type == "assignment_expression":
                return [ir.Assign(**p, targets=self.targets(e.child_by_field_name("left")),
                                  value=self.expr(e.child_by_field_name("right")))]
            if e.type == "augmented_assignment_expression":
                left = e.child_by_field_name("left")
                op = text(e.child_by_field_name("operator"))
                right = self.expr(e.child_by_field_name("right"))
                target = self.expr(left)
                value: ir.Expr = (ir.Concat(**p, parts=[target, right], kind="concat") if op == ".="
                                  else ir.Other(**p, children=[target, right], kind="binop"))
                return [ir.Assign(**p, targets=[self.expr(left)], value=value, augmented=True)]
            if e.type == "reference_assignment_expression":
                return [ir.Assign(**p, targets=self.targets(e.child_by_field_name("left")),
                                  value=self.expr(e.child_by_field_name("right")))]
            if e.type == "throw_expression":
                thrown = named_children(e)
                return [ir.ExprStmt(**p, expr=self.expr(thrown[0]) if thrown else None, exits=True)]
            return [ir.ExprStmt(**p, expr=self.expr(e))]
        if t == "echo_statement":
            args = [self.expr(c) for c in named_children(node)]
            return [ir.ExprStmt(**p, expr=ir.Call(**p, func=ir.Name(**p, id="echo"), args=args, construct=True))]
        if t == "exit_statement":
            args = [self.expr(c) for c in named_children(node)]
            return [ir.ExprStmt(**p, expr=ir.Call(**p, func=ir.Name(**p, id="exit"), args=args, construct=True))]
        if t == "function_definition":
            func = self.function(node, name=text(node.child_by_field_name("name")), nested=not toplevel)
            if toplevel:
                self.module.functions.append(func)
                return []
            return [ir.FunctionDef(**p, func=func)]
        if t in {"class_declaration", "trait_declaration", "interface_declaration", "enum_declaration"}:
            return self.class_decl(node, toplevel)
        if t == "return_statement":
            inner = named_children(node)
            return [ir.Return(**p, value=self.expr(inner[0]) if inner else None)]
        if t == "if_statement":
            orelse: list[ir.Stmt] = []
            alternatives = [c for c in node.children if c.type in {"else_clause", "else_if_clause"}]
            # Build the else-if chain from the end.
            for alt in reversed(alternatives):
                if alt.type == "else_clause":
                    orelse = self.body_of(alt.child_by_field_name("body"))
                else:
                    orelse = [ir.If(**pos(alt), test=self.expr(alt.child_by_field_name("condition")),
                                    body=self.body_of(alt.child_by_field_name("body")), orelse=orelse)]
            return [ir.If(**p, test=self.expr(node.child_by_field_name("condition")),
                          body=self.body_of(node.child_by_field_name("body")), orelse=orelse)]
        if t == "foreach_statement":
            kids = named_children(node)
            iterable = kids[0] if kids else None
            binding = kids[1] if len(kids) > 1 else None
            targets: list[ir.Expr] = []
            if binding is not None:
                if binding.type == "pair":
                    targets = [self.expr(c) for c in named_children(binding)]
                else:
                    targets = self.targets(binding)
            header = [ir.Assign(**p, targets=targets, value=ir.Other(**p, children=[self.expr(iterable)],
                                                                     kind="iter"))]
            return [ir.Loop(**p, header=header, body=self.body_of(node.child_by_field_name("body")))]
        if t in {"for_statement", "while_statement", "do_statement"}:
            header: list[ir.Stmt] = []
            for field in ("initialize", "condition", "update"):
                child = node.child_by_field_name(field)
                if child is not None:
                    header.append(ir.ExprStmt(**pos(child), expr=self.expr(child)))
            return [ir.Loop(**p, header=header, body=self.body_of(node.child_by_field_name("body")))]
        if t == "try_statement":
            handlers = []
            final: list[ir.Stmt] = []
            for child in named_children(node):
                if child.type == "catch_clause":
                    handlers.append(self.body_of(child.child_by_field_name("body")))
                elif child.type == "finally_clause":
                    final = self.body_of(child.child_by_field_name("body"))
            return [ir.Try(**p, body=self.body_of(node.child_by_field_name("body")), handlers=handlers, final=final)]
        if t == "switch_statement":
            value = self.expr(node.child_by_field_name("condition"))
            body = node.child_by_field_name("body")
            chain: list[ir.Stmt] = []
            cases = list(named_children(body)) if body is not None else []
            for case in reversed(cases):
                stmts = [c for c in named_children(case) if c != case.child_by_field_name("value")]
                chain = [ir.If(**pos(case), test=value, body=self.block(stmts), orelse=chain)]
            return chain or [ir.ExprStmt(**p, expr=value)]
        if t in {"compound_statement", "colon_block"}:
            return self.block(named_children(node), toplevel)
        if t == "namespace_use_declaration":
            for clause in named_children(node):
                if clause.type == "namespace_use_clause":
                    kids = named_children(clause)
                    alias = clause.child_by_field_name("alias")
                    target = text(kids[0]).lstrip("\\").replace("\\", ".") if kids else ""
                    local = text(alias) if alias is not None else target.rsplit(".", 1)[-1]
                    if target:
                        self.module.imports[local] = target
            return []
        if t in {"namespace_definition"}:
            body = node.child_by_field_name("body")
            return self.block(named_children(body), toplevel) if body is not None else []
        if t in {"php_tag", "text", "comment", "const_declaration", "global_declaration", "unset_statement",
                 "break_statement", "continue_statement", "declare_statement", "empty_statement",
                 "static_variable_declaration", "goto_statement", "named_label_statement"}:
            return []
        return [ir.ExprStmt(**p, expr=self.expr(node))]

    def class_decl(self, node: Node, toplevel: bool) -> list[ir.Stmt]:
        name = text(node.child_by_field_name("name")) or f"<class@{node.start_point[0] + 1}>"
        body = node.child_by_field_name("body")
        out: list[ir.Stmt] = []
        if body is None:
            return out
        for member in named_children(body):
            if member.type == "method_declaration":
                func = self.function(member, name=text(member.child_by_field_name("name")), nested=not toplevel,
                                     class_name=name)
                if toplevel:
                    self.module.functions.append(func)
                else:
                    out.append(ir.FunctionDef(**pos(member), func=func))
            elif member.type == "property_declaration":
                for element in named_children(member):
                    if element.type == "property_element":
                        kids = named_children(element)
                        if len(kids) >= 2:
                            prop = text(kids[0]).lstrip("$")
                            out.append(ir.Assign(**pos(element), targets=[ir.Attr(**pos(element), value=ir.Name(
                                **pos(element), id="$this"), attr=prop)], value=self.expr(kids[-1])))
        return out

    def function(self, node: Node, name: str, nested: bool, class_name: str | None = None) -> ir.Function:
        params: list[ir.Param] = []
        params_node = node.child_by_field_name("parameters")
        if params_node is not None:
            for child in named_children(params_node):
                pname = child.child_by_field_name("name")
                if pname is None:
                    continue
                type_node = child.child_by_field_name("type")
                default = child.child_by_field_name("default_value")
                params.append(ir.Param(
                    name=text(pname), index=len(params),
                    default=self.expr(default) if default is not None else None,
                    annotation=text(type_node) if type_node is not None else None,
                    kind="vararg" if child.type == "variadic_parameter" else "normal"))
        body = node.child_by_field_name("body")
        if body is not None and body.type == "compound_statement":
            stmts = self.block(named_children(body))
        elif body is not None:
            stmts = [ir.Return(**pos(body), value=self.expr(body))]
        else:
            stmts = []
        if not name:
            name = f"<closure@{node.start_point[0] + 1}>"
        return ir.Function(**pos(node), name=name, qualname=f"{class_name}.{name}" if class_name else name,
                           params=params, body=stmts, class_name=class_name, is_method=class_name is not None,
                           nested=nested)

    def targets(self, node: Node | None) -> list[ir.Expr]:
        if node is None:
            return []
        if node.type in {"list_literal", "array_creation_expression"}:
            out: list[ir.Expr] = []
            for element in named_children(node):
                kids = named_children(element) if element.type == "array_element_initializer" else [element]
                if kids:
                    out.append(self.expr(kids[-1]))
            return out
        return [self.expr(node)]

    # ---------------------------------------------------------- expressions

    def expr(self, node: Node | None) -> ir.Expr:
        if node is None:
            return ir.Const(line=0)
        t = node.type
        p = pos(node)
        if t == "variable_name":
            return ir.Name(**p, id=text(node))
        if t in {"name", "qualified_name"}:
            return ir.Name(**p, id=text(node).lstrip("\\").replace("\\", "."))
        if t in {"parenthesized_expression", "argument"}:
            kids = named_children(node)
            return self.expr(kids[-1]) if kids else ir.Other(**p)
        if t == "member_access_expression" or t == "nullsafe_member_access_expression":
            return ir.Attr(**p, value=self.expr(node.child_by_field_name("object")),
                           attr=text(node.child_by_field_name("name")))
        if t in {"scoped_property_access_expression", "class_constant_access_expression"}:
            kids = named_children(node)
            scope = self.expr(kids[0]) if kids else ir.Name(**p, id="?")
            return ir.Attr(**p, value=scope, attr=text(kids[-1]).lstrip("$") if len(kids) > 1 else "")
        if t == "subscript_expression":
            kids = named_children(node)
            base = self.expr(kids[0]) if kids else ir.Other(**p)
            index = self.expr(kids[1]) if len(kids) > 1 else None
            return ir.Subscript(**p, value=base, index=index)
        if t == "function_call_expression":
            func_node = node.child_by_field_name("function")
            func = self.expr(func_node)
            qualified = func_node is not None and func_node.type == "qualified_name"
            if isinstance(func, ir.Name) and "." in func.id and qualified:
                func = ir.Name(**pos(func_node), id=func.id.rsplit(".", 1)[-1])
            return ir.Call(**p, func=func, args=self.arguments(node.child_by_field_name("arguments")))
        if t in {"member_call_expression", "nullsafe_member_call_expression"}:
            func = ir.Attr(**p, value=self.expr(node.child_by_field_name("object")),
                           attr=text(node.child_by_field_name("name")))
            return ir.Call(**p, func=func, args=self.arguments(node.child_by_field_name("arguments")))
        if t == "scoped_call_expression":
            scope = node.child_by_field_name("scope")
            func = ir.Attr(**p, value=ir.Name(**pos(scope), id=text(scope).lstrip("\\").replace("\\", "."))
                           if scope is not None else ir.Name(**p, id="?"), attr=text(node.child_by_field_name("name")))
            return ir.Call(**p, func=func, args=self.arguments(node.child_by_field_name("arguments")))
        if t == "object_creation_expression":
            kids = named_children(node)
            cls = next((k for k in kids if k.type in {"name", "qualified_name", "variable_name"}), None)
            args_node = next((k for k in kids if k.type == "arguments"), None)
            return ir.Call(**p, func=self.expr(cls) if cls is not None else ir.Name(**p, id="?"),
                           args=self.arguments(args_node), is_new=True)
        if t in _INCLUDES:
            kids = named_children(node)
            return ir.Call(**p, func=ir.Name(**p, id=_INCLUDES[t]), args=[self.expr(k) for k in kids], construct=True)
        if t == "print_intrinsic":
            kids = named_children(node)
            return ir.Call(**p, func=ir.Name(**p, id="print"), args=[self.expr(k) for k in kids], construct=True)
        if t == "shell_command_expression":
            return ir.Call(**p, func=ir.Name(**p, id="shell_exec"), args=[self.interpolated(node)], construct=True)
        if t == "cast_expression":
            cast = text(node.child_by_field_name("type")).lower()
            return ir.Call(**p, func=ir.Name(**p, id=f"({cast})"), args=[self.expr(node.child_by_field_name("value"))])
        if t == "string":
            return ir.Str(**p, value="".join(text(c) for c in named_children(node) if c.type == "string_content"))
        if t in {"encapsed_string", "heredoc"}:
            return self.interpolated(node)
        if t == "nowdoc":
            body = node.child_by_field_name("value")
            return ir.Str(**p, value=text(body))
        if t in {"integer", "float"}:
            return ir.Const(**p, value=text(node))
        if t == "boolean":
            return ir.Const(**p, value=text(node).lower() == "true")
        if t == "null":
            return ir.Const(**p, value=None)
        if t == "binary_expression":
            op = text(node.child_by_field_name("operator"))
            left = self.expr(node.child_by_field_name("left"))
            right = self.expr(node.child_by_field_name("right"))
            if op == ".":
                parts = []
                for side in (left, right):
                    if isinstance(side, ir.Concat) and side.kind == "concat":
                        parts.extend(side.parts)
                    else:
                        parts.append(side)
                return ir.Concat(**p, parts=parts, kind="concat")
            if op in _COMPARE_OPS:
                return ir.Compare(**p, left=left, ops=[op], comparators=[right])
            return ir.Other(**p, children=[left, right], kind="boolop" if op in {"&&", "||", "and", "or", "??"}
                            else "binop")
        if t == "conditional_expression":
            kids = named_children(node)
            return ir.Other(**p, children=[self.expr(k) for k in kids[1:]] or [self.expr(k) for k in kids],
                            kind="ternary")
        if t in {"unary_op_expression", "update_expression", "error_suppression_expression", "clone_expression",
                 "reference_modifier"}:
            return ir.Other(**p, children=[self.expr(k) for k in named_children(node)], kind=unary_kind(node))
        if t == "array_creation_expression":
            keys: list[ir.Expr | None] = []
            values: list[ir.Expr] = []
            keyed = False
            for element in named_children(node):
                kids = named_children(element)
                if len(kids) == 2:
                    keyed = True
                    keys.append(self.expr(kids[0]))
                    values.append(self.expr(kids[1]))
                elif kids:
                    keys.append(None)
                    values.append(self.expr(kids[0]))
            if keyed:
                return ir.DictLit(**p, keys=keys, values=values)
            return ir.ListLit(**p, items=values)
        if t in {"anonymous_function", "anonymous_function_creation_expression", "arrow_function"}:
            return ir.FuncExpr(**p, func=self.function(node, name="", nested=True))
        if t in {"assignment_expression", "augmented_assignment_expression"}:
            return ir.Other(**p, children=[self.expr(node.child_by_field_name("right"))], kind="assign")
        if t == "match_expression":
            return ir.Other(**p, children=[self.expr(k) for k in named_children(node)], kind="ternary")
        if t == "dynamic_variable_name":
            return ir.Other(**p, children=[self.expr(k) for k in named_children(node)], kind="variable_variable")
        return ir.Other(**p, children=[self.expr(k) for k in named_children(node)], kind=t)

    def arguments(self, node: Node | None) -> list[ir.Expr]:
        if node is None:
            return []
        out: list[ir.Expr] = []
        for arg in named_children(node):
            if arg.type == "argument":
                kids = [k for k in named_children(arg) if k.type != "name" or len(named_children(arg)) == 1]
                out.append(self.expr(kids[-1]) if kids else ir.Other(**pos(arg)))
            elif arg.type == "variadic_placeholder":
                continue
            else:
                out.append(self.expr(arg))
        return out

    def interpolated(self, node: Node) -> ir.Expr:
        parts: list[ir.Expr] = []
        stack = list(node.children)
        for child in stack:
            if child.type in {"string_content", "string_value", "escape_sequence"}:
                parts.append(ir.Str(**pos(child), value=text(child)))
            elif child.type == "heredoc_body":
                for inner in child.children:
                    if inner.type in {"string_content", "string_value", "escape_sequence"}:
                        parts.append(ir.Str(**pos(inner), value=text(inner)))
                    elif inner.is_named:
                        parts.append(self.expr(inner))
            elif child.is_named and child.type not in {"heredoc_start", "heredoc_end"}:
                parts.append(self.expr(child))
        if not parts:
            return ir.Str(**pos(node), value="")
        if all(isinstance(x, ir.Str) for x in parts):
            return ir.Str(**pos(node), value="".join(x.value for x in parts))  # type: ignore[union-attr]
        return ir.Concat(**pos(node), parts=parts, kind="template")
