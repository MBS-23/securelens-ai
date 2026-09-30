"""Tree-sitter frontends for Java, C#, Go, C and C++.

The five grammars share most constructs (calls, member access, declarations,
control flow). ``_BaseLowerer`` handles what is common; each language class
overrides the handful of node shapes that differ. Adding a new language means
adding one small subclass and a rule pack.
"""

from __future__ import annotations

from tree_sitter import Node

from securelens.scanners.sast import ir
from securelens.scanners.sast.treesitter import count_errors, named_children, parse, pos, text, unary_kind

_COMPARE = {"==", "!=", "<", ">", "<=", ">=", "===", "!=="}
_LOGICAL = {"&&", "||", "and", "or", "??"}
_INT_TYPES = {"int", "long", "short", "byte", "double", "float", "bool", "boolean", "char", "decimal", "uint",
              "ulong", "Integer", "Long", "size_t", "unsigned", "int64_t", "int32_t", "uint32_t", "uint64_t"}


class _BaseLowerer:
    language = "generic"
    block_types = {"block", "compound_statement", "statement_list", "declaration_list", "class_body",
                   "field_declaration_list", "switch_block", "constructor_body"}
    expr_stmt_types = {"expression_statement"}
    string_types = {"string_literal", "character_literal", "char_literal"}
    string_content_types = {"string_fragment", "string_literal_content", "string_content", "escape_sequence",
                            "interpreted_string_literal_content", "raw_string_literal_content", "character"}
    number_types = {"decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal",
                    "decimal_floating_point_literal", "integer_literal", "real_literal", "number_literal",
                    "int_literal", "float_literal", "imaginary_literal"}
    true_types = {"true"}
    false_types = {"false"}
    null_types = {"null_literal", "null", "nil", "nullptr"}
    function_types: set[str] = set()
    lambda_types: set[str] = set()
    class_types: set[str] = set()

    def __init__(self, module: ir.Module) -> None:
        self.module = module
        self.class_stack: list[str] = []

    # --------------------------------------------------------------- blocks

    def lower_root(self, root: Node) -> list[ir.Stmt]:
        return self.block(named_children(root), toplevel=True)

    def block(self, nodes: list[Node], toplevel: bool = False) -> list[ir.Stmt]:
        out: list[ir.Stmt] = []
        for node in nodes:
            out.extend(self.stmt(node, toplevel))
        return out

    def body_of(self, node: Node | None) -> list[ir.Stmt]:
        if node is None:
            return []
        if node.type in self.block_types:
            return self.block(named_children(node))
        return self.stmt(node, False)

    # ----------------------------------------------------------- statements

    def stmt(self, node: Node, toplevel: bool) -> list[ir.Stmt]:
        special = self.stmt_specific(node, toplevel)
        if special is not None:
            return special
        t = node.type
        p = pos(node)
        if t in self.block_types:
            return self.block(named_children(node), toplevel)
        if t in self.expr_stmt_types:
            inner = named_children(node)
            return self.expr_stmt(inner[0]) if inner else []
        if t in self.function_types:
            func = self.function(node, nested=not toplevel)
            if func is None:
                return []
            if toplevel:
                self.module.functions.append(func)
                return []
            return [ir.FunctionDef(**p, func=func)]
        if t in self.class_types:
            return self.class_decl(node, toplevel)
        if t == "return_statement":
            inner = [c for c in named_children(node) if c.type != "expression_list"] or [
                c for n in named_children(node) for c in named_children(n)]
            return [ir.Return(**p, value=self.expr(inner[0]) if inner else None)]
        if t == "if_statement":
            cond = node.child_by_field_name("condition")
            alt = node.child_by_field_name("alternative")
            orelse: list[ir.Stmt] = []
            if alt is not None:
                orelse = self.block(named_children(alt)) if alt.type == "else_clause" else self.body_of(alt)
            init = node.child_by_field_name("initializer")
            pre = self.stmt(init, False) if init is not None else []
            return [*pre, ir.If(**p, test=self.expr(cond), body=self.body_of(node.child_by_field_name("consequence")),
                                orelse=orelse)]
        if t in {"while_statement", "do_statement"}:
            cond = node.child_by_field_name("condition")
            return [ir.Loop(**p, header=[ir.ExprStmt(**p, expr=self.expr(cond))] if cond is not None else [],
                            body=self.body_of(node.child_by_field_name("body")))]
        if t == "for_statement":
            return [self.for_loop(node)]
        if t in {"throw_statement", "throw_expression"}:
            inner = named_children(node)
            return [ir.ExprStmt(**p, expr=self.expr(inner[0]) if inner else None, exits=True)]
        if t == "try_statement":
            return [self.try_stmt(node)]
        if t in {"labeled_statement", "synchronized_statement", "lock_statement", "unsafe_statement",
                 "checked_statement", "fixed_statement"}:
            body = node.child_by_field_name("body") or (named_children(node)[-1] if named_children(node) else None)
            return self.body_of(body)
        if t in {"comment", "line_comment", "block_comment", "empty_statement", "break_statement",
                 "continue_statement", "import_declaration", "package_declaration", "package_clause",
                 "preproc_include", "using_directive", "goto_statement", "access_specifier", "attribute_list",
                 "type_definition", "struct_specifier", "enum_specifier", "union_specifier", "field_declaration"}:
            if t == "field_declaration":
                return self.field_decl(node)
            return []
        return [ir.ExprStmt(**p, expr=self.expr(node))]

    def stmt_specific(self, node: Node, toplevel: bool) -> list[ir.Stmt] | None:
        return None

    def field_decl(self, node: Node) -> list[ir.Stmt]:
        return []

    def expr_stmt(self, node: Node) -> list[ir.Stmt]:
        p = pos(node)
        if node.type in {"assignment_expression", "assignment_statement"}:
            return self.assignment(node)
        if node.type in {"update_expression", "inc_statement", "dec_statement", "postfix_unary_expression",
                         "prefix_unary_expression"}:
            kids = named_children(node)
            if kids:
                target = self.expr(kids[0])
                return [ir.Assign(**p, targets=[target], value=ir.Other(**p, children=[target], kind="unary"),
                                  augmented=True)]
        return [ir.ExprStmt(**p, expr=self.expr(node))]

    def assignment(self, node: Node) -> list[ir.Stmt]:
        p = pos(node)
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        op = text(node.child_by_field_name("operator")) or "="
        targets = self.targets(left)
        value = self.expr(right)
        if op == "+=" and targets:
            value = ir.Concat(**p, parts=[targets[0], value], kind="concat")
            return [ir.Assign(**p, targets=targets, value=value, augmented=True)]
        if op not in {"=", ":="} and targets:
            return [ir.Assign(**p, targets=targets, value=ir.Other(**p, children=[targets[0], value],
                                                                   kind=f"binop:{op[:-1]}"), augmented=True)]
        return [ir.Assign(**p, targets=targets, value=value)]

    def targets(self, node: Node | None) -> list[ir.Expr]:
        if node is None:
            return []
        if node.type in {"expression_list", "tuple_expression", "argument_list"}:
            return [self.expr(c) for c in named_children(node)]
        return [self.expr(node)]

    def for_loop(self, node: Node) -> ir.Stmt:
        p = pos(node)
        header: list[ir.Stmt] = []
        for field in ("init", "initializer", "condition", "update", "increment"):
            child = node.child_by_field_name(field)
            if child is not None:
                if child.type.endswith(("declaration", "statement")):
                    header.extend(self.stmt(child, False))
                else:
                    header.append(ir.ExprStmt(**pos(child), expr=self.expr(child)))
        return ir.Loop(**p, header=header, body=self.body_of(node.child_by_field_name("body")))

    def try_stmt(self, node: Node) -> ir.Stmt:
        p = pos(node)
        handlers: list[list[ir.Stmt]] = []
        final: list[ir.Stmt] = []
        for child in named_children(node):
            if child.type == "catch_clause":
                handlers.append(self.body_of(child.child_by_field_name("body") or (
                    named_children(child)[-1] if named_children(child) else None)))
            elif child.type == "finally_clause":
                kids = named_children(child)
                final = self.body_of(child.child_by_field_name("body") or (kids[-1] if kids else None))
        return ir.Try(**p, body=self.body_of(node.child_by_field_name("body")), handlers=handlers, final=final)

    def class_decl(self, node: Node, toplevel: bool) -> list[ir.Stmt]:
        name = text(node.child_by_field_name("name")) or f"<class@{node.start_point[0] + 1}>"
        body = node.child_by_field_name("body")
        self.class_stack.append(name)
        out: list[ir.Stmt] = []
        try:
            if body is not None:
                for member in named_children(body):
                    out.extend(self.stmt(member, toplevel))
        finally:
            self.class_stack.pop()
        return out

    # ------------------------------------------------------------ functions

    def function(self, node: Node, nested: bool) -> ir.Function | None:
        raise NotImplementedError

    def make_function(self, node: Node, name: str, params: list[ir.Param], body: Node | None,
                      decorators: list[ir.Expr], nested: bool, class_name: str | None = None) -> ir.Function:
        class_name = class_name if class_name is not None else (self.class_stack[-1] if self.class_stack else None)
        if body is None:
            stmts: list[ir.Stmt] = []
        elif body.type in self.block_types:
            stmts = self.block(named_children(body))
        elif body.type == "arrow_expression_clause":
            kids = named_children(body)
            stmts = [ir.Return(**pos(body), value=self.expr(kids[0]))] if kids else []
        else:
            stmts = [ir.Return(**pos(body), value=self.expr(body))]
        return ir.Function(**pos(node), name=name, qualname=f"{class_name}.{name}" if class_name else name,
                           params=params, body=stmts, decorators=decorators, class_name=class_name,
                           is_method=class_name is not None, nested=nested)

    # ---------------------------------------------------------- expressions

    def expr(self, node: Node | None) -> ir.Expr:
        if node is None:
            return ir.Const(line=0)
        special = self.expr_specific(node)
        if special is not None:
            return special
        t = node.type
        p = pos(node)
        if t in {"identifier", "field_identifier", "type_identifier", "package_identifier", "property_identifier",
                 "namespace_identifier", "statement_identifier"}:
            return ir.Name(**p, id=text(node))
        if t in {"this", "this_expression"}:
            return ir.Name(**p, id="this")
        if t in self.string_types:
            return ir.Str(**p, value="".join(text(c) for c in node.children if c.type in self.string_content_types)
                          if any(c.type in self.string_content_types for c in node.children)
                          else text(node).strip("\"'`"))
        if t in self.number_types:
            return ir.Const(**p, value=text(node))
        if t in self.true_types:
            return ir.Const(**p, value=True)
        if t in self.false_types:
            return ir.Const(**p, value=False)
        if t in self.null_types:
            return ir.Const(**p, value=None)
        if t == "binary_expression":
            return self.binary(node)
        if t in {"parenthesized_expression", "argument", "literal_element", "expression_list"}:
            kids = named_children(node)
            return self.expr(kids[-1]) if kids else ir.Other(**p)
        if t in {"ternary_expression", "conditional_expression"}:
            cons = node.child_by_field_name("consequence")
            alt = node.child_by_field_name("alternative")
            kids = [c for c in (cons, alt) if c is not None] or named_children(node)[1:]
            return ir.Other(**p, children=[self.expr(k) for k in kids], kind="ternary")
        if t in self.lambda_types:
            func = self.lambda_function(node)
            return ir.FuncExpr(**p, func=func) if func else ir.Other(**p)
        if t in {"assignment_expression"}:
            return ir.Other(**p, children=[self.expr(node.child_by_field_name("right"))], kind="assign")
        if t in {"unary_expression", "update_expression", "prefix_unary_expression", "postfix_unary_expression"}:
            return ir.Other(**p, children=[self.expr(c) for c in named_children(node)], kind=unary_kind(node))
        return ir.Other(**p, children=[self.expr(c) for c in named_children(node)
                                       if not c.type.endswith(("type", "type_arguments", "type_parameters"))],
                        kind=t)

    def expr_specific(self, node: Node) -> ir.Expr | None:
        return None

    def lambda_function(self, node: Node) -> ir.Function | None:
        return None

    def binary(self, node: Node) -> ir.Expr:
        p = pos(node)
        op = text(node.child_by_field_name("operator"))
        left = self.expr(node.child_by_field_name("left"))
        right = self.expr(node.child_by_field_name("right"))
        if op == "+" and self.plus_is_concat(left, right):
            parts: list[ir.Expr] = []
            for side in (left, right):
                if isinstance(side, ir.Concat) and side.kind == "concat":
                    parts.extend(side.parts)
                else:
                    parts.append(side)
            return ir.Concat(**p, parts=parts, kind="concat")
        if op in _COMPARE:
            return ir.Compare(**p, left=left, ops=[op], comparators=[right])
        kind = "boolop" if op in _LOGICAL else f"binop:{op}"
        return ir.Other(**p, children=[left, right], kind=kind)

    def plus_is_concat(self, left: ir.Expr, right: ir.Expr) -> bool:
        return True

    def arguments(self, node: Node | None) -> list[ir.Expr]:
        if node is None:
            return []
        return [self.expr(a) for a in named_children(node) if a.type not in {"comment"}]


# ===================================================================== Java


class JavaLowerer(_BaseLowerer):
    language = "java"
    function_types = {"method_declaration", "constructor_declaration", "compact_constructor_declaration"}
    lambda_types = {"lambda_expression"}
    class_types = {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration"}
    string_types = {"string_literal", "character_literal", "text_block"}

    def stmt_specific(self, node: Node, toplevel: bool) -> list[ir.Stmt] | None:
        t = node.type
        p = pos(node)
        if t == "import_declaration":
            path = next((text(c) for c in named_children(node) if c.type in {"scoped_identifier", "identifier"}), "")
            if path and not any(c.type == "asterisk" for c in node.children):
                self.module.imports[path.rsplit(".", 1)[-1]] = path
            return []
        if t in {"local_variable_declaration", "field_declaration"}:
            out: list[ir.Stmt] = []
            for decl in named_children(node):
                if decl.type == "variable_declarator":
                    name = decl.child_by_field_name("name")
                    value = decl.child_by_field_name("value")
                    if name is not None and value is not None:
                        target: ir.Expr = ir.Name(**pos(name), id=text(name))
                        if t == "field_declaration":
                            target = ir.Attr(**pos(name), value=ir.Name(**pos(name), id="this"), attr=text(name))
                        out.append(ir.Assign(**pos(decl), targets=[target], value=self.expr(value)))
            return out
        if t == "enhanced_for_statement":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            header = [ir.Assign(**p, targets=[ir.Name(**pos(name), id=text(name))] if name is not None else [],
                                value=ir.Other(**p, children=[self.expr(value)], kind="iter"))]
            return [ir.Loop(**p, header=header, body=self.body_of(node.child_by_field_name("body")))]
        if t == "try_with_resources_statement":
            pre: list[ir.Stmt] = []
            resources = node.child_by_field_name("resources")
            for res in named_children(resources) if resources is not None else []:
                name, value = res.child_by_field_name("name"), res.child_by_field_name("value")
                if name is not None and value is not None:
                    pre.append(ir.Assign(**pos(res), targets=[ir.Name(**pos(name), id=text(name))],
                                         value=self.expr(value)))
            return [*pre, self.try_stmt(node)]
        if t in {"switch_expression", "switch_statement"}:
            value = self.expr(node.child_by_field_name("condition"))
            body = node.child_by_field_name("body")
            chain: list[ir.Stmt] = []
            groups = named_children(body) if body is not None else []
            for group in reversed(groups):
                stmts = [c for c in named_children(group) if c.type not in {"switch_label"}]
                chain = [ir.If(**pos(group), test=value, body=self.block(stmts), orelse=chain)]
            return chain or [ir.ExprStmt(**p, expr=value)]
        if t in {"static_initializer", "yield_statement", "local_class_declaration"}:
            kids = named_children(node)
            return self.block(kids) if kids else []
        return None

    def decorators(self, node: Node) -> list[ir.Expr]:
        out: list[ir.Expr] = []
        for child in node.children:
            if child.type == "modifiers":
                for mod in named_children(child):
                    if mod.type in {"marker_annotation", "annotation"}:
                        name = text(mod.child_by_field_name("name"))
                        args_node = mod.child_by_field_name("arguments")
                        name_expr = ir.Name(**pos(mod), id=name.rsplit(".", 1)[-1])
                        if args_node is not None:
                            out.append(ir.Call(**pos(mod), func=name_expr,
                                               args=[self.expr(a) for a in named_children(args_node)]))
                        else:
                            out.append(name_expr)
        return out

    def function(self, node: Node, nested: bool) -> ir.Function | None:
        name = text(node.child_by_field_name("name")) or "<init>"
        params: list[ir.Param] = []
        params_node = node.child_by_field_name("parameters")
        for param in named_children(params_node) if params_node is not None else []:
            if param.type in {"formal_parameter", "spread_parameter", "receiver_parameter"}:
                pname = param.child_by_field_name("name")
                ptype = param.child_by_field_name("type")
                if pname is None:
                    ident = [c for c in named_children(param) if c.type in {"identifier", "variable_declarator"}]
                    pname = ident[-1] if ident else None
                if pname is None:
                    continue
                params.append(ir.Param(name=text(pname).split("=")[0].strip(), index=len(params),
                                       annotation=text(ptype) if ptype is not None else None,
                                       kind="vararg" if param.type == "spread_parameter" else "normal"))
        return self.make_function(node, name, params, node.child_by_field_name("body"), self.decorators(node), nested)

    def lambda_function(self, node: Node) -> ir.Function | None:
        params: list[ir.Param] = []
        pnode = node.child_by_field_name("parameters")
        if pnode is not None:
            idents = [pnode] if pnode.type == "identifier" else [
                (c.child_by_field_name("name") or c) for c in named_children(pnode)]
            for ident in idents:
                params.append(ir.Param(name=text(ident), index=len(params)))
        return self.make_function(node, f"<lambda@{node.start_point[0] + 1}>", params,
                                  node.child_by_field_name("body"), [], True, class_name="")

    def expr_specific(self, node: Node) -> ir.Expr | None:
        t = node.type
        p = pos(node)
        if t == "method_invocation":
            obj = node.child_by_field_name("object")
            name = text(node.child_by_field_name("name"))
            func: ir.Expr = ir.Attr(**p, value=self.expr(obj), attr=name) if obj is not None else ir.Name(**p, id=name)
            return ir.Call(**p, func=func, args=self.arguments(node.child_by_field_name("arguments")))
        if t == "field_access":
            return ir.Attr(**p, value=self.expr(node.child_by_field_name("object")),
                           attr=text(node.child_by_field_name("field")))
        if t == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            type_name = text(type_node).split("<", 1)[0]
            return ir.Call(**p, func=ir.Name(**pos(type_node) if type_node is not None else p, id=type_name),
                           args=self.arguments(node.child_by_field_name("arguments")), is_new=True)
        if t == "array_creation_expression":
            value = node.child_by_field_name("value")
            return self.expr(value) if value is not None else ir.ListLit(**p)
        if t == "array_initializer":
            return ir.ListLit(**p, items=[self.expr(c) for c in named_children(node)])
        if t == "array_access":
            return ir.Subscript(**p, value=self.expr(node.child_by_field_name("array")),
                                index=self.expr(node.child_by_field_name("index")))
        if t == "cast_expression":
            type_text = text(node.child_by_field_name("type"))
            value = self.expr(node.child_by_field_name("value"))
            if type_text in _INT_TYPES:
                return ir.Call(**p, func=ir.Name(**p, id=f"({type_text})"), args=[value])
            return value
        if t == "instanceof_expression":
            return ir.Compare(**p, left=self.expr(named_children(node)[0]), ops=["instanceof"], comparators=[])
        if t in {"method_reference", "class_literal", "super"}:
            return ir.Other(**p, kind=t)
        return None


# ======================================================================= C#


class CSharpLowerer(_BaseLowerer):
    language = "csharp"
    function_types = {"method_declaration", "constructor_declaration", "local_function_statement",
                      "operator_declaration"}
    lambda_types = {"lambda_expression", "anonymous_method_expression"}
    class_types = {"class_declaration", "struct_declaration", "record_declaration", "interface_declaration",
                   "record_struct_declaration"}
    string_types = {"string_literal", "character_literal", "verbatim_string_literal", "raw_string_literal"}
    true_types = {"true"}
    null_types = {"null_literal"}

    def __init__(self, module: ir.Module) -> None:
        super().__init__(module)
        self.controller_stack: list[bool] = []

    def stmt_specific(self, node: Node, toplevel: bool) -> list[ir.Stmt] | None:
        t = node.type
        p = pos(node)
        if t == "using_directive":
            names = [c for c in named_children(node) if c.type in {"qualified_name", "identifier"}]
            alias = node.child_by_field_name("name")
            if names:
                target = text(names[-1])
                self.module.imports[text(alias) if alias is not None else target.rsplit(".", 1)[-1]] = target
            return []
        if t in {"namespace_declaration", "file_scoped_namespace_declaration"}:
            body = node.child_by_field_name("body")
            if body is not None:
                return self.block(named_children(body), toplevel)
            return self.block([c for c in named_children(node) if c.type not in {"qualified_name", "identifier"}],
                              toplevel)
        if t in {"global_statement"}:
            return self.block(named_children(node), toplevel)
        if t in {"local_declaration_statement", "field_declaration", "event_field_declaration"}:
            out: list[ir.Stmt] = []
            for decl_holder in named_children(node):
                if decl_holder.type != "variable_declaration":
                    continue
                for decl in named_children(decl_holder):
                    if decl.type != "variable_declarator":
                        continue
                    name = decl.child_by_field_name("name")
                    kids = [c for c in named_children(decl) if c != name]
                    if name is None or not kids:
                        continue
                    value_node = kids[-1]
                    if value_node.type == "equals_value_clause":
                        inner = named_children(value_node)
                        value_node = inner[-1] if inner else value_node
                    target: ir.Expr = ir.Name(**pos(name), id=text(name))
                    if t == "field_declaration":
                        target = ir.Attr(**pos(name), value=ir.Name(**pos(name), id="this"), attr=text(name))
                    out.append(ir.Assign(**pos(decl), targets=[target], value=self.expr(value_node)))
            return out
        if t == "property_declaration":
            value = node.child_by_field_name("value")
            if value is not None:
                name = text(node.child_by_field_name("name"))
                return [ir.Assign(**p, targets=[ir.Attr(**p, value=ir.Name(**p, id="this"), attr=name)],
                                  value=self.expr(value))]
            return []
        if t == "foreach_statement":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            header = [ir.Assign(**p, targets=[self.expr(left)] if left is not None else [],
                                value=ir.Other(**p, children=[self.expr(right)], kind="iter"))]
            return [ir.Loop(**p, header=header, body=self.body_of(node.child_by_field_name("body")))]
        if t == "using_statement":
            kids = named_children(node)
            pre: list[ir.Stmt] = []
            for kid in kids[:-1]:
                pre.extend(self.stmt(kid, False) if kid.type.endswith("declaration") else
                           [ir.ExprStmt(**pos(kid), expr=self.expr(kid))])
            return pre + self.body_of(node.child_by_field_name("body") or (kids[-1] if kids else None))
        if t == "switch_statement":
            value = self.expr(node.child_by_field_name("value"))
            body = node.child_by_field_name("body")
            chain: list[ir.Stmt] = []
            for section in reversed(named_children(body) if body is not None else []):
                labels = {"case_switch_label", "default_switch_label", "constant_pattern", "case_pattern_switch_label"}
                stmts = [c for c in named_children(section) if c.type not in labels]
                chain = [ir.If(**pos(section), test=value, body=self.block(stmts), orelse=chain)]
            return chain or [ir.ExprStmt(**p, expr=value)]
        if t == "class_declaration":
            base_list = next((c for c in named_children(node) if c.type == "base_list"), None)
            is_controller = base_list is not None and any(
                text(b).endswith(("Controller", "ControllerBase", "PageModel", "Hub"))
                for b in named_children(base_list))
            attrs = self.attributes(node)
            is_controller = is_controller or any(isinstance(a, ir.Name) and a.id in {"ApiController", "Controller"}
                                                 for a in attrs)
            self.controller_stack.append(is_controller)
            try:
                return self.class_decl(node, toplevel)
            finally:
                self.controller_stack.pop()
        return None

    def attributes(self, node: Node) -> list[ir.Expr]:
        out: list[ir.Expr] = []
        for child in node.children:
            if child.type == "attribute_list":
                for attr in named_children(child):
                    if attr.type != "attribute":
                        continue
                    name = text(attr.child_by_field_name("name")).rsplit(".", 1)[-1]
                    if name.endswith("Attribute"):
                        name = name[: -len("Attribute")]
                    args = next((c for c in named_children(attr) if c.type == "attribute_argument_list"), None)
                    name_expr = ir.Name(**pos(attr), id=name)
                    out.append(ir.Call(**pos(attr), func=name_expr, args=[self.expr(a) for a in named_children(args)])
                               if args is not None else name_expr)
        return out

    def function(self, node: Node, nested: bool) -> ir.Function | None:
        name = text(node.child_by_field_name("name")) or ".ctor"
        params: list[ir.Param] = []
        params_node = node.child_by_field_name("parameters")
        for param in named_children(params_node) if params_node is not None else []:
            if param.type != "parameter":
                continue
            pname = param.child_by_field_name("name")
            ptype = param.child_by_field_name("type")
            if pname is None:
                continue
            params.append(ir.Param(name=text(pname), index=len(params),
                                   annotation=text(ptype) if ptype is not None else None))
        decorators = self.attributes(node)
        is_public = any(c.type == "modifier" and text(c) == "public" for c in node.children)
        if self.controller_stack and self.controller_stack[-1] and is_public and node.type == "method_declaration":
            decorators.append(ir.Name(**pos(node), id="__controller_action__"))
        body = node.child_by_field_name("body")
        if body is None:
            body = next((c for c in named_children(node) if c.type == "arrow_expression_clause"), None)
        return self.make_function(node, name, params, body, decorators, nested)

    def lambda_function(self, node: Node) -> ir.Function | None:
        params: list[ir.Param] = []
        pnode = node.child_by_field_name("parameters")
        if pnode is not None:
            if pnode.type in {"identifier", "implicit_parameter"}:
                params.append(ir.Param(name=text(pnode), index=0))
            else:
                for c in named_children(pnode):
                    pname = c.child_by_field_name("name") or c
                    ptype = c.child_by_field_name("type")
                    params.append(ir.Param(name=text(pname), index=len(params),
                                           annotation=text(ptype) if ptype is not None else None))
        return self.make_function(node, f"<lambda@{node.start_point[0] + 1}>", params,
                                  node.child_by_field_name("body"), [], True, class_name="")

    def expr_specific(self, node: Node) -> ir.Expr | None:
        t = node.type
        p = pos(node)
        if t == "invocation_expression":
            func = self.expr(node.child_by_field_name("function"))
            return ir.Call(**p, func=func, args=self.arguments(node.child_by_field_name("arguments")))
        if t == "member_access_expression":
            return ir.Attr(**p, value=self.expr(node.child_by_field_name("expression")),
                           attr=text(node.child_by_field_name("name")))
        if t == "conditional_access_expression":
            kids = named_children(node)
            return self.expr(kids[0]) if kids else ir.Other(**p)
        if t in {"object_creation_expression", "implicit_object_creation_expression"}:
            type_node = node.child_by_field_name("type")
            type_name = text(type_node).split("<", 1)[0] if type_node is not None else "object"
            args = self.arguments(node.child_by_field_name("arguments"))
            init = node.child_by_field_name("initializer")
            if init is not None:
                args.append(self.initializer(init))
            return ir.Call(**p, func=ir.Name(**p, id=type_name), args=args, is_new=True)
        if t == "element_access_expression":
            sub = node.child_by_field_name("subscript")
            kids = named_children(sub) if sub is not None else []
            return ir.Subscript(**p, value=self.expr(node.child_by_field_name("expression")),
                                index=self.expr(kids[0]) if kids else None)
        if t == "interpolated_string_expression":
            parts: list[ir.Expr] = []
            for child in named_children(node):
                if child.type in {"string_content", "interpolated_string_text", "escape_sequence"}:
                    parts.append(ir.Str(**pos(child), value=text(child)))
                elif child.type == "interpolation":
                    inner = [c for c in named_children(child) if c.type not in {"interpolation_brace",
                                                                                "interpolation_format_clause",
                                                                                "interpolation_alignment_clause"}]
                    if inner:
                        parts.append(self.expr(inner[0]))
            return ir.Concat(**p, parts=parts or [ir.Str(**p, value="")], kind="template")
        if t == "verbatim_string_literal":
            return ir.Str(**p, value=text(node)[2:-1])
        if t == "boolean_literal":
            return ir.Const(**p, value=text(node) == "true")
        if t == "cast_expression":
            type_text = text(node.child_by_field_name("type"))
            value = self.expr(node.child_by_field_name("value"))
            if type_text in _INT_TYPES:
                return ir.Call(**p, func=ir.Name(**p, id=f"({type_text})"), args=[value])
            return value
        if t in {"await_expression", "parenthesized_expression", "checked_expression", "ref_expression"}:
            kids = named_children(node)
            return self.expr(kids[-1]) if kids else ir.Other(**p)
        if t in {"initializer_expression", "collection_expression"}:
            return self.initializer(node)
        if t == "array_creation_expression" or t == "implicit_array_creation_expression":
            init = next((c for c in named_children(node) if c.type == "initializer_expression"), None)
            return self.initializer(init) if init is not None else ir.ListLit(**p)
        if t in {"is_expression", "as_expression", "is_pattern_expression"}:
            kids = named_children(node)
            return self.expr(kids[0]) if kids else ir.Other(**p)
        return None

    def initializer(self, node: Node) -> ir.Expr:
        p = pos(node)
        keys: list[ir.Expr | None] = []
        values: list[ir.Expr] = []
        items: list[ir.Expr] = []
        for child in named_children(node):
            if child.type == "assignment_expression":
                left = child.child_by_field_name("left")
                keys.append(ir.Str(**pos(child), value=text(left).strip("[]\"")))
                values.append(self.expr(child.child_by_field_name("right")))
            else:
                items.append(self.expr(child))
        if keys:
            return ir.DictLit(**p, keys=keys, values=values)
        return ir.ListLit(**p, items=items)


# ======================================================================= Go


class GoLowerer(_BaseLowerer):
    language = "go"
    function_types = {"function_declaration", "method_declaration"}
    lambda_types = {"func_literal"}
    string_types = {"interpreted_string_literal", "raw_string_literal", "rune_literal"}
    true_types = {"true"}
    null_types = {"nil"}

    def stmt_specific(self, node: Node, toplevel: bool) -> list[ir.Stmt] | None:
        t = node.type
        p = pos(node)
        if t == "import_declaration":
            for spec in [c for c in named_children(node) if c.type == "import_spec"] + [
                    s for c in named_children(node) if c.type == "import_spec_list" for s in named_children(c)]:
                path_node = spec.child_by_field_name("path")
                path = "".join(text(c) for c in named_children(path_node)) if path_node is not None else ""
                alias = spec.child_by_field_name("name")
                if path:
                    local = text(alias) if alias is not None else path.rsplit("/", 1)[-1]
                    if local not in {"_", "."}:
                        self.module.imports[local] = path
            return []
        if t in {"short_var_declaration", "assignment_statement"}:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            targets = self.targets(left)
            values = [self.expr(c) for c in named_children(right)] if right is not None else []
            op = text(node.child_by_field_name("operator")) if t == "assignment_statement" else ":="
            if op not in {"=", ":="}:
                target = targets[0] if targets else ir.Name(**p, id="_")
                value = values[0] if values else ir.Const(**p)
                combined: ir.Expr = (ir.Concat(**p, parts=[target, value], kind="concat") if op == "+="
                                     else ir.Other(**p, children=[target, value], kind=f"binop:{op[:-1]}"))
                return [ir.Assign(**p, targets=[target], value=combined, augmented=True)]
            if len(values) == len(targets):
                return [ir.Assign(**p, targets=[tg], value=v) for tg, v in zip(targets, values, strict=False)]
            return [ir.Assign(**p, targets=targets, value=values[0] if values else ir.Const(**p))]
        if t in {"var_declaration", "const_declaration"}:
            out: list[ir.Stmt] = []
            specs = [c for c in named_children(node) if c.type in {"var_spec", "const_spec"}]
            specs += [s for c in named_children(node) if c.type in {"var_spec_list", "const_spec_list"}
                      for s in named_children(c)]
            for spec in specs:
                names = [c for c in named_children(spec) if c.type == "identifier"]
                value = spec.child_by_field_name("value")
                if value is None:
                    for n in names:
                        out.append(ir.Assign(**pos(spec), targets=[ir.Name(**pos(n), id=text(n))],
                                             value=ir.Other(**pos(spec), kind="decl")))
                    continue
                values = [self.expr(c) for c in named_children(value)]
                for i, n in enumerate(names):
                    v = values[i] if i < len(values) else (values[0] if values else ir.Const(**pos(spec)))
                    out.append(ir.Assign(**pos(spec), targets=[ir.Name(**pos(n), id=text(n))], value=v))
            return out
        if t == "for_statement":
            header: list[ir.Stmt] = []
            body = node.child_by_field_name("body")
            for child in named_children(node):
                if child == body:
                    continue
                if child.type == "range_clause":
                    left = child.child_by_field_name("left")
                    right = child.child_by_field_name("right")
                    header.append(ir.Assign(**pos(child), targets=self.targets(left),
                                            value=ir.Other(**pos(child), children=[self.expr(right)], kind="iter")))
                elif child.type == "for_clause":
                    for field in ("initializer", "condition", "update"):
                        part = child.child_by_field_name(field)
                        if part is not None:
                            header.extend(self.stmt(part, False))
                else:
                    header.append(ir.ExprStmt(**pos(child), expr=self.expr(child)))
            return [ir.Loop(**p, header=header, body=self.body_of(body))]
        if t in {"expression_switch_statement", "type_switch_statement", "select_statement"}:
            value_node = node.child_by_field_name("value")
            value = self.expr(value_node) if value_node is not None else ir.Const(**p)
            chain: list[ir.Stmt] = []
            cases = [c for c in named_children(node) if c.type in {"expression_case", "default_case", "type_case",
                                                                   "communication_case"}]
            for case in reversed(cases):
                stmts = [c for c in named_children(case) if c.type not in {"expression_list", "type_identifier"}
                         and c != case.child_by_field_name("value")]
                chain = [ir.If(**pos(case), test=value, body=self.block(stmts), orelse=chain)]
            init = node.child_by_field_name("initializer")
            return (self.stmt(init, False) if init is not None else []) + (chain or [ir.ExprStmt(**p, expr=value)])
        if t == "go_statement":
            kids = named_children(node)
            inner = self.expr(kids[0]) if kids else ir.Const(**p)
            return [ir.ExprStmt(**p, expr=ir.Call(**p, func=ir.Name(**p, id="__go__"), args=[inner]))]
        if t == "defer_statement":
            kids = named_children(node)
            return [ir.ExprStmt(**p, expr=self.expr(kids[0]))] if kids else []
        if t in {"inc_statement", "dec_statement"}:
            kids = named_children(node)
            target = self.expr(kids[0]) if kids else ir.Name(**p, id="_")
            return [ir.Assign(**p, targets=[target], value=ir.Other(**p, children=[target], kind="unary"),
                              augmented=True)]
        if t == "send_statement":
            return [ir.ExprStmt(**p, expr=ir.Other(**p, children=[self.expr(c) for c in named_children(node)],
                                                   kind="send"))]
        if t in {"type_declaration", "package_clause"}:
            return []
        return None

    def function(self, node: Node, nested: bool) -> ir.Function | None:
        name = text(node.child_by_field_name("name")) or "<func>"
        params: list[ir.Param] = []
        class_name = None
        receiver = node.child_by_field_name("receiver")
        if receiver is not None:
            decl = next((c for c in named_children(receiver) if c.type == "parameter_declaration"), None)
            if decl is not None:
                rtype = text(decl.child_by_field_name("type")).lstrip("*")
                class_name = rtype.split("[", 1)[0]
                rname = decl.child_by_field_name("name")
                params.append(ir.Param(name=text(rname) if rname is not None else "_recv", index=0,
                                       annotation=rtype))
        self._params(node.child_by_field_name("parameters"), params)
        func = self.make_function(node, name, params, node.child_by_field_name("body"), [], nested,
                                  class_name=class_name or "")
        if class_name:
            func.class_name = class_name
            func.is_method = True
            func.qualname = f"{class_name}.{name}"
        return func

    def _params(self, pnode: Node | None, params: list[ir.Param]) -> None:
        for decl in named_children(pnode) if pnode is not None else []:
            if decl.type not in {"parameter_declaration", "variadic_parameter_declaration"}:
                continue
            ptype = decl.child_by_field_name("type")
            names = [c for c in named_children(decl) if c.type == "identifier"]
            for n in names or [decl]:
                params.append(ir.Param(name=text(n) if names else f"_p{len(params)}", index=len(params),
                                       annotation=text(ptype) if ptype is not None else None,
                                       kind="vararg" if decl.type.startswith("variadic") else "normal"))

    def lambda_function(self, node: Node) -> ir.Function | None:
        params: list[ir.Param] = []
        self._params(node.child_by_field_name("parameters"), params)
        return self.make_function(node, f"<func@{node.start_point[0] + 1}>", params,
                                  node.child_by_field_name("body"), [], True, class_name="")

    def expr_specific(self, node: Node) -> ir.Expr | None:
        t = node.type
        p = pos(node)
        if t == "call_expression":
            func_node = node.child_by_field_name("function")
            args = self.arguments(node.child_by_field_name("arguments"))
            func = self.expr(func_node)
            if func_node is not None and func_node.type in {"slice_type", "array_type", "map_type",
                                                            "parenthesized_type", "pointer_type"}:
                func = ir.Name(**pos(func_node), id=text(func_node))
            return ir.Call(**p, func=func, args=args)
        if t == "selector_expression":
            return ir.Attr(**p, value=self.expr(node.child_by_field_name("operand")),
                           attr=text(node.child_by_field_name("field")))
        if t == "index_expression":
            return ir.Subscript(**p, value=self.expr(node.child_by_field_name("operand")),
                                index=self.expr(node.child_by_field_name("index")))
        if t == "slice_expression":
            return ir.Subscript(**p, value=self.expr(node.child_by_field_name("operand")), index=None)
        if t == "type_assertion_expression" or t == "type_conversion_expression":
            operand = node.child_by_field_name("operand")
            return self.expr(operand) if operand is not None else ir.Other(**p)
        if t == "unary_expression":
            op = text(node.child_by_field_name("operator"))
            operand = self.expr(node.child_by_field_name("operand"))
            if op in {"&", "*", "<-"}:
                return operand
            return ir.Other(**p, children=[operand], kind="not" if op == "!" else "unary")
        if t == "composite_literal":
            type_node = node.child_by_field_name("type")
            body = node.child_by_field_name("body")
            type_name = text(type_node).lstrip("*&") if type_node is not None else "struct"
            keyed = [c for c in named_children(body) if c.type == "keyed_element"] if body is not None else []
            if keyed:
                keys: list[ir.Expr | None] = []
                values: list[ir.Expr] = []
                for element in keyed:
                    kids = named_children(element)
                    if len(kids) >= 2:
                        keys.append(ir.Str(**pos(kids[0]), value=text(kids[0])))
                        values.append(self.expr(kids[1]))
                return ir.Call(**p, func=ir.Name(**p, id=type_name), args=[ir.DictLit(**p, keys=keys, values=values)],
                               is_new=True)
            elements = named_children(body) if body is not None else []
            # Newer grammars wrap each element: literal_value > literal_element > expression.
            elements = [named_children(c)[0] if c.type == "literal_element" and named_children(c) else c
                        for c in elements]
            return ir.ListLit(**p, items=[self.expr(c) for c in elements])
        if t in {"raw_string_literal"}:
            return ir.Str(**p, value=text(node).strip("`"))
        if t in {"iota"}:
            return ir.Const(**p, value=0)
        return None


# ==================================================================== C/C++


def _declarator_name(node: Node | None) -> Node | None:
    """Innermost identifier of a (possibly pointer/array/function) declarator."""
    current = node
    while current is not None and current.type not in {"identifier", "field_identifier", "qualified_identifier",
                                                       "destructor_name", "operator_name"}:
        inner = current.child_by_field_name("declarator")
        if inner is None:
            kids = [c for c in named_children(current) if c.type not in {"type_qualifier", "attribute_specifier"}]
            inner = kids[0] if kids else None
        current = inner
    return current


class CLowerer(_BaseLowerer):
    language = "c"
    function_types = {"function_definition"}
    lambda_types = {"lambda_expression"}
    class_types: set[str] = set()
    string_types = {"string_literal", "char_literal", "raw_string_literal", "system_lib_string"}
    null_types = {"null", "nullptr", "NULL"}

    def plus_is_concat(self, left: ir.Expr, right: ir.Expr) -> bool:
        # In C, + on char* is pointer arithmetic, not concatenation.
        return False

    def stmt_specific(self, node: Node, toplevel: bool) -> list[ir.Stmt] | None:
        t = node.type
        p = pos(node)
        if t == "declaration":
            out: list[ir.Stmt] = []
            for decl in named_children(node):
                if decl.type == "init_declarator":
                    name = _declarator_name(decl.child_by_field_name("declarator"))
                    value = decl.child_by_field_name("value")
                    if name is not None and value is not None:
                        out.append(ir.Assign(**pos(decl), targets=[ir.Name(**pos(name), id=self._name(name))],
                                             value=self.expr(value)))
                elif decl.type in {"identifier", "array_declarator", "pointer_declarator"}:
                    name = _declarator_name(decl)
                    if name is not None:
                        out.append(ir.Assign(**pos(decl), targets=[ir.Name(**pos(name), id=self._name(name))],
                                             value=ir.Other(**pos(decl), kind="decl")))
            return out
        if t == "preproc_def":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and value is not None:
                raw = text(value).strip()
                if raw.startswith('"') and raw.endswith('"'):
                    return [ir.Assign(**p, targets=[ir.Name(**pos(name), id=text(name))],
                                      value=ir.Str(**p, value=raw[1:-1]))]
            return []
        if t in {"preproc_ifdef", "preproc_if", "preproc_else", "preproc_elif", "linkage_specification",
                 "namespace_definition", "template_declaration", "export_declaration"}:
            body = node.child_by_field_name("body")
            kids = named_children(body) if body is not None else [c for c in named_children(node)
                                                                    if c.type not in {"identifier", "string_literal",
                                                                                      "template_parameter_list",
                                                                                      "namespace_identifier"}]
            return self.block(kids, toplevel)
        if t == "switch_statement":
            value = self.expr(node.child_by_field_name("condition"))
            body = node.child_by_field_name("body")
            return [ir.If(**p, test=value, body=self.body_of(body), orelse=[])]
        if t == "case_statement":
            return self.block([c for c in named_children(node) if c != node.child_by_field_name("value")])
        if t == "for_range_loop":
            decl = node.child_by_field_name("declarator")
            right = node.child_by_field_name("right")
            name = _declarator_name(decl)
            header = [ir.Assign(**p, targets=[ir.Name(**pos(name), id=text(name))] if name is not None else [],
                                value=ir.Other(**p, children=[self.expr(right)], kind="iter"))]
            return [ir.Loop(**p, header=header, body=self.body_of(node.child_by_field_name("body")))]
        return None

    def expr_stmt(self, node: Node) -> list[ir.Stmt]:
        # std::cin >> a >> b  — each extracted operand receives untrusted input.
        if node.type == "binary_expression" and text(node.child_by_field_name("operator")) == ">>":
            operands: list[Node] = []
            current: Node | None = node
            while current is not None and current.type == "binary_expression" and text(
                    current.child_by_field_name("operator")) == ">>":
                right = current.child_by_field_name("right")
                if right is not None:
                    operands.append(right)
                current = current.child_by_field_name("left")
            stream = text(current).replace("::", ".") if current is not None else ""
            if stream.endswith(("cin", "wcin")) or stream.endswith("ifstream"):
                p = pos(node)
                return [ir.Assign(**p, targets=[self.expr(o)],
                                  value=ir.Call(**p, func=ir.Name(**p, id=f"{stream}.extract")))
                        for o in reversed(operands)]
        return super().expr_stmt(node)

    def _name(self, node: Node) -> str:
        return text(node).replace("::", ".")

    def function(self, node: Node, nested: bool) -> ir.Function | None:
        declarator = node.child_by_field_name("declarator")
        func_decl = declarator
        while func_decl is not None and func_decl.type != "function_declarator":
            func_decl = func_decl.child_by_field_name("declarator")
        if func_decl is None:
            return None
        name_node = _declarator_name(func_decl.child_by_field_name("declarator"))
        full = self._name(name_node) if name_node is not None else "<function>"
        class_name = self.class_stack[-1] if self.class_stack else None
        if "." in full:
            class_name, _, short = full.rpartition(".")
        else:
            short = full
        params: list[ir.Param] = []
        plist = func_decl.child_by_field_name("parameters")
        for param in named_children(plist) if plist is not None else []:
            if param.type in {"parameter_declaration", "optional_parameter_declaration"}:
                pname = _declarator_name(param.child_by_field_name("declarator"))
                ptype = param.child_by_field_name("type")
                if pname is not None:
                    params.append(ir.Param(name=text(pname), index=len(params),
                                           annotation=text(ptype) if ptype is not None else None))
            elif param.type == "variadic_parameter":
                params.append(ir.Param(name="...", index=len(params), kind="vararg"))
        func = self.make_function(node, short, params, node.child_by_field_name("body"), [], nested,
                                  class_name=class_name or "")
        if class_name:
            func.class_name = class_name
            func.is_method = True
            func.qualname = f"{class_name}.{short}"
        return func

    def lambda_function(self, node: Node) -> ir.Function | None:
        params: list[ir.Param] = []
        decl = node.child_by_field_name("declarator")
        plist = decl.child_by_field_name("parameters") if decl is not None else None
        for param in named_children(plist) if plist is not None else []:
            pname = _declarator_name(param.child_by_field_name("declarator"))
            if pname is not None:
                params.append(ir.Param(name=text(pname), index=len(params)))
        return self.make_function(node, f"<lambda@{node.start_point[0] + 1}>", params,
                                  node.child_by_field_name("body"), [], True, class_name="")

    def expr_specific(self, node: Node) -> ir.Expr | None:
        t = node.type
        p = pos(node)
        if t == "call_expression":
            return ir.Call(**p, func=self.expr(node.child_by_field_name("function")),
                           args=self.arguments(node.child_by_field_name("arguments")))
        if t == "field_expression":
            return ir.Attr(**p, value=self.expr(node.child_by_field_name("argument")),
                           attr=text(node.child_by_field_name("field")))
        if t == "subscript_expression":
            index = node.child_by_field_name("index")
            if index is None:
                indices = node.child_by_field_name("indices")
                kids = named_children(indices) if indices is not None else []
                index = kids[0] if kids else None
            return ir.Subscript(**p, value=self.expr(node.child_by_field_name("argument")), index=self.expr(index)
                                if index is not None else None)
        if t in {"pointer_expression", "cast_expression", "parenthesized_expression", "reference_expression"}:
            value = node.child_by_field_name("argument") or node.child_by_field_name("value")
            if value is None:
                kids = [c for c in named_children(node) if c.type != "type_descriptor"]
                value = kids[-1] if kids else None
            return self.expr(value) if value is not None else ir.Other(**p)
        if t in {"sizeof_expression", "alignof_expression", "offsetof_expression"}:
            return ir.Const(**p, value="sizeof")
        if t == "concatenated_string":
            return ir.Str(**p, value="".join(
                "".join(text(c) for c in s.children if c.type in self.string_content_types)
                for s in named_children(node) if s.type == "string_literal"))
        if t in {"qualified_identifier", "template_function", "scoped_identifier", "scoped_type_identifier"}:
            return ir.Name(**p, id=self._name(node).split("<", 1)[0])
        if t == "new_expression":
            type_node = node.child_by_field_name("type")
            declarator = node.child_by_field_name("declarator")
            args_node = node.child_by_field_name("arguments")
            if declarator is not None and declarator.type == "new_declarator":
                size = named_children(declarator)
                return ir.Call(**p, func=ir.Name(**p, id="new[]"), args=[self.expr(size[0])] if size else [],
                               is_new=True)
            type_name = text(type_node).split("<", 1)[0] if type_node is not None else "new"
            return ir.Call(**p, func=ir.Name(**p, id=type_name),
                           args=self.arguments(args_node), is_new=True)
        if t == "delete_expression":
            kids = named_children(node)
            is_array = "[" in text(node).split(kids[-1].text.decode() if kids else "", 1)[0] if kids else False
            return ir.Call(**p, func=ir.Name(**p, id="delete[]" if is_array else "delete"),
                           args=[self.expr(kids[-1])] if kids else [])
        if t == "initializer_list":
            return ir.ListLit(**p, items=[self.expr(c) for c in named_children(node)])
        if t in {"compound_literal_expression"}:
            kids = named_children(node)
            return self.expr(kids[-1]) if kids else ir.Other(**p)
        if t in {"true", "false"}:
            return ir.Const(**p, value=t == "true")
        return None


class CppLowerer(CLowerer):
    language = "cpp"
    class_types = {"class_specifier", "struct_specifier"}

    def plus_is_concat(self, left: ir.Expr, right: ir.Expr) -> bool:
        # std::string + std::string concatenates; with a string literal on either side it is almost always text.
        return any(isinstance(x, ir.Str | ir.Concat) for x in (left, right)) or True

    def stmt_specific(self, node: Node, toplevel: bool) -> list[ir.Stmt] | None:
        if node.type in {"class_specifier", "struct_specifier"} and node.child_by_field_name("body") is not None:
            return self.class_decl(node, toplevel)
        if node.type == "field_declaration":
            return []
        return super().stmt_specific(node, toplevel)


# ================================================================ frontend


_LOWERERS: dict[str, tuple[type[_BaseLowerer], str]] = {
    "java": (JavaLowerer, "java"),
    "csharp": (CSharpLowerer, "csharp"),
    "go": (GoLowerer, "go"),
    "c": (CLowerer, "c"),
    "cpp": (CppLowerer, "cpp"),
}


class GenericFrontend:
    def __init__(self, language: str) -> None:
        if language not in _LOWERERS:
            raise ValueError(f"unsupported language: {language}")
        self.language = language

    def parse(self, path: str, source: str) -> ir.Module:
        cls, grammar = _LOWERERS[self.language]
        root = parse(grammar, source.encode("utf-8", errors="replace"))
        toplevel = ir.Function(line=1, name="<module>", qualname="<module>")
        module = ir.Module(path=path, language=self.language, toplevel=toplevel, lines=source.splitlines())
        module.parse_errors = count_errors(root)
        lowerer = cls(module)
        try:
            toplevel.body = lowerer.lower_root(root)
        except RecursionError:
            module.parse_errors += 1
        return module
