"""Shared tree-sitter plumbing for the JavaScript/TypeScript and PHP frontends."""

from __future__ import annotations

from functools import lru_cache

from tree_sitter import Language, Node, Parser


@lru_cache(maxsize=8)
def language(name: str) -> Language:
    if name == "javascript":
        import tree_sitter_javascript as mod

        return Language(mod.language())
    if name == "typescript":
        import tree_sitter_typescript as mod

        return Language(mod.language_typescript())
    if name == "tsx":
        import tree_sitter_typescript as mod

        return Language(mod.language_tsx())
    if name == "php":
        import tree_sitter_php as mod

        return Language(mod.language_php())
    if name == "java":
        import tree_sitter_java as mod

        return Language(mod.language())
    if name == "csharp":
        import tree_sitter_c_sharp as mod

        return Language(mod.language())
    if name == "go":
        import tree_sitter_go as mod

        return Language(mod.language())
    if name == "c":
        import tree_sitter_c as mod

        return Language(mod.language())
    if name == "cpp":
        import tree_sitter_cpp as mod

        return Language(mod.language())
    raise ValueError(f"no tree-sitter grammar for {name}")


def parse(name: str, source: bytes) -> Node:
    parser = Parser(language(name))
    return parser.parse(source).root_node


def text(node: Node | None) -> str:
    if node is None:
        return ""
    return node.text.decode("utf-8", errors="replace") if node.text is not None else ""


def pos(node: Node) -> dict:
    return {"line": node.start_point[0] + 1, "col": node.start_point[1], "end_line": node.end_point[0] + 1}


def named_children(node: Node) -> list[Node]:
    return [c for c in node.children if c.is_named and c.type != "comment"]


def unary_kind(node: Node) -> str:
    """IR kind for a prefix operator node: ``not`` for logical negation, ``unary`` otherwise."""
    op = node.child_by_field_name("operator")
    if op is None and node.children and not node.children[0].is_named:
        op = node.children[0]
    return "not" if text(op) == "!" else "unary"


def count_errors(node: Node, limit: int = 1000) -> int:
    """Number of ERROR / MISSING nodes (bounded)."""
    count = 0
    stack = [node]
    while stack and count < limit:
        current = stack.pop()
        if current.type == "ERROR" or current.is_missing:
            count += 1
        if current.has_error:
            stack.extend(current.children)
    return count
