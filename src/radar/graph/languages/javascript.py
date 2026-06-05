"""JS/TS/TSX extractor: function defs, call sites, imports, Express routes.

Pure parsing via tree-sitter — scanned code is never executed. Uses manual AST
walking (node.type / child_by_field_name) which is stable across py-tree-sitter
versions, instead of the query API which is not.
"""

import posixpath

import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from tree_sitter import Language, Parser

from radar.graph.languages.base import LanguageExtractor, register
from radar.graph.languages.javascript_imports import (
    parse_import_statement,
    parse_require_bindings,
    string_value as _string_value,
    text as _text,
)
from radar.graph.model import CallSite, FileFacts, FunctionDef, RouteDef

_LANGUAGES = {
    ".js": Language(tsjs.language()),
    ".jsx": Language(tsjs.language()),
    ".mjs": Language(tsjs.language()),
    ".cjs": Language(tsjs.language()),
    ".ts": Language(tsts.language_typescript()),
    ".tsx": Language(tsts.language_tsx()),
}

_FUNC_VALUE_TYPES = {"arrow_function", "function_expression", "function", "generator_function"}
_ROUTE_OBJECTS = {"app", "router", "server"}
_ROUTE_METHODS = {"get", "post", "put", "delete", "patch"}
_SOURCE_EXTS = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")


class JavaScriptExtractor(LanguageExtractor):
    name = "javascript"
    extensions = tuple(_LANGUAGES)

    def extract(self, source: bytes, relpath: str) -> FileFacts:
        ext = relpath[relpath.rfind(".") :].lower()
        parser = Parser(_LANGUAGES[ext])
        tree = parser.parse(source)
        facts = FileFacts(file=relpath, language=self.name)
        self._walk(tree.root_node, facts, func_stack=[], class_name=None)
        return facts

    def resolve_module(self, source: str, importer: str, files: set[str]) -> str | None:
        """'./utils' relative to importer -> repo relpath, None if not local."""
        if not source.startswith("."):
            return None
        base = posixpath.normpath(posixpath.join(posixpath.dirname(importer), source))
        candidates = [base] + [base + e for e in _SOURCE_EXTS]
        candidates += [posixpath.join(base, "index" + e) for e in _SOURCE_EXTS]
        return next((c for c in candidates if c in files), None)

    # -- traversal ----------------------------------------------------------

    def _walk(self, node, facts, func_stack, class_name) -> None:
        handler = getattr(self, f"_on_{node.type}", None)
        if handler and handler(node, facts, func_stack, class_name):
            return  # handler did its own recursion
        for child in node.children:
            if child.type == "class_declaration" or child.type == "class":
                name_node = child.child_by_field_name("name")
                self._walk(child, facts, func_stack, _text(name_node) if name_node else class_name)
            else:
                self._walk(child, facts, func_stack, class_name)

    def _add_def(self, name, node, facts, func_stack) -> None:
        facts.defs.append(
            FunctionDef(name=name, start_line=node.start_point[0] + 1, end_line=node.end_point[0] + 1)
        )

    def _recurse_body(self, name, node, facts, func_stack, class_name) -> None:
        func_stack.append(name)
        for child in node.children:
            self._walk(child, facts, func_stack, class_name)
        func_stack.pop()

    def _on_function_declaration(self, node, facts, func_stack, class_name) -> bool:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return False
        name = _text(name_node)
        self._add_def(name, node, facts, func_stack)
        self._recurse_body(name, node, facts, func_stack, class_name)
        return True

    _on_generator_function_declaration = _on_function_declaration

    def _on_method_definition(self, node, facts, func_stack, class_name) -> bool:
        name_node = node.child_by_field_name("name")
        if name_node is None or name_node.type == "computed_property_name":
            return False
        name = _text(name_node)
        qualified = f"{class_name}.{name}" if class_name else name
        self._add_def(qualified, node, facts, func_stack)
        self._recurse_body(qualified, node, facts, func_stack, class_name)
        return True

    def _on_variable_declarator(self, node, facts, func_stack, class_name) -> bool:
        name_node = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name_node is None or value is None:
            return False
        if value.type in _FUNC_VALUE_TYPES and name_node.type == "identifier":
            name = _text(name_node)
            self._add_def(name, value, facts, func_stack)
            self._recurse_body(name, value, facts, func_stack, class_name)
            return True
        if value.type == "call_expression":  # const x = require('...')
            fn = value.child_by_field_name("function")
            if fn is not None and fn.type == "identifier" and _text(fn) == "require":
                args = value.child_by_field_name("arguments")
                src = _string_value(args.named_children[0]) if args and args.named_children else None
                if src:
                    parse_require_bindings(name_node, src, facts)
                    return True
        return False

    def _on_pair(self, node, facts, func_stack, class_name) -> bool:
        key, value = node.child_by_field_name("key"), node.child_by_field_name("value")
        if key is None or value is None or value.type not in _FUNC_VALUE_TYPES:
            return False
        name = _string_value(key) if key.type == "string" else _text(key)
        if not name or key.type == "computed_property_name":
            return False
        self._add_def(name, value, facts, func_stack)
        self._recurse_body(name, value, facts, func_stack, class_name)
        return True

    def _on_assignment_expression(self, node, facts, func_stack, class_name) -> bool:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None or right.type not in _FUNC_VALUE_TYPES:
            return False
        if left.type != "member_expression":
            return False
        prop = left.child_by_field_name("property")
        if prop is None or prop.type != "property_identifier":
            return False
        name = _text(prop)  # exports.foo = () => {} -> "foo"
        self._add_def(name, right, facts, func_stack)
        self._recurse_body(name, right, facts, func_stack, class_name)
        return True

    def _on_import_statement(self, node, facts, func_stack, class_name) -> bool:
        parse_import_statement(node, facts)
        return True

    def _on_call_expression(self, node, facts, func_stack, class_name) -> bool:
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None:
            return False
        caller = func_stack[-1] if func_stack else None
        line = node.start_point[0] + 1
        if fn.type == "identifier":
            name = _text(fn)
            if name != "require":
                facts.calls.append(CallSite(caller, name, line))
        elif fn.type == "member_expression":
            if self._maybe_route(fn, args, facts, func_stack, class_name, line):
                return True
            prop = fn.child_by_field_name("property")
            obj = fn.child_by_field_name("object")
            if prop is not None and prop.type == "property_identifier":
                obj_name = _text(obj) if obj is not None and obj.type == "identifier" else None
                facts.calls.append(CallSite(caller, _text(prop), line, object=obj_name))
        if args is not None:
            for child in args.children:
                self._walk(child, facts, func_stack, class_name)
        return True

    def _maybe_route(self, fn, args, facts, func_stack, class_name, line) -> bool:
        obj, prop = fn.child_by_field_name("object"), fn.child_by_field_name("property")
        if obj is None or prop is None or obj.type != "identifier":
            return False
        if _text(obj) not in _ROUTE_OBJECTS or _text(prop) not in _ROUTE_METHODS:
            return False
        arg_nodes = args.named_children if args is not None else []
        path = _string_value(arg_nodes[0]) if arg_nodes else None
        if path is None:
            return False
        method = _text(prop).upper()
        for handler_node in arg_nodes[1:]:
            if handler_node.type == "identifier":
                facts.routes.append(RouteDef(method, path, _text(handler_node), line))
            elif handler_node.type in _FUNC_VALUE_TYPES:
                synthetic = f"<route {method} {path}>"
                self._add_def(synthetic, handler_node, facts, func_stack)
                facts.routes.append(RouteDef(method, path, synthetic, line))
                self._recurse_body(synthetic, handler_node, facts, func_stack, class_name)
        return True


register(JavaScriptExtractor())
