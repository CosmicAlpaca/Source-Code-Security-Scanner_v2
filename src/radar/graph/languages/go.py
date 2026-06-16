"""Go extractor: function/method defs, call sites, imports, HTTP route handlers.

Supports standard library net/http and gorilla/mux route registration patterns.
Plugin self-registers — zero core changes required (see base.py).
"""

import posixpath

try:
    import tree_sitter_go as tsgo
    from tree_sitter import Language, Parser
    _LANGUAGE = Language(tsgo.language())
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

from radar.graph.languages.base import LanguageExtractor, register
from radar.graph.model import CallSite, FileFacts, FunctionDef, ImportBinding, RouteDef

# HTTP handler registration patterns:
#   http.HandleFunc("/path", handler)
#   mux.HandleFunc("/path", handler)
#   router.Get("/path", handler)  — gorilla/mux
_HANDLE_FUNC = "HandleFunc"
_ROUTE_METHODS = {"Get", "Post", "Put", "Delete", "Patch", "Head", "Options"}
_ROUTE_OBJECTS = {"http", "mux", "router", "r", "srv"}


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node else ""


def _string_value(node) -> str | None:
    """Extract string content from interpreted_string_literal (strips quotes)."""
    if node is None:
        return None
    if node.type == "interpreted_string_literal":
        raw = _text(node)
        return raw[1:-1] if len(raw) >= 2 else raw
    return None


class GoExtractor(LanguageExtractor):
    name = "go"
    extensions = (".go",)

    def extract(self, source: bytes, relpath: str) -> FileFacts:
        if not _AVAILABLE:
            return FileFacts(file=relpath, language=self.name)
        tree = Parser(_LANGUAGE).parse(source)
        facts = FileFacts(file=relpath, language=self.name)
        self._walk(tree.root_node, facts, func_stack=[], pkg=None)
        return facts

    def resolve_module(self, source: str, importer: str, files: set[str]) -> str | None:
        """Go uses package paths — no relative resolution needed for the graph."""
        return None

    # -- traversal ----------------------------------------------------------

    def _walk(self, node, facts, func_stack, pkg) -> None:
        handler = getattr(self, f"_on_{node.type}", None)
        if handler and handler(node, facts, func_stack, pkg):
            return
        for child in node.children:
            self._walk(child, facts, func_stack, pkg)

    def _on_function_declaration(self, node, facts, func_stack, pkg) -> bool:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return False
        name = _text(name_node)
        facts.defs.append(FunctionDef(name, node.start_point[0] + 1, node.end_point[0] + 1))
        func_stack.append(name)
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                self._walk(child, facts, func_stack, pkg)
        func_stack.pop()
        return True

    def _on_method_declaration(self, node, facts, func_stack, pkg) -> bool:
        name_node = node.child_by_field_name("name")
        receiver = node.child_by_field_name("receiver")
        if name_node is None:
            return False
        method_name = _text(name_node)
        # Qualify with receiver type: func (h *Handler) ServeHTTP → "Handler.ServeHTTP"
        recv_type = self._receiver_type(receiver)
        qualified = f"{recv_type}.{method_name}" if recv_type else method_name
        facts.defs.append(FunctionDef(qualified, node.start_point[0] + 1, node.end_point[0] + 1))
        func_stack.append(qualified)
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                self._walk(child, facts, func_stack, pkg)
        func_stack.pop()
        return True

    @staticmethod
    def _receiver_type(receiver_node) -> str | None:
        """Extract type name from receiver parameter list, e.g. '(h *Handler)' → 'Handler'."""
        if receiver_node is None:
            return None
        for param in receiver_node.named_children:
            if param.type == "parameter_declaration":
                type_node = param.child_by_field_name("type")
                if type_node is None:
                    continue
                # *TypeName → strip pointer
                if type_node.type == "pointer_type":
                    inner = type_node.named_children[0] if type_node.named_children else None
                    return _text(inner) if inner else None
                return _text(type_node)
        return None

    def _on_call_expression(self, node, facts, func_stack, pkg) -> bool:
        fn_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        if fn_node is None:
            return False
        caller = func_stack[-1] if func_stack else None
        line = node.start_point[0] + 1

        if fn_node.type == "identifier":
            facts.calls.append(CallSite(caller, _text(fn_node), line))
        elif fn_node.type == "selector_expression":
            operand = fn_node.child_by_field_name("operand")
            field = fn_node.child_by_field_name("field")
            if operand is not None and field is not None:
                obj_name = _text(operand)
                method = _text(field)
                facts.calls.append(CallSite(caller, method, line, object=obj_name))
                # Route detection
                self._maybe_route(obj_name, method, args_node, facts, func_stack, line)

        # Recurse into arguments
        if args_node:
            for child in args_node.children:
                self._walk(child, facts, func_stack, pkg)
        return True

    def _maybe_route(self, obj: str, method: str, args_node, facts, func_stack, line) -> None:
        """Detect http.HandleFunc / mux.Get patterns and emit RouteDef."""
        arg_nodes = args_node.named_children if args_node else []

        if method == _HANDLE_FUNC and len(arg_nodes) >= 2:
            # http.HandleFunc("/path", handlerFunc)
            path = _string_value(arg_nodes[0])
            handler = self._handler_name(arg_nodes[1])
            if path and handler:
                # HandleFunc registers for all methods — use "*"
                facts.routes.append(RouteDef("*", path, handler, line))

        elif method in _ROUTE_METHODS and obj in _ROUTE_OBJECTS and len(arg_nodes) >= 2:
            # router.Get("/path", handler) — gorilla/mux style
            path = _string_value(arg_nodes[0])
            handler = self._handler_name(arg_nodes[1])
            if path and handler:
                facts.routes.append(RouteDef(method.upper(), path, handler, line))

    @staticmethod
    def _handler_name(node) -> str | None:
        if node is None:
            return None
        if node.type == "identifier":
            return _text(node)
        if node.type == "selector_expression":
            field = node.child_by_field_name("field")
            return _text(field) if field else None
        return None

    def _on_import_declaration(self, node, facts, func_stack, pkg) -> bool:
        for child in node.named_children:
            if child.type == "import_spec_list":
                for spec in child.named_children:
                    if spec.type == "import_spec":
                        self._add_import(spec, facts)
            elif child.type == "import_spec":
                self._add_import(child, facts)
        return True

    @staticmethod
    def _add_import(spec_node, facts) -> None:
        path_node = spec_node.child_by_field_name("path")
        name_node = spec_node.child_by_field_name("name")
        if path_node is None:
            return
        source = _string_value(path_node) or ""
        # Local name: explicit alias, or last path segment
        if name_node is not None and name_node.type in ("identifier", "package_identifier"):
            local = _text(name_node)
        else:
            local = source.rsplit("/", 1)[-1]
        facts.imports.append(ImportBinding(local, source, "*"))


if _AVAILABLE:
    register(GoExtractor())
