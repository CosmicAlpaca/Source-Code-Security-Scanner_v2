"""PHP extractor: function/method defs, call sites, imports, route handlers.

Supports Laravel route registration (Route::get/post/...) with closure and
[Controller::class, 'method'] handlers, plus a plain-PHP entrypoint heuristic
(functions that read $_GET/$_POST/... are marked as HTTP entrypoints).
Plugin self-registers — zero core changes required (see base.py).
"""

try:
    import tree_sitter_php as tsphp
    from tree_sitter import Language, Parser
    _LANGUAGE = Language(tsphp.language_php())
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

from radar.graph.languages.base import LanguageExtractor, register
from radar.graph.model import CallSite, FileFacts, FunctionDef, ImportBinding, RouteDef

# Laravel facade + HTTP verbs: Route::get("/path", handler)
_ROUTE_FACADE = "Route"
_ROUTE_VERBS = {"get", "post", "put", "patch", "delete", "options", "any"}
# Superglobals whose use marks the enclosing function as an HTTP entrypoint
_SUPERGLOBALS = {"_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"}


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node else ""


def _string_value(node) -> str | None:
    """Content of a PHP string literal (encapsed/single-quoted), quotes stripped."""
    if node is None:
        return None
    if node.type in ("encapsed_string", "string"):
        for child in node.named_children:
            if child.type == "string_content":
                return _text(child)
        raw = _text(node)
        return raw[1:-1] if len(raw) >= 2 else raw
    return None


def _arg_exprs(args_node) -> list:
    """Unwrap `arguments` → inner expression of each `argument` node."""
    if args_node is None:
        return []
    out = []
    for child in args_node.named_children:
        inner = child.named_children[0] if child.type == "argument" and child.named_children else child
        out.append(inner)
    return out


class PHPExtractor(LanguageExtractor):
    name = "php"
    extensions = (".php",)

    def extract(self, source: bytes, relpath: str) -> FileFacts:
        if not _AVAILABLE:
            return FileFacts(file=relpath, language=self.name)
        tree = Parser(_LANGUAGE).parse(source)
        facts = FileFacts(file=relpath, language=self.name)
        self._walk(tree.root_node, facts, func_stack=[], class_name=None)
        return facts

    def resolve_module(self, source: str, importer: str, files: set[str]) -> str | None:
        """Best-effort PSR-4: match the imported class basename to a <Class>.php file."""
        target = source.rsplit("\\", 1)[-1] + ".php"
        for f in files:
            if f == target or f.endswith("/" + target):
                return f
        return None

    # -- traversal ----------------------------------------------------------

    def _walk(self, node, facts, func_stack, class_name) -> None:
        handler = getattr(self, f"_on_{node.type}", None)
        if handler and handler(node, facts, func_stack, class_name):
            return
        for child in node.children:
            self._walk(child, facts, func_stack, class_name)

    def _on_function_definition(self, node, facts, func_stack, class_name) -> bool:
        return self._def(node, facts, func_stack, class_name, qualify=False)

    def _on_method_declaration(self, node, facts, func_stack, class_name) -> bool:
        return self._def(node, facts, func_stack, class_name, qualify=True)

    def _def(self, node, facts, func_stack, class_name, qualify) -> bool:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return False
        name = _text(name_node)
        qualified = f"{class_name}.{name}" if qualify and class_name else name
        facts.defs.append(FunctionDef(qualified, node.start_point[0] + 1, node.end_point[0] + 1))
        func_stack.append(qualified)
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                self._walk(child, facts, func_stack, class_name)
        func_stack.pop()
        return True

    def _on_class_declaration(self, node, facts, func_stack, class_name) -> bool:
        name_node = node.child_by_field_name("name")
        cname = _text(name_node) if name_node else class_name
        for child in node.children:
            if child.type == "declaration_list":
                for member in child.children:
                    self._walk(member, facts, func_stack, cname)
        return True

    def _on_interface_declaration(self, node, facts, func_stack, class_name) -> bool:
        return self._on_class_declaration(node, facts, func_stack, class_name)

    def _on_trait_declaration(self, node, facts, func_stack, class_name) -> bool:
        return self._on_class_declaration(node, facts, func_stack, class_name)

    def _on_function_call_expression(self, node, facts, func_stack, class_name) -> bool:
        fn = node.child_by_field_name("function")
        caller = func_stack[-1] if func_stack else None
        if fn is not None and fn.type in ("name", "qualified_name"):
            facts.calls.append(CallSite(caller, _text(fn).lstrip("\\").rsplit("\\", 1)[-1], node.start_point[0] + 1))
        self._walk_args(node, facts, func_stack, class_name)
        return True

    def _on_member_call_expression(self, node, facts, func_stack, class_name) -> bool:
        name_node = node.child_by_field_name("name")
        obj_node = node.child_by_field_name("object")
        if name_node is not None:
            caller = func_stack[-1] if func_stack else None
            obj = _text(obj_node).lstrip("$") if obj_node else None
            facts.calls.append(CallSite(caller, _text(name_node), node.start_point[0] + 1, object=obj))
        self._walk_args(node, facts, func_stack, class_name)
        return True

    def _on_scoped_call_expression(self, node, facts, func_stack, class_name) -> bool:
        scope = _text(node.child_by_field_name("scope"))
        name_node = node.child_by_field_name("name")
        method = _text(name_node) if name_node else ""
        line = node.start_point[0] + 1
        if scope == _ROUTE_FACADE and method.lower() in _ROUTE_VERBS:
            self._laravel_route(method, node, facts, line)
        else:
            caller = func_stack[-1] if func_stack else None
            facts.calls.append(CallSite(caller, method, line, object=scope or None))
        self._walk_args(node, facts, func_stack, class_name)
        return True

    def _laravel_route(self, verb: str, node, facts, line) -> None:
        args = _arg_exprs(node.child_by_field_name("arguments"))
        if len(args) < 2:
            return
        path = _string_value(args[0])
        if path is None:
            return
        method = "*" if verb.lower() == "any" else verb.upper()
        handler, handler_object = self._handler(args[1])
        facts.routes.append(RouteDef(method, path, handler, line, handler_object=handler_object))

    @staticmethod
    def _handler(node):
        """Resolve a Laravel handler arg to (handler, handler_object)."""
        # "Controller@method" string  → qualified "Controller.method"
        s = _string_value(node)
        if s and "@" in s:
            cls, _, m = s.partition("@")
            return f"{cls}.{m}", None
        # [Controller::class, "method"] array → qualified "Controller.method"
        if node is not None and node.type == "array_creation_expression":
            cls = m = None
            elems = [e for e in node.named_children if e.type == "array_element_initializer"]
            if len(elems) >= 2:
                first = elems[0].named_children[0] if elems[0].named_children else None
                if first is not None and first.type == "class_constant_access_expression":
                    # `Controller::class` → class name is the first named child
                    cls = _text(first.named_children[0]) if first.named_children else None
                m = _string_value(elems[1].named_children[0] if elems[1].named_children else None)
            if cls and m:
                return f"{cls}.{m}", None
        # closure / unknown → route node only, no edge
        return None, None

    def _on_subscript_expression(self, node, facts, func_stack, class_name) -> bool:
        var = node.named_children[0] if node.named_children else None
        if var is not None and var.type == "variable_name" and _text(var).lstrip("$") in _SUPERGLOBALS:
            handler = func_stack[-1] if func_stack else None
            # Unique path per entrypoint so two functions in one file don't collapse
            # into a single route node (route_id = method + path).
            path = "/" + facts.file + "#" + (handler or str(node.start_point[0] + 1))
            if not any(r.path == path for r in facts.routes):
                facts.routes.append(RouteDef("*", path, handler, node.start_point[0] + 1))
        return False  # keep walking (args/keys may contain calls)

    def _on_namespace_use_declaration(self, node, facts, func_stack, class_name) -> bool:
        for clause in node.named_children:
            if clause.type != "namespace_use_clause":
                continue
            qn = next((c for c in clause.named_children if c.type in ("qualified_name", "name")), None)
            alias = clause.child_by_field_name("alias")
            if qn is None:
                continue
            source = _text(qn).lstrip("\\")
            local = _text(alias) if alias else source.rsplit("\\", 1)[-1]
            facts.imports.append(ImportBinding(local, source, local))
        return True

    # -- helpers ------------------------------------------------------------

    def _walk_args(self, node, facts, func_stack, class_name) -> None:
        args = node.child_by_field_name("arguments")
        if args:
            for child in args.children:
                self._walk(child, facts, func_stack, class_name)


if _AVAILABLE:
    register(PHPExtractor())
