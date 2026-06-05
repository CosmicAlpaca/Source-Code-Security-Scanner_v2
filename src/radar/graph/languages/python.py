"""Python extractor: defs, calls, imports, Flask/FastAPI route decorators.

Proves the plugin architecture: this file registers itself via the package
auto-discovery — zero core changes. Pure parsing, scanned code never runs.
"""

import posixpath

import tree_sitter_python as tspy
from tree_sitter import Language, Parser

from radar.graph.languages.base import LanguageExtractor, register
from radar.graph.model import CallSite, FileFacts, FunctionDef, ImportBinding, RouteDef

_LANGUAGE = Language(tspy.language())
_ROUTE_METHODS = {"get", "post", "put", "delete", "patch"}
_DEFAULT_FLASK_METHODS = ["GET"]


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _string_value(node) -> str | None:
    if node is None or node.type != "string":
        return None
    return "".join(_text(c) for c in node.children if c.type == "string_content")


class PythonExtractor(LanguageExtractor):
    name = "python"
    extensions = (".py",)

    def extract(self, source: bytes, relpath: str) -> FileFacts:
        tree = Parser(_LANGUAGE).parse(source)
        facts = FileFacts(file=relpath, language=self.name)
        self._walk(tree.root_node, facts, func_stack=[], class_name=None)
        return facts

    def resolve_module(self, source: str, importer: str, files: set[str]) -> str | None:
        """'.utils' / '..services.db' relative, or 'app.services.db' root-relative."""
        if source.startswith("."):
            dots = len(source) - len(source.lstrip("."))
            base = posixpath.dirname(importer)
            for _ in range(dots - 1):
                base = posixpath.dirname(base)
            rest = source.lstrip(".").replace(".", "/")
            path = posixpath.normpath(posixpath.join(base, rest)) if rest else base
        else:
            path = source.replace(".", "/")
        for candidate in (f"{path}.py", posixpath.join(path, "__init__.py")):
            if candidate in files:
                return candidate
        return None

    # -- traversal ----------------------------------------------------------

    def _walk(self, node, facts, func_stack, class_name) -> None:
        handler = getattr(self, f"_on_{node.type}", None)
        if handler and handler(node, facts, func_stack, class_name):
            return
        for child in node.children:
            if child.type == "class_definition":
                name_node = child.child_by_field_name("name")
                self._walk(child, facts, func_stack, _text(name_node) if name_node else class_name)
            else:
                self._walk(child, facts, func_stack, class_name)

    def _on_decorated_definition(self, node, facts, func_stack, class_name) -> bool:
        definition = node.child_by_field_name("definition")
        if definition is None or definition.type != "function_definition":
            return False  # decorated class — recurse normally
        name_node = definition.child_by_field_name("name")
        func_name = _text(name_node) if name_node else "<anonymous>"
        qualified = f"{class_name}.{func_name}" if class_name else func_name
        for child in node.children:
            if child.type == "decorator":
                self._maybe_route(child, qualified, facts)
        return self._handle_function(definition, qualified, facts, func_stack, class_name)

    def _on_function_definition(self, node, facts, func_stack, class_name) -> bool:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return False
        name = _text(name_node)
        qualified = f"{class_name}.{name}" if class_name else name
        return self._handle_function(node, qualified, facts, func_stack, class_name)

    def _handle_function(self, node, qualified, facts, func_stack, class_name) -> bool:
        facts.defs.append(
            FunctionDef(qualified, node.start_point[0] + 1, node.end_point[0] + 1)
        )
        func_stack.append(qualified)
        for child in node.children:
            self._walk(child, facts, func_stack, class_name)
        func_stack.pop()
        return True

    def _on_call(self, node, facts, func_stack, class_name) -> bool:
        fn = node.child_by_field_name("function")
        if fn is None:
            return False
        caller = func_stack[-1] if func_stack else None
        line = node.start_point[0] + 1
        if fn.type == "identifier":
            facts.calls.append(CallSite(caller, _text(fn), line))
        elif fn.type == "attribute":
            attr = fn.child_by_field_name("attribute")
            obj = fn.child_by_field_name("object")
            if attr is not None:
                obj_name = _text(obj) if obj is not None and obj.type == "identifier" else None
                facts.calls.append(CallSite(caller, _text(attr), line, object=obj_name))
        args = node.child_by_field_name("arguments")
        if args is not None:
            for child in args.children:
                self._walk(child, facts, func_stack, class_name)
        return True

    def _on_import_statement(self, node, facts, func_stack, class_name) -> bool:
        for child in node.named_children:
            if child.type == "dotted_name":  # import a.b -> binds first segment, keep full source
                facts.imports.append(ImportBinding(_text(child).split(".")[0], _text(child), "*"))
            elif child.type == "aliased_import":
                name = child.child_by_field_name("name")
                alias = child.child_by_field_name("alias")
                if name is not None and alias is not None:
                    facts.imports.append(ImportBinding(_text(alias), _text(name), "*"))
        return True

    def _on_import_from_statement(self, node, facts, func_stack, class_name) -> bool:
        module = node.child_by_field_name("module_name")
        if module is None:
            return True
        source = _text(module)
        for child in node.named_children:
            if child == module:
                continue
            if child.type == "dotted_name":
                imported = _text(child)
                facts.imports.append(ImportBinding(imported, source, imported))
            elif child.type == "aliased_import":
                name = child.child_by_field_name("name")
                alias = child.child_by_field_name("alias")
                if name is not None and alias is not None:
                    facts.imports.append(ImportBinding(_text(alias), source, _text(name)))
        return True

    def _maybe_route(self, decorator, handler_name, facts) -> None:
        call = next((c for c in decorator.children if c.type == "call"), None)
        if call is None:
            return
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "attribute":
            return
        attr_node = fn.child_by_field_name("attribute")
        if attr_node is None:
            return
        attr = _text(attr_node)
        args = call.child_by_field_name("arguments")
        arg_nodes = args.named_children if args is not None else []
        path = _string_value(arg_nodes[0]) if arg_nodes else None
        if path is None:
            return
        line = decorator.start_point[0] + 1
        if attr in _ROUTE_METHODS:  # FastAPI style: @router.get("/x")
            facts.routes.append(RouteDef(attr.upper(), path, handler_name, line))
        elif attr == "route":  # Flask style: @app.route("/x", methods=["POST"])
            for method in self._flask_methods(arg_nodes):
                facts.routes.append(RouteDef(method, path, handler_name, line))

    @staticmethod
    def _flask_methods(arg_nodes) -> list[str]:
        for arg in arg_nodes:
            if arg.type == "keyword_argument":
                key = arg.child_by_field_name("name")
                value = arg.child_by_field_name("value")
                if key is not None and _text(key) == "methods" and value is not None:
                    methods = [_string_value(c) for c in value.named_children if c.type == "string"]
                    return [m.upper() for m in methods if m] or _DEFAULT_FLASK_METHODS
        return _DEFAULT_FLASK_METHODS


register(PythonExtractor())
