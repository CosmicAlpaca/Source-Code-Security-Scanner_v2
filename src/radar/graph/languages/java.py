"""Java extractor: method defs, call sites, imports, Spring/JAX-RS route annotations.

Detects Spring MVC (@GetMapping, @PostMapping, @RequestMapping) and
JAX-RS (@GET/@POST + @Path) route annotations.
Plugin self-registers — zero core changes required (see base.py).
"""

try:
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Parser
    _LANGUAGE = Language(tsjava.language())
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

from radar.graph.languages.base import LanguageExtractor, register
from radar.graph.model import CallSite, FileFacts, FunctionDef, ImportBinding, RouteDef

# Spring MVC mapping annotations → HTTP method
_SPRING_MAPPINGS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}
# JAX-RS HTTP method annotations
_JAXRS_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node else ""


def _string_value(node) -> str | None:
    """Extract string content from string_literal (strips quotes)."""
    if node is None:
        return None
    if node.type == "string_literal":
        raw = _text(node)
        return raw[1:-1] if len(raw) >= 2 else raw
    return None


class JavaExtractor(LanguageExtractor):
    name = "java"
    extensions = (".java",)

    def extract(self, source: bytes, relpath: str) -> FileFacts:
        if not _AVAILABLE:
            return FileFacts(file=relpath, language=self.name)
        tree = Parser(_LANGUAGE).parse(source)
        facts = FileFacts(file=relpath, language=self.name)
        self._walk(tree.root_node, facts, func_stack=[], class_name=None)
        return facts

    def resolve_module(self, source: str, importer: str, files: set[str]) -> str | None:
        """Java uses FQN imports — convert to file path for local classes."""
        path = source.replace(".", "/") + ".java"
        return path if path in files else None

    # -- traversal ----------------------------------------------------------

    def _walk(self, node, facts, func_stack, class_name) -> None:
        handler = getattr(self, f"_on_{node.type}", None)
        if handler and handler(node, facts, func_stack, class_name):
            return
        for child in node.children:
            self._walk(child, facts, func_stack, class_name)

    def _on_class_declaration(self, node, facts, func_stack, class_name) -> bool:
        name_node = node.child_by_field_name("name")
        cname = _text(name_node) if name_node else class_name
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                self._walk(child, facts, func_stack, cname)
        return True

    def _on_interface_declaration(self, node, facts, func_stack, class_name) -> bool:
        return self._on_class_declaration(node, facts, func_stack, class_name)

    def _on_enum_declaration(self, node, facts, func_stack, class_name) -> bool:
        return self._on_class_declaration(node, facts, func_stack, class_name)

    def _on_method_declaration(self, node, facts, func_stack, class_name) -> bool:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return False
        method_name = _text(name_node)
        qualified = f"{class_name}.{method_name}" if class_name else method_name

        # Collect annotations on this method (they're siblings in parent's body)
        annotations = self._collect_annotations(node)
        path, http_method = self._resolve_route(annotations)
        if path is not None and http_method is not None:
            facts.routes.append(RouteDef(http_method, path, qualified, node.start_point[0] + 1))

        facts.defs.append(FunctionDef(qualified, node.start_point[0] + 1, node.end_point[0] + 1))
        func_stack.append(qualified)
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                self._walk(child, facts, func_stack, class_name)
        func_stack.pop()
        return True

    def _on_constructor_declaration(self, node, facts, func_stack, class_name) -> bool:
        return self._on_method_declaration(node, facts, func_stack, class_name)

    def _collect_annotations(self, method_node) -> list:
        """Collect annotation nodes that are preceding siblings of the method in its parent."""
        parent = method_node.parent
        if parent is None:
            return []
        annotations = []
        for child in parent.children:
            if child == method_node:
                break
            if child.type in ("annotation", "marker_annotation"):
                annotations.append(child)
            elif child.type not in ("annotation", "marker_annotation", "modifiers"):
                # Reset on non-annotation nodes (other methods, fields)
                annotations = []
        return annotations

    def _resolve_route(self, annotations: list) -> tuple[str | None, str | None]:
        """Return (path, http_method) from Spring or JAX-RS annotations, or (None, None)."""
        path: str | None = None
        http_method: str | None = None

        for ann in annotations:
            name_node = ann.child_by_field_name("name")
            if name_node is None:
                continue
            ann_name = _text(name_node)

            # Spring: @GetMapping("/path"), @RequestMapping(value="/path", method=...)
            if ann_name in _SPRING_MAPPINGS:
                http_method = _SPRING_MAPPINGS[ann_name]
                path = self._annotation_string_value(ann) or path
            elif ann_name == "RequestMapping":
                http_method = self._spring_request_method(ann) or "GET"
                path = self._annotation_string_value(ann) or path

            # JAX-RS: @GET, @POST, etc.
            elif ann_name.upper() in _JAXRS_METHODS:
                http_method = ann_name.upper()

            # JAX-RS: @Path("/path")
            elif ann_name == "Path":
                path = self._annotation_string_value(ann) or path

        return path, http_method

    @staticmethod
    def _annotation_string_value(ann_node) -> str | None:
        """Extract the first string value from annotation arguments."""
        args = ann_node.child_by_field_name("arguments")
        if args is None:
            return None
        for child in args.named_children:
            # @Mapping("/path") — positional string
            if child.type == "string_literal":
                raw = _text(child)
                return raw[1:-1] if len(raw) >= 2 else raw
            # @Mapping(value = "/path") or @Mapping(value = {"/path"})
            if child.type == "element_value_pair":
                key = child.child_by_field_name("key")
                value = child.child_by_field_name("value")
                if key is not None and _text(key) in ("value", "path") and value is not None:
                    if value.type == "string_literal":
                        raw = _text(value)
                        return raw[1:-1] if len(raw) >= 2 else raw
                    # array initializer {"/path"}
                    if value.type == "array_initializer":
                        for elem in value.named_children:
                            if elem.type == "string_literal":
                                raw = _text(elem)
                                return raw[1:-1] if len(raw) >= 2 else raw
        return None

    @staticmethod
    def _spring_request_method(ann_node) -> str | None:
        """Extract HTTP method from @RequestMapping(method = RequestMethod.GET)."""
        args = ann_node.child_by_field_name("arguments")
        if args is None:
            return None
        for child in args.named_children:
            if child.type == "element_value_pair":
                key = child.child_by_field_name("key")
                value = child.child_by_field_name("value")
                if key is not None and _text(key) == "method" and value is not None:
                    # RequestMethod.GET → "GET"
                    text_val = _text(value)
                    for m in _JAXRS_METHODS:
                        if m in text_val.upper():
                            return m
        return None

    def _on_method_invocation(self, node, facts, func_stack, class_name) -> bool:
        name_node = node.child_by_field_name("name")
        obj_node = node.child_by_field_name("object")
        args_node = node.child_by_field_name("arguments")
        if name_node is None:
            return False
        caller = func_stack[-1] if func_stack else None
        line = node.start_point[0] + 1
        obj_name = _text(obj_node) if obj_node and obj_node.type == "identifier" else None
        facts.calls.append(CallSite(caller, _text(name_node), line, object=obj_name))
        if args_node:
            for child in args_node.children:
                self._walk(child, facts, func_stack, class_name)
        return True

    def _on_import_declaration(self, node, facts, func_stack, class_name) -> bool:
        # import com.example.Foo; → local="Foo", source="com.example.Foo"
        for child in node.named_children:
            if child.type == "scoped_identifier":
                source = _text(child)
                local = source.rsplit(".", 1)[-1]
                facts.imports.append(ImportBinding(local, source, local))
        return True


if _AVAILABLE:
    register(JavaExtractor())
