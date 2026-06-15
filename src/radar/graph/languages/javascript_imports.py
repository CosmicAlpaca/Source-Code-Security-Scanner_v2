"""JS/TS import-binding extraction helpers (shared by the javascript plugin).

Not a language plugin itself — defines no extractor, registers nothing.
"""

from radar.graph.model import FileFacts, ImportBinding


def text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def string_value(node) -> str | None:
    """Literal value of a string node ('...' or \"...\"), None for dynamic."""
    if node is None or node.type != "string":
        return None
    return "".join(text(c) for c in node.children if c.type == "string_fragment")


def parse_import_statement(node, facts: FileFacts) -> None:
    """import def, { x, y as z }, * as ns from './a'"""
    src = string_value(node.child_by_field_name("source"))
    if not src:
        return
    for clause in (c for c in node.children if c.type == "import_clause"):
        for child in clause.children:
            if child.type == "identifier":
                facts.imports.append(ImportBinding(text(child), src, "default"))
            elif child.type == "namespace_import":
                ident = next((c for c in child.children if c.type == "identifier"), None)
                if ident is not None:
                    facts.imports.append(ImportBinding(text(ident), src, "*"))
            elif child.type == "named_imports":
                for spec in (s for s in child.named_children if s.type == "import_specifier"):
                    name_n = spec.child_by_field_name("name")
                    alias_n = spec.child_by_field_name("alias")
                    if name_n is not None:
                        imported = text(name_n)
                        local = text(alias_n) if alias_n is not None else imported
                        facts.imports.append(ImportBinding(local, src, imported))


def parse_require_bindings(name_node, src: str, facts: FileFacts) -> None:
    """const db = require('./db') | const {a, b: c} = require('...')"""
    if name_node.type == "identifier":
        facts.imports.append(ImportBinding(text(name_node), src, "default"))
    elif name_node.type == "object_pattern":
        for child in name_node.named_children:
            if child.type == "shorthand_property_identifier_pattern":
                facts.imports.append(ImportBinding(text(child), src, text(child)))
            elif child.type == "pair_pattern":
                key, value = child.child_by_field_name("key"), child.child_by_field_name("value")
                if key is not None and value is not None and value.type == "identifier":
                    facts.imports.append(ImportBinding(text(value), src, text(key)))
