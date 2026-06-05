"""Language plugin interface + registry.

Adding a language = drop one module in this package that defines a
LanguageExtractor subclass and calls register() at import time. The package
__init__ auto-imports every module here, so the core never references a
specific language.
"""

from abc import ABC, abstractmethod

from radar.graph.model import FileFacts


class LanguageExtractor(ABC):
    """Extracts function defs, call sites, imports and routes from one file."""

    #: language name stored on nodes, e.g. "javascript"
    name: str = ""
    #: file extensions handled, e.g. (".js", ".jsx")
    extensions: tuple[str, ...] = ()

    @abstractmethod
    def extract(self, source: bytes, relpath: str) -> FileFacts:
        """Parse source (never executed) and return raw facts."""


#: extension -> extractor instance
EXTRACTORS: dict[str, LanguageExtractor] = {}


def register(extractor: LanguageExtractor) -> None:
    for ext in extractor.extensions:
        EXTRACTORS[ext] = extractor


def extractor_for(relpath: str) -> LanguageExtractor | None:
    dot = relpath.rfind(".")
    if dot == -1:
        return None
    return EXTRACTORS.get(relpath[dot:].lower())
