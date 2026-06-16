"""OpenAI Chat Completions over stdlib urllib + a verdict cache. No SDK dependency.

Key/model/base_url resolve from the environment, falling back to a repo-root `.env`
(parsed with stdlib so we add no python-dotenv dependency). Verdicts are cached
outside the repo (keyed by model+finding+snippet+reachability) so re-runs are
stable and cost nothing.
"""

import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from radar.cache import verdict_cache_path
from radar.triage.prompt import build_messages

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_BASE_URL = "https://api.openai.com/v1"
_EXPLOITABILITY = {"exploitable", "likely", "unlikely", "false_positive"}
_VERDICT_KEYS = ("exploitability", "confidence", "reasoning", "exploit_path", "reachable")
_CACHE_VERSION = "v2"  # bump when prompt/verdict schema changes to invalidate stale entries


class TriageError(RuntimeError):
    """LLM call could not complete (no key, HTTP error, or bad response)."""


def load_dotenv(root: Path) -> None:
    """Populate os.environ from <root>/.env for keys not already set. Stdlib only."""
    path = root / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def resolve_key() -> str | None:
    return os.environ.get("OPENAI_API_KEY") or os.environ.get("RADAR_AI_API_KEY")


def resolve_model() -> str:
    return os.environ.get("RADAR_AI_MODEL") or DEFAULT_MODEL


def resolve_base_url() -> str:
    return (os.environ.get("OPENAI_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")


def cache_key(model: str, finding, snippet: str, status: str) -> str:
    blob = f"{_CACHE_VERSION}\0{model}\0{finding.rule}\0{finding.path}:{finding.line}\0{status}\0{snippet}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def _normalize(verdict: dict) -> dict:
    out = {k: verdict.get(k) for k in _VERDICT_KEYS}
    if out["exploitability"] not in _EXPLOITABILITY:
        out["exploitability"] = "unlikely"
    try:
        out["confidence"] = max(0.0, min(1.0, float(out["confidence"])))
    except (TypeError, ValueError):
        out["confidence"] = 0.0
    out["reasoning"] = str(out.get("reasoning") or "").strip()
    out["exploit_path"] = str(out.get("exploit_path") or "").strip()
    out["reachable"] = bool(out.get("reachable"))
    return out


def call(messages: list[dict], model: str, key: str, base_url: str, timeout: int = 60) -> dict:
    body = json.dumps(
        {
            "model": model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": messages,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500] if exc.fp else ""
        raise TriageError(f"OpenAI HTTP {exc.code}: {detail}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TriageError(f"OpenAI request failed: {exc}") from None
    try:
        content = payload["choices"][0]["message"]["content"]
        return _normalize(json.loads(content))
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise TriageError(f"Unparseable OpenAI response: {exc}") from None


def get_verdict(root: Path, finding, snippet: str, reach, *, model: str | None = None, force: bool = False):
    """Return (verdict, cached). A cache hit avoids any network call."""
    model = model or resolve_model()
    path = verdict_cache_path(root, cache_key(model, finding, snippet, reach.status))
    if not force and path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8")), True
        except (OSError, json.JSONDecodeError):
            pass  # corrupt cache entry — re-query
    key = resolve_key()
    if not key:
        raise TriageError(
            "No API key. Set OPENAI_API_KEY (or RADAR_AI_API_KEY) in your environment "
            "or a repo-root .env file, then re-run `radar triage`."
        )
    verdict = call(build_messages(finding, snippet, reach), model, key, resolve_base_url())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(verdict, indent=1, sort_keys=True), encoding="utf-8")
    return verdict, False
