"""Prompt construction + secret redaction (all offline, no network)."""

from radar.scan.findings import Finding
from radar.triage.prompt import build_messages, redact
from radar.triage.reachability import Reach


def test_redact_masks_planted_secrets():
    snippet = (
        "const k = 'AKIAIOSFODNN7EXAMPLE';\n"
        "const key = 'sk-abcdEFGH1234567890ABCDEF';\n"
        "password = 'hunter2secret'\n"
    )
    out = redact(snippet)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "sk-abcdEFGH1234567890ABCDEF" not in out
    assert "hunter2secret" not in out
    assert "«redacted»" in out


def test_build_messages_carries_reachability_and_routes():
    finding = Finding("ERROR", "session.js", 5, "js.xss", "reflected xss")
    reach = Reach("session.js::handleLogin", ["POST /login"], "reachable")
    messages = build_messages(finding, "res.send(user)", reach)
    assert messages[0]["role"] == "system"
    user = messages[1]["content"]
    assert "reachable" in user
    assert "POST /login" in user
    assert "js.xss" in user


def test_system_prompt_warns_unknown_is_not_safe():
    finding = Finding("WARNING", "a.js", 1, "r", "m")
    reach = Reach(None, [], "unknown")
    system = build_messages(finding, "x", reach)[0]["content"]
    assert "NOT proof" in system or "not proof" in system.lower()


def test_system_prompt_requests_exploit_path():
    msgs = build_messages(Finding("ERROR", "a.js", 1, "r", "m"), "x", Reach(None, [], "unknown"))
    assert "exploit_path" in msgs[0]["content"]


def test_prompt_includes_owasp_from_metadata():
    finding = Finding("ERROR", "a.py", 3, "python.lang.security.dangerous", "m",
                      metadata={"owasp": "A03:2021 - Injection", "cwe": "CWE-78"})
    user = build_messages(finding, "x", Reach(None, [], "unknown"))[1]["content"]
    assert "A03:2021 - Injection" in user and "CWE-78" in user


def test_prompt_owasp_falls_back_to_rule_keyword():
    finding = Finding("ERROR", "x.js", 1, "js-sql-string-concat", "m")  # no metadata
    user = build_messages(finding, "x", Reach(None, [], "unknown"))[1]["content"]
    assert "A03" in user  # keyword classifier kicked in


def test_normalize_adds_exploit_path_default():
    from radar.triage.llm_client import _normalize
    v = _normalize({"exploitability": "likely", "confidence": 0.5, "reasoning": "r"})
    assert v["exploit_path"] == ""  # missing -> safe default, no KeyError downstream
