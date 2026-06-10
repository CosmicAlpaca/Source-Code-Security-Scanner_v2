"""scan.runner tests — runtime discovery + argv building (no real Semgrep call)."""

import json
import subprocess

import pytest

from radar.scan import runner


def test_rules_dir_bundled():
    rd = runner.rules_dir()
    assert rd.is_dir()
    yamls = list(rd.glob("*.yaml"))
    assert len(yamls) >= 1, "rules directory should contain at least one rule"
    # every rule ships with a code fixture (.js/.py) next to it for `semgrep --test`
    for y in yamls:
        fixtures = [p for p in rd.glob(f"{y.stem}.*") if p.suffix != ".yaml"]
        assert fixtures, f"no fixture for {y.name}"


def test_detect_runtime_prefers_native(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/usr/bin/semgrep" if name == "semgrep" else None)
    assert runner.detect_runtime() == "native"


def test_detect_runtime_falls_back_to_docker(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/usr/bin/docker" if name == "docker" else None)
    assert runner.detect_runtime() == "docker"


def test_detect_runtime_raises_when_neither(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    with pytest.raises(runner.ScanError, match="No Semgrep runtime"):
        runner.detect_runtime()


def test_build_argv_native_has_presets_and_rules(tmp_path):
    argv = runner.build_argv(tmp_path, "native")
    assert argv[:3] == ["semgrep", "scan", "--json"]
    assert "p/security-audit" in argv and "p/owasp-top-ten" in argv
    assert str(runner.rules_dir()) in argv
    assert argv[-1] == str(tmp_path)


def test_build_argv_native_rules_only_drops_presets(tmp_path):
    argv = runner.build_argv(tmp_path, "native", rules_only=True)
    assert "p/security-audit" not in argv
    assert str(runner.rules_dir()) in argv


def test_build_argv_sarif_flag(tmp_path):
    argv = runner.build_argv(tmp_path, "native", sarif=True)
    assert "--sarif" in argv and "--json" not in argv


def test_build_argv_docker_mounts_readonly(tmp_path):
    argv = runner.build_argv(tmp_path, "docker")
    assert argv[:3] == ["docker", "run", "--rm"]
    assert f"{tmp_path.as_posix()}:/src:ro" in argv
    assert f"{runner.rules_dir().as_posix()}:/rules:ro" in argv
    assert ["-w", "/src"] == argv[argv.index("-w"):argv.index("-w") + 2]
    assert "/rules" in argv  # rules referenced by container path
    assert argv[-1] == "."   # scan cwd (=/src) so paths come out repo-relative
    assert runner.DOCKER_IMAGE in argv


def test_build_argv_extra_config_appended(tmp_path):
    argv = runner.build_argv(tmp_path, "native", extra_config=["p/django"])
    assert "p/django" in argv


def test_run_semgrep_parses_json(tmp_path, monkeypatch):
    payload = {"results": [], "errors": []}

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert runner.run_semgrep(tmp_path, runtime="native") == payload


def test_run_semgrep_raises_on_unparseable_output(tmp_path, monkeypatch):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 2, stdout="", stderr="config error: bad rule")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    with pytest.raises(runner.ScanError, match="bad rule"):
        runner.run_semgrep(tmp_path, runtime="native")
