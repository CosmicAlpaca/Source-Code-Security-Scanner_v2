"""radar.config.yml loader tests."""

import pytest

from radar.config import RadarConfig, load_config


def write_config(tmp_path, content: str):
    (tmp_path / "radar.config.yml").write_text(content, encoding="utf-8")
    return tmp_path


def test_missing_file_returns_none(tmp_path):
    assert load_config(tmp_path) is None


def test_load_features_and_exclude(tmp_path):
    config = load_config(write_config(tmp_path, (
        "features:\n"
        "  Authentication: [\"src/auth/**\", \"src/middleware/session*\"]\n"
        "  Payment: \"src/billing/**\"\n"
        "exclude: [\"**/migrations/**\"]\n"
    )))
    assert config.feature_for("src/auth/validate.js") == "Authentication"
    assert config.feature_for("src/middleware/session-store.js") == "Authentication"
    assert config.feature_for("src/billing/invoice.py") == "Payment"
    assert config.feature_for("src/other/x.js") is None
    assert config.is_excluded("app/migrations/0001_init.py")
    assert not config.is_excluded("app/models.py")


def test_empty_file(tmp_path):
    config = load_config(write_config(tmp_path, ""))
    assert config == RadarConfig()
    assert config.feature_for("anything.py") is None


def test_invalid_features_type_raises(tmp_path):
    with pytest.raises(ValueError, match="features"):
        load_config(write_config(tmp_path, "features: [a, b]\n"))


def test_invalid_exclude_type_raises(tmp_path):
    with pytest.raises(ValueError, match="exclude"):
        load_config(write_config(tmp_path, "exclude: {a: b}\n"))


def test_first_matching_feature_wins(tmp_path):
    config = load_config(write_config(tmp_path, (
        "features:\n  A: [\"src/**\"]\n  B: [\"src/x*\"]\n"
    )))
    assert config.feature_for("src/x.js") == "A"
