"""Тесты загрузки config.toml."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from attack_analyzer.config import ConfigError, Settings, load_settings, settings_from_dict

PROJECT_CONFIG = Path(__file__).resolve().parents[1] / "config.toml"


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATTACK_ANALYZER_DB", raising=False)
    monkeypatch.delenv("ATTACK_ANALYZER_CONFIG", raising=False)


def test_project_config_matches_defaults() -> None:
    assert load_settings(PROJECT_CONFIG).detector == Settings().detector


def test_partial_config_keeps_other_defaults() -> None:
    settings = settings_from_dict({"detector": {"bruteforce": {"threshold": 3}}})
    assert settings.detector.bruteforce.threshold == 3
    assert settings.detector.bruteforce.window == timedelta(minutes=10)
    assert settings.detector.enumeration == Settings().detector.enumeration


@pytest.mark.parametrize(
    "data",
    [
        {"detector": {"bruteforce": {"treshold": 3}}},
        {"detector": {"bruteforse": {}}},
        {"detecter": {}},
        {"detector": {"bruteforce": {"threshold": 0}}},
        {"detector": {"bruteforce": {"threshold": "10"}}},
        {"detector": {"repeated": 3}},
    ],
)
def test_invalid_config_is_rejected(data: dict) -> None:
    with pytest.raises(ConfigError):
        settings_from_dict(data)


def test_missing_default_file_gives_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_settings() == Settings()


def test_missing_explicit_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "nope.toml")


def test_environment_overrides_database_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.toml"
    config.write_text('[database]\nurl = "sqlite:///from_file.db"\n', encoding="utf-8")
    assert load_settings(config).database_url == "sqlite:///from_file.db"
    monkeypatch.setenv("ATTACK_ANALYZER_DB", "sqlite:///from_env.db")
    assert load_settings(config).database_url == "sqlite:///from_env.db"


def test_broken_toml(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("[detector\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(config)
