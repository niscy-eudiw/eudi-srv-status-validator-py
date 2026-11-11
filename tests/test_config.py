"""Configuration loading (app/config.py)."""

from __future__ import annotations

import pytest

from app import config


def test_load_from_config_path(configuration):
    assert config.load_config() == configuration


def test_load_is_cached(tmp_path, monkeypatch, configuration):
    first = config.load_config()
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "other.yaml"))
    assert config.load_config() is first


def test_explicit_path(tmp_path):
    path = tmp_path / "explicit.yaml"
    path.write_text("server:\n  port: 1\n")
    assert config.load_config(str(path)) == {"server": {"port": 1}}


def test_default_path_is_the_repository_config(monkeypatch):
    monkeypatch.delenv("CONFIG_PATH")
    config.load_config.cache_clear()
    assert "trust_validator" in config.load_config()


def test_missing_file(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "missing.yaml"))
    config.load_config.cache_clear()
    with pytest.raises(FileNotFoundError):
        config.load_config()


def test_empty_file(write_config):
    write_config(None)
    assert config.load_config() == {}


def test_top_level_must_be_a_mapping(tmp_path, monkeypatch):
    path = tmp_path / "list.yaml"
    path.write_text("- a\n- b\n")
    with pytest.raises(ValueError):
        config.load_config(str(path))


def test_invalid_yaml(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("server: [unclosed\n")
    with pytest.raises(Exception):
        config.load_config(str(path))


def test_get_value():
    assert config.get("trust_validator", "timeout") == 5


@pytest.mark.parametrize(
    ("section", "key"),
    [("missing", "x"), ("trust_validator", "missing")],
)
def test_get_default(section, key):
    assert config.get(section, key, "default") == "default"


def test_get_section_not_a_mapping(write_config):
    write_config({"cache": 5})
    assert config.get("cache", "max_size", 7) == 7


def test_get_when_loading_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "missing.yaml"))
    config.load_config.cache_clear()
    assert config.get("cache", "max_size", 7) == 7
