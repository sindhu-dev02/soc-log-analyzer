import pytest

from socanalyzer.config import ConfigError, load_config


def test_valid_config_loads(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("brute_force:\n  threshold: 8\n  window_seconds: 30\n")

    cfg = load_config(f)

    assert cfg.threshold == 8
    assert cfg.window.total_seconds() == 30


def test_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yaml")


def test_bad_threshold_raises(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("brute_force:\n  threshold: -3\n")

    with pytest.raises(ConfigError):
        load_config(f)