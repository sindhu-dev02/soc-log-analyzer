from dataclasses import dataclass
from datetime import timedelta

import yaml


class ConfigError(Exception):
    """Raised when the config file is missing or has bad values."""


@dataclass(frozen=True)
class Config:
    log_file: str = "sample_logs/auth.log"
    year: int = 2026
    threshold: int = 5
    window: timedelta = timedelta(seconds=60)
    allowlist_ips: frozenset = frozenset()
    spray_threshold: int = 5
    spray_window: timedelta = timedelta(seconds=300)
    dist_threshold: int = 5
    dist_window: timedelta = timedelta(seconds=300)


def _positive_int(value, name):
    # bool is a subclass of int in Python, so exclude it explicitly
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"'{name}' must be a positive whole number, got {value!r}")
    return value


def load_config(path="config.yaml"):
    """Read the YAML file and return a validated Config."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}")
    except yaml.YAMLError as e:
        raise ConfigError(f"config file is not valid YAML: {e}")

    if not isinstance(data, dict):
        raise ConfigError("config file must contain key: value settings")

    defaults = Config()
    brute = data.get("brute_force") or {}

    spray = data.get("user_spraying") or {}

    dist = data.get("distributed_attack") or {}

    allowlist = data.get("allowlist_ips") or []
    if not isinstance(allowlist, list):
        raise ConfigError("'allowlist_ips' must be a list")

    return Config(
        log_file=str(data.get("log_file", defaults.log_file)),
        year=_positive_int(data.get("year", defaults.year), "year"),
        threshold=_positive_int(
            brute.get("threshold", defaults.threshold), "brute_force.threshold"
        ),
        window=timedelta(seconds=_positive_int(
            brute.get("window_seconds", 60), "brute_force.window_seconds"
        )),
        allowlist_ips=frozenset(str(ip) for ip in allowlist),

        spray_threshold=_positive_int(
            spray.get("threshold", defaults.spray_threshold), "user_spraying.threshold"
        ),
        spray_window=timedelta(seconds=_positive_int(
            spray.get("window_seconds", 300), "user_spraying.window_seconds"
        )),
                dist_threshold=_positive_int(
            dist.get("threshold", defaults.dist_threshold), "distributed_attack.threshold"
        ),
        dist_window=timedelta(seconds=_positive_int(
            dist.get("window_seconds", 300), "distributed_attack.window_seconds"
        )),
    )