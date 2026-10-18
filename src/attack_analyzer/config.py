"""Настройки из config.toml: адрес базы и пороги детектора."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, fields
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional, Union

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

CONFIG_ENV = "ATTACK_ANALYZER_CONFIG"
DATABASE_URL_ENV = "ATTACK_ANALYZER_DB"
DEFAULT_CONFIG_PATH = Path("config.toml")


class ConfigError(ValueError):
    """Ошибка в файле настроек."""


def _require_positive(section: str, **values: int) -> None:
    for name, value in values.items():
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ConfigError(f"[{section}] {name} должно быть целым числом больше 0, получено {value!r}")


@dataclass(frozen=True)
class BruteforceConfig:
    threshold: int = 10
    window_minutes: int = 10

    def __post_init__(self) -> None:
        _require_positive("detector.bruteforce", threshold=self.threshold, window_minutes=self.window_minutes)

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.window_minutes)


@dataclass(frozen=True)
class EnumerationConfig:
    distinct_usernames: int = 5
    window_minutes: int = 60

    def __post_init__(self) -> None:
        _require_positive(
            "detector.enumeration",
            distinct_usernames=self.distinct_usernames,
            window_minutes=self.window_minutes,
        )

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.window_minutes)


@dataclass(frozen=True)
class RepeatedConfig:
    min_active_days: int = 3

    def __post_init__(self) -> None:
        _require_positive("detector.repeated", min_active_days=self.min_active_days)


@dataclass(frozen=True)
class SuccessAfterAttackConfig:
    min_failed_before: int = 5
    lookback_hours: int = 24

    def __post_init__(self) -> None:
        _require_positive(
            "detector.success_after_attack",
            min_failed_before=self.min_failed_before,
            lookback_hours=self.lookback_hours,
        )

    @property
    def lookback(self) -> timedelta:
        return timedelta(hours=self.lookback_hours)


@dataclass(frozen=True)
class DetectorConfig:
    bruteforce: BruteforceConfig = field(default_factory=BruteforceConfig)
    enumeration: EnumerationConfig = field(default_factory=EnumerationConfig)
    repeated: RepeatedConfig = field(default_factory=RepeatedConfig)
    success_after_attack: SuccessAfterAttackConfig = field(default_factory=SuccessAfterAttackConfig)


@dataclass(frozen=True)
class Settings:
    database_url: Optional[str] = None
    detector: DetectorConfig = field(default_factory=DetectorConfig)


def _section(cls: type, table: Any, name: str) -> Any:
    if not isinstance(table, dict):
        raise ConfigError(f"[{name}] должно быть таблицей TOML")
    # Неизвестный ключ почти всегда опечатка ("treshold"), а молча
    # проигнорированный порог потом очень трудно найти.
    unknown = set(table) - {item.name for item in fields(cls)}
    if unknown:
        raise ConfigError(f"[{name}] неизвестные параметры: {', '.join(sorted(unknown))}")
    return cls(**table)


def settings_from_dict(data: dict[str, Any]) -> Settings:
    """Принимает разобранный TOML, возвращает проверенные Settings."""
    unknown = set(data) - {"database", "detector"}
    if unknown:
        raise ConfigError(f"неизвестные разделы: {', '.join(sorted(unknown))}")

    database = data.get("database", {})
    detector_table = data.get("detector", {})
    sections = {
        "bruteforce": BruteforceConfig,
        "enumeration": EnumerationConfig,
        "repeated": RepeatedConfig,
        "success_after_attack": SuccessAfterAttackConfig,
    }
    unknown = set(detector_table) - set(sections)
    if unknown:
        raise ConfigError(f"[detector] неизвестные разделы: {', '.join(sorted(unknown))}")
    detector = DetectorConfig(
        **{
            name: _section(cls, detector_table[name], f"detector.{name}")
            for name, cls in sections.items()
            if name in detector_table
        }
    )
    return Settings(database_url=database.get("url"), detector=detector)


def load_settings(path: Union[str, Path, None] = None) -> Settings:
    """Принимает путь к TOML (None — ATTACK_ANALYZER_CONFIG или ./config.toml), возвращает Settings.

    Если файла нет, используются значения по умолчанию. Переменная
    ATTACK_ANALYZER_DB переопределяет адрес базы из файла.
    """
    explicit = path is not None or CONFIG_ENV in os.environ
    config_path = Path(path or os.environ.get(CONFIG_ENV, DEFAULT_CONFIG_PATH))
    if config_path.exists():
        with config_path.open("rb") as handle:
            try:
                settings = settings_from_dict(tomllib.load(handle))
            except tomllib.TOMLDecodeError as error:
                raise ConfigError(f"{config_path}: {error}") from error
    elif explicit:
        raise ConfigError(f"файл настроек не найден: {config_path}")
    else:
        settings = Settings()

    if DATABASE_URL_ENV in os.environ:
        settings = Settings(database_url=os.environ[DATABASE_URL_ENV], detector=settings.detector)
    return settings
