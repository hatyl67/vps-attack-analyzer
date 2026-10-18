"""Общие типы данных: их используют парсер, генератор, а позже БД и API."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class EventType(str, Enum):
    """Тип события аутентификации SSH."""

    # Наследование от str: значение пишется в DataFrame, БД и JSON обычной строкой.
    FAILED_LOGIN = "failed_login"
    INVALID_USER = "invalid_user"
    ACCEPTED = "accepted"
    # Соединение без нормального SSH-рукопожатия: так ведут себя сканеры портов.
    SCANNER = "scanner"


@dataclass(frozen=True)
class AuthEvent:
    """Одно распознанное событие из лога."""

    timestamp: datetime  # всегда timezone-aware, в UTC
    event_type: EventType
    ip: str
    host: str
    username: Optional[str] = None
    port: Optional[int] = None
    auth_method: Optional[str] = None
    invalid_user: bool = False
    source: str = "ssh"
