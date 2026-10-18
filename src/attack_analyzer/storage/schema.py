"""ORM-модели таблиц events и attackers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Enum, Index, String, TypeDecorator
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from attack_analyzer.models import EventType, IncidentKind

# Самая длинная текстовая запись IP: IPv6 с IPv4-хвостом, 45 символов.
IP_LENGTH = 45


class UTCDateTime(TypeDecorator[datetime]):
    """DateTime, который хранит время в UTC и возвращает timezone-aware datetime."""

    # SQLite не умеет хранить часовой пояс: aware-время записалось бы строкой
    # без смещения и прочиталось naive. Поэтому на входе приводим к UTC,
    # а на выходе возвращаем пояс обратно.
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: Optional[datetime], dialect: Dialect) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("ожидается timezone-aware datetime")
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value: Optional[datetime], dialect: Dialect) -> Optional[datetime]:
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc)


def _string_enum(enum_class: type) -> Enum:
    # native_enum=False: в SQLite нет типа ENUM, хранится обычная строка.
    # values_callable: в базу пишется "failed_login", а не имя члена "FAILED_LOGIN".
    return Enum(
        enum_class,
        native_enum=False,
        length=30,
        values_callable=lambda members: [member.value for member in members],
    )


class Base(DeclarativeBase):
    pass


class Event(Base):
    """Одно событие из лога (строка таблицы events)."""

    __tablename__ = "events"
    # Детектор будет искать события одного IP во временном окне.
    __table_args__ = (Index("ix_events_ip_timestamp", "ip", "timestamp"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    # Хэш содержимого события: по нему повторный импорт того же лога не создаёт дублей.
    event_key: Mapped[str] = mapped_column(String(40), unique=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    event_type: Mapped[EventType] = mapped_column(_string_enum(EventType), index=True)
    ip: Mapped[str] = mapped_column(String(IP_LENGTH))
    username: Mapped[Optional[str]] = mapped_column(String(255))
    port: Mapped[Optional[int]]
    auth_method: Mapped[Optional[str]] = mapped_column(String(50))
    invalid_user: Mapped[bool] = mapped_column(default=False)
    host: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(20))


class Attacker(Base):
    """Сводка по IP, от которого были неудачные входы, неверные логины или сканирование."""

    __tablename__ = "attackers"

    ip: Mapped[str] = mapped_column(String(IP_LENGTH), primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    total_events: Mapped[int]
    failed_logins: Mapped[int]
    invalid_users: Mapped[int]
    scanner_hits: Mapped[int]
    successful_logins: Mapped[int]
    distinct_usernames: Mapped[int]


class IncidentRecord(Base):
    """Атака, найденная детектором (строка таблицы incidents)."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[IncidentKind] = mapped_column(_string_enum(IncidentKind), index=True)
    ip: Mapped[str] = mapped_column(String(IP_LENGTH), index=True)
    start: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    end: Mapped[datetime] = mapped_column(UTCDateTime)
    event_count: Mapped[int]
    distinct_usernames: Mapped[int]
    details: Mapped[str] = mapped_column(String(255))
