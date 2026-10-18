"""Запись событий в базу, пересчёт таблиц attackers и incidents, чтение."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional, Sequence

import pandas as pd
from sqlalchemy import Insert, Select, case, delete, func, insert, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

from attack_analyzer.models import AuthEvent, EventType, Incident, IncidentKind
from attack_analyzer.parsers import events_to_dataframe
from attack_analyzer.storage.schema import Attacker, Event, IncidentRecord

HOSTILE_EVENT_TYPES = (EventType.FAILED_LOGIN, EventType.INVALID_USER, EventType.SCANNER)


def _missing_to_none(value: Any) -> Any:
    return None if pd.isna(value) else value


def _event_rows(events: pd.DataFrame) -> list[dict[str, Any]]:
    rows = []
    occurrences: Counter[str] = Counter()
    for record in events.to_dict("records"):
        port = _missing_to_none(record["port"])
        row = {
            "timestamp": record["timestamp"].to_pydatetime(),
            "event_type": EventType(record["event_type"]),
            "ip": record["ip"],
            "username": _missing_to_none(record["username"]),
            # numpy.int64 из pandas sqlite3 записать не умеет, нужен обычный int.
            "port": int(port) if port is not None else None,
            "auth_method": _missing_to_none(record["auth_method"]),
            "invalid_user": bool(record["invalid_user"]),
            "host": record["host"],
            "source": record["source"],
        }
        identity = [
            row["source"],
            row["host"],
            row["timestamp"].isoformat(),
            row["event_type"].value,
            row["ip"],
            row["port"],
            row["username"],
        ]
        # json, а не "|".join: так None и пустой логин "" дают разные строки.
        content = json.dumps(identity, ensure_ascii=False)
        # Одинаковые события бывают на самом деле: "message repeated 3 times"
        # даёт три идентичные строки. Номер повтора внутри файла делает их ключи
        # разными, а при повторном импорте того же файла ключи совпадут.
        row["event_key"] = hashlib.sha1(f"{content}#{occurrences[content]}".encode()).hexdigest()
        occurrences[content] += 1
        rows.append(row)
    return rows


def _insert_ignoring_duplicates(session: Session) -> Insert:
    # INSERT ... ON CONFLICT DO NOTHING пишется по-разному в разных СУБД,
    # поэтому конструкцию берём из модуля конкретного диалекта.
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        return sqlite.insert(Event).on_conflict_do_nothing(index_elements=["event_key"])
    if dialect == "postgresql":
        return postgresql.insert(Event).on_conflict_do_nothing(index_elements=["event_key"])
    raise NotImplementedError(f"СУБД {dialect} не поддерживается")


def count_events(session: Session) -> int:
    """Возвращает число событий в базе."""
    return session.scalar(select(func.count()).select_from(Event)) or 0


def save_events(session: Session, events: pd.DataFrame) -> int:
    """Принимает DataFrame из парсера, сохраняет новые события, возвращает число добавленных."""
    if events.empty:
        return 0
    # Считаем разницу до и после: rowcount у пакетной вставки надёжен не во всех драйверах.
    before = count_events(session)
    session.execute(_insert_ignoring_duplicates(session), _event_rows(events))
    return count_events(session) - before


def _count_where(condition: Any) -> Any:
    return func.sum(case((condition, 1), else_=0))


def refresh_attackers(session: Session) -> int:
    """Пересчитывает таблицу attackers по всем событиям, возвращает число атакующих IP."""
    # Таблица целиком выводится из events, поэтому проще и надёжнее
    # пересобрать её, чем обновлять счётчики по кусочкам при каждом импорте.
    is_hostile = Event.event_type.in_(HOSTILE_EVENT_TYPES)
    summary = (
        select(
            Event.ip,
            func.min(Event.timestamp),
            func.max(Event.timestamp),
            func.count(),
            _count_where(Event.event_type == EventType.FAILED_LOGIN),
            _count_where(Event.event_type == EventType.INVALID_USER),
            _count_where(Event.event_type == EventType.SCANNER),
            _count_where(Event.event_type == EventType.ACCEPTED),
            # case без else даёт NULL для мирных событий, а COUNT(DISTINCT) NULL не считает.
            func.count(func.distinct(case((is_hostile, Event.username)))),
        )
        .group_by(Event.ip)
        .having(_count_where(is_hostile) > 0)
    )
    columns = [
        "ip",
        "first_seen",
        "last_seen",
        "total_events",
        "failed_logins",
        "invalid_users",
        "scanner_hits",
        "successful_logins",
        "distinct_usernames",
    ]
    session.execute(delete(Attacker))
    session.execute(insert(Attacker).from_select(columns, summary))
    return count_attackers(session)


@dataclass(frozen=True)
class EventFilter:
    """Условия выборки событий. Время — aware datetime, until не включается."""

    since: Optional[datetime] = None
    until: Optional[datetime] = None
    ip: Optional[str] = None
    username: Optional[str] = None
    event_types: Optional[Sequence[EventType]] = None


def _filtered(query: Select, filters: Optional[EventFilter]) -> Select:
    if filters is None:
        return query
    if filters.since is not None:
        query = query.where(Event.timestamp >= filters.since)
    if filters.until is not None:
        query = query.where(Event.timestamp < filters.until)
    if filters.ip is not None:
        query = query.where(Event.ip == filters.ip)
    if filters.username is not None:
        query = query.where(Event.username == filters.username)
    if filters.event_types:
        query = query.where(Event.event_type.in_(filters.event_types))
    return query


def read_events(session: Session, filters: Optional[EventFilter] = None) -> pd.DataFrame:
    """Принимает фильтр, возвращает DataFrame событий (как у парсера), отсортированный по времени."""
    query = _filtered(select(Event).order_by(Event.timestamp, Event.id), filters)
    return events_to_dataframe(
        AuthEvent(
            timestamp=event.timestamp,
            event_type=event.event_type,
            ip=event.ip,
            host=event.host,
            username=event.username,
            port=event.port,
            auth_method=event.auth_method,
            invalid_user=event.invalid_user,
            source=event.source,
        )
        for event in session.scalars(query)
    )


def list_events(
    session: Session,
    filters: Optional[EventFilter] = None,
    *,
    limit: int = 100,
    offset: int = 0,
) -> tuple[int, list[Event]]:
    """Принимает фильтр и страницу, возвращает (сколько всего подходит, события страницы от новых к старым)."""
    total = session.scalar(_filtered(select(func.count()).select_from(Event), filters)) or 0
    query = _filtered(select(Event), filters).order_by(Event.timestamp.desc(), Event.id.desc())
    return total, list(session.scalars(query.limit(limit).offset(offset)))


ATTACKER_SORT_FIELDS = (
    "failed_logins",
    "invalid_users",
    "scanner_hits",
    "distinct_usernames",
    "total_events",
    "last_seen",
)


def top_attackers(session: Session, limit: int = 10, order_by: str = "failed_logins") -> list[Attacker]:
    """Принимает размер топа и поле из ATTACKER_SORT_FIELDS, возвращает атакующих по убыванию этого поля."""
    if order_by not in ATTACKER_SORT_FIELDS:
        raise ValueError(f"order_by должен быть одним из {ATTACKER_SORT_FIELDS}")
    query = (
        select(Attacker)
        .order_by(getattr(Attacker, order_by).desc(), Attacker.total_events.desc(), Attacker.ip)
        .limit(limit)
    )
    return list(session.scalars(query))


def get_attacker(session: Session, ip: str) -> Optional[Attacker]:
    """Возвращает сводку по IP или None, если IP не атаковал."""
    return session.get(Attacker, ip)


def count_attackers(session: Session) -> int:
    """Возвращает число атакующих IP."""
    return session.scalar(select(func.count()).select_from(Attacker)) or 0


def count_incidents_by_kind(session: Session) -> dict[IncidentKind, int]:
    """Возвращает число инцидентов каждого вида (виды без инцидентов — с нулём)."""
    rows = session.execute(select(IncidentRecord.kind, func.count()).group_by(IncidentRecord.kind))
    counts = {kind: 0 for kind in IncidentKind}
    counts.update({kind: count for kind, count in rows})
    return counts


def replace_incidents(session: Session, incidents: Sequence[Incident]) -> int:
    """Заменяет содержимое таблицы incidents новыми инцидентами, возвращает их число."""
    # Детектор каждый раз смотрит на все события, поэтому старые инциденты
    # не дополняем, а заменяем: иначе после смены порогов остались бы устаревшие.
    session.execute(delete(IncidentRecord))
    session.add_all(
        IncidentRecord(
            kind=incident.kind,
            ip=incident.ip,
            start=incident.start,
            end=incident.end,
            event_count=incident.event_count,
            distinct_usernames=incident.distinct_usernames,
            details=incident.details,
        )
        for incident in incidents
    )
    session.flush()
    return len(incidents)


def read_incidents(
    session: Session,
    *,
    kind: Optional[IncidentKind] = None,
    ip: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
) -> list[Incident]:
    """Принимает необязательные фильтры, возвращает инциденты из базы по времени начала."""
    query = select(IncidentRecord).order_by(IncidentRecord.start, IncidentRecord.id)
    if kind is not None:
        query = query.where(IncidentRecord.kind == kind)
    if ip is not None:
        query = query.where(IncidentRecord.ip == ip)
    # Инцидент попадает в период, если пересекается с ним, а не только начался внутри.
    if since is not None:
        query = query.where(IncidentRecord.end >= since)
    if until is not None:
        query = query.where(IncidentRecord.start < until)
    return [
        Incident(
            kind=record.kind,
            ip=record.ip,
            start=record.start,
            end=record.end,
            event_count=record.event_count,
            distinct_usernames=record.distinct_usernames,
            details=record.details,
        )
        for record in session.scalars(query)
    ]
