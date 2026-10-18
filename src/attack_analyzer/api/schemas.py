"""Pydantic-схемы ответов API: они же задают документацию в /docs."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from attack_analyzer.models import EventType, IncidentKind


class ORMModel(BaseModel):
    # from_attributes: схему можно собрать прямо из ORM-объекта или dataclass
    # (Event, Attacker, Incident), а не только из словаря.
    model_config = ConfigDict(from_attributes=True)


class EventOut(ORMModel):
    id: int
    timestamp: datetime
    event_type: EventType
    ip: str
    username: Optional[str]
    port: Optional[int]
    auth_method: Optional[str]
    invalid_user: bool
    host: str
    source: str


class EventPage(BaseModel):
    total: int = Field(description="Сколько событий подходит под фильтр")
    limit: int
    offset: int
    items: list[EventOut]


class AttackerOut(ORMModel):
    ip: str
    first_seen: datetime
    last_seen: datetime
    total_events: int
    failed_logins: int
    invalid_users: int
    scanner_hits: int
    successful_logins: int
    distinct_usernames: int


class IncidentOut(ORMModel):
    kind: IncidentKind
    ip: str
    start: datetime
    end: datetime
    event_count: int
    distinct_usernames: int
    details: str


class AttackerDetails(AttackerOut):
    incidents: list[IncidentOut]


class TimelinePoint(BaseModel):
    start: datetime = Field(description="Начало корзины в запрошенном поясе")
    total: int
    counts: dict[EventType, int]


class Heatmap(BaseModel):
    timezone: str
    weekdays: list[str]
    hours: list[int]
    counts: list[list[int]] = Field(description="counts[день недели][час]")


class NamedCount(BaseModel):
    value: str
    count: int


class Summary(BaseModel):
    total_events: int
    by_type: dict[EventType, int]
    unique_ips: int
    attackers: int
    incidents: dict[IncidentKind, int]
    first_event: Optional[datetime]
    last_event: Optional[datetime]


class Health(BaseModel):
    status: str
    events: int
