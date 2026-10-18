"""Эндпоинты API. Только чтение: события в базу попадают через CLI import."""

from dataclasses import replace
from enum import Enum
from typing import Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from attack_analyzer import analytics
from attack_analyzer.api.dependencies import event_filter, get_session, timezone_param
from attack_analyzer.api.schemas import (
    AttackerDetails,
    AttackerOut,
    EventOut,
    EventPage,
    Health,
    Heatmap,
    IncidentOut,
    NamedCount,
    Summary,
    TimelinePoint,
)
from attack_analyzer.models import EventType, IncidentKind
from attack_analyzer.storage import (
    ATTACKER_SORT_FIELDS,
    EventFilter,
    count_attackers,
    count_events,
    count_incidents_by_kind,
    get_attacker,
    list_events,
    read_events,
    read_incidents,
    top_attackers,
)

router = APIRouter()

# Enum собираем из списка полей хранилища, чтобы не дублировать его здесь;
# FastAPI покажет допустимые значения в /docs и сам вернёт 422 на остальные.
AttackerSort = Enum("AttackerSort", {name: name for name in ATTACKER_SORT_FIELDS}, type=str)


class Bucket(str, Enum):
    hour = "hour"
    day = "day"


@router.get("/health", response_model=Health, tags=["service"])
def health(session: Session = Depends(get_session)) -> Health:
    return Health(status="ok", events=count_events(session))


@router.get("/events", response_model=EventPage, tags=["events"])
def events(
    filters: EventFilter = Depends(event_filter),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
) -> EventPage:
    """События от новых к старым с фильтрами и постраничной выдачей."""
    total, page = list_events(session, filters, limit=limit, offset=offset)
    items = [EventOut.model_validate(event) for event in page]
    return EventPage(total=total, limit=limit, offset=offset, items=items)


@router.get("/attackers/top", response_model=list[AttackerOut], tags=["attackers"])
def attackers_top(
    limit: int = Query(10, ge=1, le=500),
    order_by: AttackerSort = Query(AttackerSort.failed_logins),  # type: ignore[valid-type, attr-defined]
    session: Session = Depends(get_session),
) -> list[AttackerOut]:
    """Самые активные атакующие IP по выбранному показателю."""
    return [AttackerOut.model_validate(item) for item in top_attackers(session, limit, order_by.value)]


@router.get("/attackers/{ip}", response_model=AttackerDetails, tags=["attackers"])
def attacker_details(ip: str, session: Session = Depends(get_session)) -> AttackerDetails:
    """Сводка по одному IP и найденные для него инциденты."""
    attacker = get_attacker(session, ip)
    if attacker is None:
        raise HTTPException(status_code=404, detail=f"IP {ip} не найден среди атакующих")
    incidents = [IncidentOut.model_validate(incident) for incident in read_incidents(session, ip=ip)]
    return AttackerDetails(**AttackerOut.model_validate(attacker).model_dump(), incidents=incidents)


@router.get("/incidents", response_model=list[IncidentOut], tags=["incidents"])
def incidents(
    kind: Optional[IncidentKind] = None,
    ip: Optional[str] = None,
    filters: EventFilter = Depends(event_filter),
    session: Session = Depends(get_session),
) -> list[IncidentOut]:
    """Атаки, найденные детектором; since/until отбирают инциденты, пересекающие период."""
    found = read_incidents(session, kind=kind, ip=ip, since=filters.since, until=filters.until)
    return [IncidentOut.model_validate(incident) for incident in found]


@router.get("/stats/summary", response_model=Summary, tags=["stats"])
def stats_summary(
    filters: EventFilter = Depends(event_filter),
    session: Session = Depends(get_session),
) -> Summary:
    """Общие цифры по событиям за период; attackers и incidents — по всей базе."""
    numbers = analytics.summary(read_events(session, filters))
    return Summary(
        **numbers,
        attackers=count_attackers(session),
        incidents=count_incidents_by_kind(session),
    )


@router.get("/stats/timeline", response_model=list[TimelinePoint], tags=["stats"])
def stats_timeline(
    bucket: Bucket = Bucket.hour,
    tz: ZoneInfo = Depends(timezone_param),
    filters: EventFilter = Depends(event_filter),
    session: Session = Depends(get_session),
) -> list[TimelinePoint]:
    """Число событий по часам или дням, с разбивкой по типам."""
    table = analytics.timeline(read_events(session, filters), bucket.value, tz)
    return [
        TimelinePoint(
            start=start.to_pydatetime(),
            total=int(row["total"]),
            counts={EventType(name): int(row[name]) for name in analytics.EVENT_TYPE_VALUES},
        )
        for start, row in table.iterrows()
    ]


@router.get("/stats/heatmap", response_model=Heatmap, tags=["stats"])
def stats_heatmap(
    tz: ZoneInfo = Depends(timezone_param),
    filters: EventFilter = Depends(event_filter),
    session: Session = Depends(get_session),
) -> Heatmap:
    """Тепловая карта «день недели x час» в выбранном поясе."""
    table = analytics.weekday_hour_heatmap(read_events(session, filters), tz)
    return Heatmap(
        timezone=tz.key,
        weekdays=list(table.index),
        hours=[int(hour) for hour in table.columns],
        counts=table.astype(int).values.tolist(),
    )


@router.get("/stats/top-usernames", response_model=list[NamedCount], tags=["stats"])
def stats_top_usernames(
    limit: int = Query(10, ge=1, le=500),
    filters: EventFilter = Depends(event_filter),
    session: Session = Depends(get_session),
) -> list[NamedCount]:
    """Самые частые логины; без event_type считаются только неудачные входы."""
    if not filters.event_types:
        filters = replace(filters, event_types=[EventType.FAILED_LOGIN])
    counts = analytics.top_values(read_events(session, filters), "username", limit)
    return [NamedCount(value=str(value), count=int(count)) for value, count in counts.items()]

