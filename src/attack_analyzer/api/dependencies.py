"""Зависимости FastAPI: сессия базы и общие параметры запросов."""

from datetime import datetime, timezone
from typing import Iterator, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import HTTPException, Query, Request
from sqlalchemy.orm import Session

from attack_analyzer.models import EventType
from attack_analyzer.storage import EventFilter


def get_session(request: Request) -> Iterator[Session]:
    """Отдаёт сессию на время запроса и закрывает её после ответа."""
    with request.app.state.session_factory() as session:
        yield session


def as_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Принимает datetime из запроса, возвращает aware-время в UTC (время без пояса считается UTC)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def event_filter(
    since: Optional[datetime] = Query(None, description="Начало периода, ISO 8601; без пояса — UTC"),
    until: Optional[datetime] = Query(None, description="Конец периода (не включается)"),
    ip: Optional[str] = Query(None, description="Только события этого IP"),
    username: Optional[str] = Query(None, description="Только события с этим логином"),
    event_type: Optional[list[EventType]] = Query(None, description="Типы событий; можно повторять параметр"),
) -> EventFilter:
    """Собирает EventFilter из параметров запроса."""
    since_utc, until_utc = as_utc(since), as_utc(until)
    if since_utc is not None and until_utc is not None and since_utc >= until_utc:
        raise HTTPException(status_code=422, detail="since должно быть раньше until")
    return EventFilter(since=since_utc, until=until_utc, ip=ip, username=username, event_types=event_type)


def timezone_param(tz: str = Query("UTC", description="Пояс для группировки, например Europe/Moscow")) -> ZoneInfo:
    """Проверяет имя часового пояса и возвращает ZoneInfo."""
    try:
        return ZoneInfo(tz)
    # ValueError: ZoneInfo отвергает имена вроде "../etc/passwd" ещё до поиска файла.
    except (ZoneInfoNotFoundError, ValueError):
        raise HTTPException(status_code=422, detail=f"неизвестный часовой пояс: {tz}") from None
