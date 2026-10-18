"""Клиент HTTP API для дашборда: запросы и превращение JSON в DataFrame."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from typing import Any, Optional
from zoneinfo import ZoneInfo

import httpx
import pandas as pd

from attack_analyzer import analytics

API_URL_ENV = "ATTACK_ANALYZER_API"
DEFAULT_API_URL = "http://127.0.0.1:8000"


class ApiError(RuntimeError):
    """API недоступно или ответило ошибкой."""


@dataclass(frozen=True)
class DashboardFilters:
    """Выбор пользователя в дашборде: период в днях, пояс и типы событий."""

    start: Optional[date] = None
    end: Optional[date] = None
    tz: str = "UTC"
    event_types: tuple[str, ...] = field(default_factory=tuple)

    def params(self) -> list[tuple[str, str]]:
        """Возвращает параметры запроса для эндпоинтов с фильтром событий."""
        zone = ZoneInfo(self.tz)
        result = []
        # Дни выбраны в поясе пользователя: «5 октября по Москве» начинается
        # в 21:00 UTC 4 октября. Поэтому границы считаем в его поясе.
        if self.start is not None:
            result.append(("since", datetime.combine(self.start, time(), zone).isoformat()))
        if self.end is not None:
            # end включительно для человека, а until в API не включается.
            result.append(("until", datetime.combine(self.end + timedelta(days=1), time(), zone).isoformat()))
        result.extend(("event_type", event_type) for event_type in self.event_types)
        return result


class ApiClient:
    """Обёртка над httpx.Client: один метод на эндпоинт, ответы в виде DataFrame."""

    def __init__(self, base_url: Optional[str] = None, *, http: Optional[httpx.Client] = None) -> None:
        # http можно передать готовый: тесты подставляют TestClient FastAPI,
        # который ходит в приложение напрямую, без сети.
        self._http = http or httpx.Client(
            base_url=base_url or os.environ.get(API_URL_ENV, DEFAULT_API_URL),
            timeout=15,
        )

    def _get(self, path: str, params: Optional[list[tuple[str, Any]]] = None) -> Any:
        try:
            response = self._http.get(path, params=params)
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            raise ApiError(f"API ответило {error.response.status_code} на {path}: {error.response.text}") from error
        except httpx.HTTPError as error:
            raise ApiError(f"API недоступно ({error.__class__.__name__}): {error}") from error
        return response.json()

    def summary(self, filters: DashboardFilters) -> dict[str, Any]:
        """Возвращает общие цифры за период (как /stats/summary)."""
        return self._get("/stats/summary", filters.params())

    def timeline(self, filters: DashboardFilters, bucket: str) -> pd.DataFrame:
        """Возвращает таблицу того же вида, что analytics.timeline."""
        points = self._get("/stats/timeline", [*filters.params(), ("bucket", bucket), ("tz", filters.tz)])
        columns = [*analytics.EVENT_TYPE_VALUES, "total"]
        if not points:
            return pd.DataFrame(columns=columns, dtype="int64")
        table = pd.DataFrame([{**point["counts"], "total": point["total"]} for point in points])
        table = table.reindex(columns=columns, fill_value=0)
        # Через UTC: при переходе на летнее время смещения в ответе разные,
        # и pandas не собрал бы из них один индекс с поясом.
        starts = pd.to_datetime([point["start"] for point in points], utc=True)
        table.index = starts.tz_convert(filters.tz)
        table.index.name = "start"
        return table.astype("int64")

    def heatmap(self, filters: DashboardFilters) -> pd.DataFrame:
        """Возвращает таблицу 7x24 того же вида, что analytics.weekday_hour_heatmap."""
        body = self._get("/stats/heatmap", [*filters.params(), ("tz", filters.tz)])
        table = pd.DataFrame(body["counts"], index=body["weekdays"], columns=body["hours"])
        table.index.name = "weekday"
        table.columns.name = "hour"
        return table

    def top_usernames(self, filters: DashboardFilters, limit: int) -> pd.Series:
        """Возвращает Series «логин -> число неудачных попыток»."""
        params = [(key, value) for key, value in filters.params() if key != "event_type"]
        items = self._get("/stats/top-usernames", [*params, ("limit", limit)])
        return pd.Series({item["value"]: item["count"] for item in items}, dtype="int64")

    def top_attackers(self, limit: int, order_by: str = "failed_logins") -> pd.DataFrame:
        """Возвращает топ атакующих IP за всё время."""
        items = self._get("/attackers/top", [("limit", limit), ("order_by", order_by)])
        return _frame(items, ["first_seen", "last_seen"])

    def incidents(self, filters: DashboardFilters) -> pd.DataFrame:
        """Возвращает инциденты, пересекающие период."""
        params = [(key, value) for key, value in filters.params() if key != "event_type"]
        return _frame(self._get("/incidents", params), ["start", "end"])

    def events(self, filters: DashboardFilters, *, ip: Optional[str] = None, limit: int = 200) -> pd.DataFrame:
        """Возвращает последние события за период (не больше limit)."""
        params = [*filters.params(), ("limit", limit)]
        if ip is not None:
            params.append(("ip", ip))
        return _frame(self._get("/events", params)["items"], ["timestamp"])


def _frame(items: list[dict[str, Any]], time_columns: list[str]) -> pd.DataFrame:
    df = pd.DataFrame(items)
    for column in time_columns:
        if column in df:
            df[column] = pd.to_datetime(df[column], utc=True)
    return df
