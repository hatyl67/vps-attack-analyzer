"""Агрегации DataFrame событий: ряды по времени, тепловая карта, топы.

Функции чистые (DataFrame на входе, DataFrame на выходе), поэтому их
используют и API, и графики.
"""

from __future__ import annotations

from typing import Union
from zoneinfo import ZoneInfo

import pandas as pd

from attack_analyzer.models import EventType

EVENT_TYPE_VALUES = [member.value for member in EventType]
WEEKDAY_NAMES = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
# Псевдонимы частот pandas: "h" и "D". Заглавная "H" в pandas 2.2+ устарела.
BUCKET_FREQUENCIES = {"hour": "h", "day": "D"}

TimezoneName = Union[str, ZoneInfo]


def timeline(events: pd.DataFrame, bucket: str = "hour", tz: TimezoneName = "UTC") -> pd.DataFrame:
    """Принимает события, размер корзины ("hour" или "day") и пояс.

    Возвращает DataFrame: индекс — начало корзины в поясе tz, колонки — типы
    событий и total. Пустые корзины внутри периода заполнены нулями.
    """
    if bucket not in BUCKET_FREQUENCIES:
        raise ValueError(f"bucket должен быть одним из {list(BUCKET_FREQUENCIES)}")
    columns = [*EVENT_TYPE_VALUES, "total"]
    if events.empty:
        return pd.DataFrame(columns=columns, dtype="int64")

    local_time = events["timestamp"].dt.tz_convert(tz)
    # get_dummies превращает тип события в колонки 0/1, а resample суммирует
    # их по корзинам. В отличие от groupby, resample создаёт и пустые корзины,
    # поэтому на графике не будет ложных «прямых» через часы без атак.
    one_hot = pd.get_dummies(events["event_type"].astype(str)).set_axis(pd.DatetimeIndex(local_time))
    counts = one_hot.resample(BUCKET_FREQUENCIES[bucket]).sum()
    counts = counts.reindex(columns=EVENT_TYPE_VALUES, fill_value=0).astype("int64")
    counts["total"] = counts.sum(axis=1)
    counts.index.name = "start"
    return counts


def weekday_hour_heatmap(events: pd.DataFrame, tz: TimezoneName = "UTC") -> pd.DataFrame:
    """Принимает события и пояс, возвращает таблицу 7x24: строки — дни недели (Пн..Вс), колонки — часы."""
    local_time = events["timestamp"].dt.tz_convert(tz)
    table = pd.crosstab(local_time.dt.dayofweek, local_time.dt.hour)
    table = table.reindex(index=range(7), columns=range(24), fill_value=0)
    table.index = WEEKDAY_NAMES
    table.index.name = "weekday"
    table.columns.name = "hour"
    return table


def top_values(events: pd.DataFrame, column: str, limit: int = 10) -> pd.Series:
    """Принимает события и имя колонки, возвращает limit самых частых значений с числом повторов."""
    return events[column].dropna().value_counts().head(limit)


def summary(events: pd.DataFrame) -> dict[str, object]:
    """Принимает события, возвращает общие цифры: всего, по типам, уникальных IP, период."""
    by_type = events["event_type"].astype(str).value_counts()
    return {
        "total_events": int(len(events)),
        "by_type": {value: int(by_type.get(value, 0)) for value in EVENT_TYPE_VALUES},
        "unique_ips": int(events["ip"].nunique()),
        "first_event": events["timestamp"].min().to_pydatetime() if not events.empty else None,
        "last_event": events["timestamp"].max().to_pydatetime() if not events.empty else None,
    }
