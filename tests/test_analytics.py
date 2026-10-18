"""Тесты агрегаций analytics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from attack_analyzer import analytics
from attack_analyzer.models import AuthEvent, EventType
from attack_analyzer.parsers import events_to_dataframe

START = datetime(2026, 10, 19, 22, 30, tzinfo=timezone.utc)  # понедельник


def make_events(*offsets_hours: float, event_type: EventType = EventType.FAILED_LOGIN):
    return events_to_dataframe(
        AuthEvent(timestamp=START + timedelta(hours=offset), event_type=event_type, ip="203.0.113.5", host="vps")
        for offset in offsets_hours
    )


def test_timeline_fills_empty_hours() -> None:
    table = analytics.timeline(make_events(0, 3), "hour")
    assert list(table["total"]) == [1, 0, 0, 1]
    assert list(table.columns) == [*analytics.EVENT_TYPE_VALUES, "total"]


def test_timeline_uses_timezone_for_days() -> None:
    # 22:30, 23:00 и 00:30 UTC — два разных дня в UTC, но по Москве (UTC+3) все три 20 октября.
    events = make_events(0, 0.5, 2)
    assert list(analytics.timeline(events, "day", "UTC")["total"]) == [2, 1]
    assert list(analytics.timeline(events, "day", "Europe/Moscow")["total"]) == [3]


def test_timeline_empty_and_bad_bucket() -> None:
    assert analytics.timeline(events_to_dataframe([]), "hour").empty
    with pytest.raises(ValueError):
        analytics.timeline(make_events(0), "week")


def test_heatmap_shape_and_timezone() -> None:
    table = analytics.weekday_hour_heatmap(make_events(0), "Europe/Moscow")
    assert table.shape == (7, 24)
    assert table.loc["Вт", 1] == 1
    assert int(table.values.sum()) == 1


def test_top_values_skips_missing() -> None:
    events = make_events(0, 1, event_type=EventType.SCANNER)
    assert analytics.top_values(events, "username").empty


def test_summary_counts_every_type() -> None:
    numbers = analytics.summary(make_events(0, 1))
    assert numbers["total_events"] == 2
    assert numbers["by_type"]["failed_login"] == 2
    assert numbers["by_type"]["scanner"] == 0
    assert numbers["first_event"] == START
