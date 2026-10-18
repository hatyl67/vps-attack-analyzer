"""Тесты клиента API, которым пользуется дашборд."""

from __future__ import annotations

from datetime import date

import httpx
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from attack_analyzer import charts
from attack_analyzer.dashboard.app import create_dashboard
from attack_analyzer.dashboard.client import ApiClient, ApiError, DashboardFilters
from attack_analyzer.generator import GeneratedLog

HOSTILE = tuple(charts.HOSTILE_TYPES)


@pytest.fixture(scope="module")
def client(api_client: TestClient) -> ApiClient:
    return ApiClient(http=api_client)


def test_filters_use_local_midnight() -> None:
    params = DashboardFilters(date(2026, 10, 5), date(2026, 10, 6), "Europe/Moscow", ("scanner",)).params()
    assert params == [
        ("since", "2026-10-05T00:00:00+03:00"),
        ("until", "2026-10-07T00:00:00+03:00"),
        ("event_type", "scanner"),
    ]


def test_empty_filters_have_no_params() -> None:
    assert DashboardFilters().params() == []


def test_summary_matches_generated(client: ApiClient, api_log: GeneratedLog) -> None:
    summary = client.summary(DashboardFilters())
    assert summary["total_events"] == sum(api_log.expected.values())


def test_timeline_has_analytics_shape(client: ApiClient) -> None:
    filters = DashboardFilters(date(2026, 10, 5), date(2026, 10, 8), "Europe/Moscow", HOSTILE)
    table = client.timeline(filters, "day")
    assert list(table.columns) == ["failed_login", "invalid_user", "accepted", "scanner", "total"]
    assert str(table.index.tz) == "Europe/Moscow"
    assert table.index[0] == pd.Timestamp("2026-10-05", tz="Europe/Moscow")
    assert table["accepted"].sum() == 0
    charts.draw_timeline(table, "day", filters.tz)


def test_heatmap_and_usernames(client: ApiClient) -> None:
    filters = DashboardFilters(tz="Europe/Moscow", event_types=HOSTILE)
    heatmap = client.heatmap(filters)
    assert heatmap.shape == (7, 24)
    charts.draw_heatmap(heatmap, filters.tz)

    usernames = client.top_usernames(filters, 5)
    assert usernames.index[0] == "root"
    assert list(usernames) == sorted(usernames, reverse=True)


def test_tables(client: ApiClient, api_log: GeneratedLog) -> None:
    attackers = client.top_attackers(5)
    assert len(attackers) == 5
    assert str(attackers["last_seen"].dt.tz) == "UTC"

    incidents = client.incidents(DashboardFilters())
    assert "success_after_attack" in set(incidents["kind"])

    ip = next(iter(api_log.attackers))
    events = client.events(DashboardFilters(), ip=ip, limit=50)
    assert set(events["ip"]) == {ip}


def test_period_without_events(client: ApiClient) -> None:
    filters = DashboardFilters(date(2020, 1, 1), date(2020, 1, 2), "UTC", HOSTILE)
    assert client.timeline(filters, "hour").empty
    assert client.events(filters).empty
    charts.draw_timeline(client.timeline(filters, "hour"), "hour", "UTC")


def test_unreachable_api_raises_api_error() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    broken = ApiClient(http=httpx.Client(base_url="http://api", transport=httpx.MockTransport(refuse)))
    with pytest.raises(ApiError, match="недоступно"):
        broken.summary(DashboardFilters())


def test_api_error_status_raises_api_error(client: ApiClient) -> None:
    with pytest.raises(ApiError, match="422"):
        client.heatmap(DashboardFilters(tz="UTC", event_types=("hacker",)))


def test_dashboard_app_builds() -> None:
    assert create_dashboard("http://127.0.0.1:1") is not None
