"""Тесты HTTP API на базе с сгенерированным логом."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterator
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

from attack_analyzer.api import create_app
from attack_analyzer.detector import detect
from attack_analyzer.generator import GeneratedLog, generate
from attack_analyzer.parsers import events_to_dataframe, parse_lines
from attack_analyzer.storage import make_engine, make_session_factory, refresh_attackers, replace_incidents, save_events

PROJECT_CONFIG = Path(__file__).resolve().parents[1] / "config.toml"
DAYS = 4


@pytest.fixture(scope="module")
def generated() -> GeneratedLog:
    return generate(datetime(2026, 10, 5, tzinfo=ZoneInfo("Europe/Moscow")), days=DAYS, seed=11)


@pytest.fixture(scope="module")
def client(generated: GeneratedLog, tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    url = f"sqlite:///{tmp_path_factory.mktemp('api') / 'api.db'}"
    events = events_to_dataframe(parse_lines(generated.lines, year=2026, tz="Europe/Moscow"))
    engine = make_engine(url)
    with make_session_factory(engine).begin() as session:
        save_events(session, events)
        refresh_attackers(session)
        replace_incidents(session, detect(events))
    engine.dispose()

    with TestClient(create_app(url, PROJECT_CONFIG)) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def total_events(generated: GeneratedLog) -> int:
    return sum(generated.expected.values())


def scenario_ip(generated: GeneratedLog, scenario: str) -> str:
    return next(ip for ip, name in generated.attackers.items() if name == scenario)


def test_health(client: TestClient, total_events: int) -> None:
    assert client.get("/health").json() == {"status": "ok", "events": total_events}


def test_events_first_page(client: TestClient, total_events: int) -> None:
    body = client.get("/events").json()
    assert body["total"] == total_events
    assert len(body["items"]) == 100
    times = [item["timestamp"] for item in body["items"]]
    assert times == sorted(times, reverse=True)
    assert body["items"][0]["timestamp"].endswith("Z") or body["items"][0]["timestamp"].endswith("+00:00")


def test_events_pages_do_not_overlap(client: TestClient) -> None:
    first = client.get("/events", params={"limit": 50}).json()["items"]
    second = client.get("/events", params={"limit": 50, "offset": 50}).json()["items"]
    assert not {item["id"] for item in first} & {item["id"] for item in second}


def test_events_filter_by_types_and_ip(client: TestClient, generated: GeneratedLog) -> None:
    body = client.get("/events", params=[("event_type", "scanner"), ("event_type", "invalid_user")]).json()
    assert {item["event_type"] for item in body["items"]} == {"scanner", "invalid_user"}

    ip = scenario_ip(generated, "bruteforce")
    body = client.get("/events", params={"ip": ip, "limit": 1000}).json()
    assert body["total"] > 0
    assert {item["ip"] for item in body["items"]} == {ip}


def test_events_filter_by_period(client: TestClient) -> None:
    body = client.get("/events", params={"since": "2026-10-06", "until": "2026-10-07", "limit": 1000}).json()
    assert body["total"] > 0
    assert all("2026-10-06" in item["timestamp"] for item in body["items"])


@pytest.mark.parametrize(
    "params",
    [
        {"since": "2026-10-07", "until": "2026-10-06"},
        {"limit": 0},
        {"limit": 5000},
        {"event_type": "hacker"},
        {"since": "вчера"},
    ],
)
def test_events_bad_params(client: TestClient, params: dict) -> None:
    assert client.get("/events", params=params).status_code == 422


def test_top_attackers(client: TestClient) -> None:
    top = client.get("/attackers/top", params={"limit": 5}).json()
    assert len(top) == 5
    failed = [item["failed_logins"] for item in top]
    assert failed == sorted(failed, reverse=True)

    by_scans = client.get("/attackers/top", params={"order_by": "scanner_hits"}).json()
    assert by_scans[0]["scanner_hits"] >= by_scans[-1]["scanner_hits"] > 0
    assert client.get("/attackers/top", params={"order_by": "ip; DROP TABLE"}).status_code == 422


def test_attacker_details(client: TestClient, generated: GeneratedLog) -> None:
    ip = scenario_ip(generated, "compromise")
    body = client.get(f"/attackers/{ip}").json()
    assert body["successful_logins"] == 1
    assert {"bruteforce", "success_after_attack"} <= {incident["kind"] for incident in body["incidents"]}
    assert client.get("/attackers/198.51.100.23").status_code == 404


def test_incidents_filter(client: TestClient) -> None:
    found = client.get("/incidents", params={"kind": "bruteforce"}).json()
    assert found
    assert {incident["kind"] for incident in found} == {"bruteforce"}


def test_summary(client: TestClient, generated: GeneratedLog, total_events: int) -> None:
    body = client.get("/stats/summary").json()
    assert body["total_events"] == total_events
    assert body["by_type"] == {event.value: count for event, count in generated.expected.items()}
    assert body["incidents"]["success_after_attack"] == 1


def test_timeline_by_day_in_local_time(client: TestClient, total_events: int) -> None:
    points = client.get("/stats/timeline", params={"bucket": "day", "tz": "Europe/Moscow"}).json()
    assert sum(point["total"] for point in points) == total_events
    assert points[0]["start"] == "2026-10-05T00:00:00+03:00"
    # Сессии последнего дня могут закончиться после полуночи: тогда корзин на одну больше.
    assert len(points) in (DAYS, DAYS + 1)


def test_timeline_by_hour_has_no_gaps(client: TestClient) -> None:
    points = client.get("/stats/timeline", params={"bucket": "hour"}).json()
    starts = [datetime.fromisoformat(point["start"].replace("Z", "+00:00")) for point in points]
    assert all((later - earlier).total_seconds() == 3600 for earlier, later in zip(starts, starts[1:]))


def test_heatmap(client: TestClient, total_events: int) -> None:
    body = client.get("/stats/heatmap", params={"tz": "Europe/Moscow"}).json()
    assert len(body["counts"]) == 7
    assert all(len(row) == 24 for row in body["counts"])
    assert sum(map(sum, body["counts"])) == total_events
    assert client.get("/stats/heatmap", params={"tz": "Mars/Olympus"}).status_code == 422


def test_top_usernames(client: TestClient) -> None:
    top = client.get("/stats/top-usernames", params={"limit": 3}).json()
    assert top[0]["value"] == "root"
    assert len(top) == 3
