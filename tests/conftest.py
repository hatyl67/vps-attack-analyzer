"""Общие фикстуры: база с сгенерированным логом и клиент API к ней."""

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
API_LOG_DAYS = 4


@pytest.fixture(scope="session")
def api_log() -> GeneratedLog:
    return generate(datetime(2026, 10, 5, tzinfo=ZoneInfo("Europe/Moscow")), days=API_LOG_DAYS, seed=11)


@pytest.fixture(scope="session")
def api_client(api_log: GeneratedLog, tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    url = f"sqlite:///{tmp_path_factory.mktemp('api') / 'api.db'}"
    events = events_to_dataframe(parse_lines(api_log.lines, year=2026, tz="Europe/Moscow"))
    engine = make_engine(url)
    with make_session_factory(engine).begin() as session:
        save_events(session, events)
        refresh_attackers(session)
        replace_incidents(session, detect(events))
    engine.dispose()

    with TestClient(create_app(url, PROJECT_CONFIG)) as client:
        yield client
