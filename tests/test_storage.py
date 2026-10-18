"""Тесты хранилища: сохранение без дублей, сводка по атакующим, чтение с фильтрами."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from zoneinfo import ZoneInfo

import pandas as pd
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from attack_analyzer.detector import detect
from attack_analyzer.generator import ALICE_IPS, CI_IP, GeneratedLog, generate
from attack_analyzer.models import EventType
from attack_analyzer.parsers import events_to_dataframe, parse_lines
from attack_analyzer.storage import (
    Attacker,
    count_events,
    make_engine,
    make_session_factory,
    read_events,
    read_incidents,
    refresh_attackers,
    replace_incidents,
    save_events,
    top_attackers,
)


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    with make_session_factory(engine)() as db_session:
        yield db_session
    engine.dispose()


@pytest.fixture(scope="module")
def generated() -> GeneratedLog:
    return generate(datetime(2026, 10, 1, tzinfo=ZoneInfo("Europe/Moscow")), days=5, seed=7)


@pytest.fixture(scope="module")
def generated_df(generated: GeneratedLog) -> pd.DataFrame:
    return events_to_dataframe(parse_lines(generated.lines, year=2026, tz="Europe/Moscow"))


def test_save_all_events(session: Session, generated_df: pd.DataFrame) -> None:
    assert save_events(session, generated_df) == len(generated_df)
    assert count_events(session) == len(generated_df)


def test_reimport_adds_nothing(session: Session, generated_df: pd.DataFrame) -> None:
    save_events(session, generated_df)
    assert save_events(session, generated_df) == 0
    assert count_events(session) == len(generated_df)


def test_partial_overlap_adds_only_new(session: Session, generated_df: pd.DataFrame) -> None:
    half = len(generated_df) // 2
    save_events(session, generated_df.iloc[:half])
    assert save_events(session, generated_df) == len(generated_df) - half


def test_repeated_identical_events_are_kept(session: Session) -> None:
    line = "Oct 18 03:14:15 vps sshd[1]: message repeated 3 times: [ Failed password for root from 203.0.113.5 port 1 ssh2]"
    df = events_to_dataframe(parse_lines([line], year=2026))
    assert save_events(session, df) == 3
    assert save_events(session, df) == 0


def test_empty_dataframe(session: Session) -> None:
    assert save_events(session, events_to_dataframe([])) == 0


def test_read_back_matches_saved(session: Session, generated_df: pd.DataFrame) -> None:
    save_events(session, generated_df)
    session.commit()
    loaded = read_events(session)
    pd.testing.assert_frame_equal(loaded, generated_df)


def test_read_events_filters(session: Session, generated_df: pd.DataFrame) -> None:
    save_events(session, generated_df)
    since = datetime(2026, 10, 2, tzinfo=timezone.utc)
    until = datetime(2026, 10, 3, tzinfo=timezone.utc)
    loaded = read_events(session, since=since, until=until, event_type=EventType.SCANNER)
    assert not loaded.empty
    assert loaded["timestamp"].between(since, until, inclusive="left").all()
    assert set(loaded["event_type"]) == {"scanner"}

    ip = generated_df["ip"].iloc[0]
    assert set(read_events(session, ip=ip)["ip"]) == {ip}


def test_refresh_attackers(session: Session, generated: GeneratedLog, generated_df: pd.DataFrame) -> None:
    save_events(session, generated_df)
    refresh_attackers(session)
    attackers = {attacker.ip: attacker for attacker in session.scalars(select(Attacker))}

    assert set(generated.attackers) <= set(attackers)
    assert not set(ALICE_IPS) & set(attackers)
    assert CI_IP not in attackers

    for ip, scenario in generated.attackers.items():
        attacker = attackers[ip]
        assert attacker.first_seen <= attacker.last_seen
        assert attacker.first_seen.tzinfo is not None
        expected_failed = ((generated_df["ip"] == ip) & (generated_df["event_type"] == "failed_login")).sum()
        assert attacker.failed_logins == expected_failed
        if scenario == "compromise":
            assert attacker.successful_logins == 1
        if scenario == "enumeration":
            assert attacker.distinct_usernames >= 10


def test_refresh_is_idempotent(session: Session, generated_df: pd.DataFrame) -> None:
    save_events(session, generated_df)
    assert refresh_attackers(session) == refresh_attackers(session)


def test_top_attackers_sorted(session: Session, generated_df: pd.DataFrame) -> None:
    save_events(session, generated_df)
    refresh_attackers(session)
    top = top_attackers(session, limit=5)
    assert len(top) == 5
    failed = [attacker.failed_logins for attacker in top]
    assert failed == sorted(failed, reverse=True)


def test_replace_incidents_roundtrip(session: Session, generated_df: pd.DataFrame) -> None:
    incidents = detect(generated_df)
    assert replace_incidents(session, incidents) == len(incidents)
    assert read_incidents(session) == incidents

    replace_incidents(session, incidents[:1])
    assert read_incidents(session) == incidents[:1]

    kind = incidents[0].kind
    assert all(incident.kind is kind for incident in read_incidents(session, kind=kind))
