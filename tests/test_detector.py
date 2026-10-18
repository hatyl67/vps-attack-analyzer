"""Тесты детектора: границы порогов на маленьких примерах и сверка с генератором."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo

import pandas as pd
import pytest

from attack_analyzer.config import (
    BruteforceConfig,
    DetectorConfig,
    EnumerationConfig,
    RepeatedConfig,
    SuccessAfterAttackConfig,
)
from attack_analyzer.detector import (
    detect,
    detect_bruteforce,
    detect_enumeration,
    detect_repeated,
    detect_success_after_attack,
    incidents_to_dataframe,
)
from attack_analyzer.generator import ALICE_IPS, BOB_IP, CI_IP, GeneratedLog, generate
from attack_analyzer.models import AuthEvent, EventType, IncidentKind
from attack_analyzer.parsers import events_to_dataframe, parse_lines

START = datetime(2026, 10, 18, 3, 0, tzinfo=timezone.utc)
IP = "203.0.113.5"


def event(
    seconds: float,
    event_type: EventType = EventType.FAILED_LOGIN,
    username: Optional[str] = "root",
    ip: str = IP,
) -> AuthEvent:
    return AuthEvent(
        timestamp=START + timedelta(seconds=seconds),
        event_type=event_type,
        ip=ip,
        host="vps",
        username=username,
    )


def frame(*events: AuthEvent) -> pd.DataFrame:
    return events_to_dataframe(events)


BRUTEFORCE_5_IN_60S = DetectorConfig(bruteforce=BruteforceConfig(threshold=5, window_minutes=1))


def test_bruteforce_exactly_threshold_in_window() -> None:
    events = frame(*(event(seconds) for seconds in (0, 10, 20, 30, 60)))
    [incident] = detect_bruteforce(events, BRUTEFORCE_5_IN_60S)
    assert incident.kind is IncidentKind.BRUTEFORCE
    assert incident.event_count == 5
    assert incident.start == START
    assert incident.end == START + timedelta(seconds=60)


def test_bruteforce_one_attempt_short() -> None:
    events = frame(*(event(seconds) for seconds in (0, 10, 20, 30)))
    assert detect_bruteforce(events, BRUTEFORCE_5_IN_60S) == []


def test_bruteforce_attempts_spread_wider_than_window() -> None:
    # Каждые 50 секунд: в любые 60 секунд попадает не больше двух попыток.
    events = frame(*(event(seconds) for seconds in range(0, 500, 50)))
    assert detect_bruteforce(events, BRUTEFORCE_5_IN_60S) == []


def test_bruteforce_two_series_give_two_incidents() -> None:
    first = [event(seconds) for seconds in range(0, 50, 10)]
    second = [event(3600 + seconds) for seconds in range(0, 50, 10)]
    incidents = detect_bruteforce(frame(*first, *second), BRUTEFORCE_5_IN_60S)
    assert [incident.event_count for incident in incidents] == [5, 5]


def test_bruteforce_counts_each_ip_separately() -> None:
    mixed = [event(seconds, ip=IP if seconds % 20 == 0 else "192.0.2.99") for seconds in range(0, 80, 10)]
    assert detect_bruteforce(frame(*mixed), BRUTEFORCE_5_IN_60S) == []


def test_enumeration_counts_distinct_usernames() -> None:
    config = DetectorConfig(enumeration=EnumerationConfig(distinct_usernames=3, window_minutes=10))
    same_login = frame(*(event(seconds, EventType.INVALID_USER, "admin") for seconds in range(0, 100, 10)))
    assert detect_enumeration(same_login, config) == []

    names = ["admin", "test", "oracle"]
    different = frame(*(event(index * 10, EventType.INVALID_USER, name) for index, name in enumerate(names)))
    [incident] = detect_enumeration(different, config)
    assert incident.distinct_usernames == 3


def test_enumeration_ignores_scanners() -> None:
    config = DetectorConfig(enumeration=EnumerationConfig(distinct_usernames=1, window_minutes=10))
    assert detect_enumeration(frame(event(0, EventType.SCANNER, None)), config) == []


def test_repeated_needs_enough_days() -> None:
    config = DetectorConfig(repeated=RepeatedConfig(min_active_days=3))
    two_days = frame(event(0), event(86400))
    assert detect_repeated(two_days, config) == []

    three_days = frame(event(0), event(86400), event(2 * 86400, EventType.SCANNER, None))
    [incident] = detect_repeated(three_days, config)
    assert incident.event_count == 3
    assert incident.details == "активен 3 дн."


def test_repeated_ignores_successful_logins() -> None:
    config = DetectorConfig(repeated=RepeatedConfig(min_active_days=2))
    logins = frame(*(event(day * 86400, EventType.ACCEPTED, "alice") for day in range(5)))
    assert detect_repeated(logins, config) == []


def test_success_after_attack() -> None:
    config = DetectorConfig(success_after_attack=SuccessAfterAttackConfig(min_failed_before=3, lookback_hours=1))
    attack = [event(seconds, username="bob") for seconds in (0, 10, 20)]
    [incident] = detect_success_after_attack(frame(*attack, event(30, EventType.ACCEPTED, "bob")), config)
    assert incident.kind is IncidentKind.SUCCESS_AFTER_ATTACK
    assert incident.event_count == 4
    assert "bob" in incident.details


def test_success_after_attack_outside_lookback() -> None:
    config = DetectorConfig(success_after_attack=SuccessAfterAttackConfig(min_failed_before=3, lookback_hours=1))
    attack = [event(seconds, username="bob") for seconds in (0, 10, 20)]
    late_login = event(2 * 3600, EventType.ACCEPTED, "bob")
    assert detect_success_after_attack(frame(*attack, late_login), config) == []


def test_typo_before_login_is_not_an_attack() -> None:
    events = frame(event(0, username="bob"), event(10, EventType.ACCEPTED, "bob"))
    assert detect(events) == []


def test_empty_events() -> None:
    assert detect(events_to_dataframe([])) == []
    assert incidents_to_dataframe([]).empty


@pytest.fixture(scope="module")
def generated() -> GeneratedLog:
    return generate(datetime(2026, 10, 1, tzinfo=ZoneInfo("Europe/Moscow")), days=7, seed=3)


@pytest.fixture(scope="module")
def kinds_by_ip(generated: GeneratedLog) -> dict[str, set[IncidentKind]]:
    events = events_to_dataframe(parse_lines(generated.lines, year=2026, tz="Europe/Moscow"))
    found: dict[str, set[IncidentKind]] = defaultdict(set)
    for incident in detect(events):
        found[incident.ip].add(incident.kind)
    return found


def ips_with_scenario(generated: GeneratedLog, scenario: str) -> list[str]:
    ips = [ip for ip, name in generated.attackers.items() if name == scenario]
    assert ips, f"в сгенерированном логе нет сценария {scenario}"
    return ips


def test_generated_bruteforce_found(generated: GeneratedLog, kinds_by_ip: dict[str, set[IncidentKind]]) -> None:
    for ip in ips_with_scenario(generated, "bruteforce"):
        assert IncidentKind.BRUTEFORCE in kinds_by_ip[ip]
        assert IncidentKind.ENUMERATION not in kinds_by_ip[ip]
        assert IncidentKind.REPEATED not in kinds_by_ip[ip]


def test_generated_enumeration_found(generated: GeneratedLog, kinds_by_ip: dict[str, set[IncidentKind]]) -> None:
    for ip in ips_with_scenario(generated, "enumeration"):
        assert IncidentKind.ENUMERATION in kinds_by_ip[ip]


def test_generated_slow_attackers_are_repeated_not_bruteforce(
    generated: GeneratedLog, kinds_by_ip: dict[str, set[IncidentKind]]
) -> None:
    for ip in ips_with_scenario(generated, "slow"):
        assert kinds_by_ip[ip] == {IncidentKind.REPEATED}


def test_generated_compromise_found(generated: GeneratedLog, kinds_by_ip: dict[str, set[IncidentKind]]) -> None:
    [ip] = ips_with_scenario(generated, "compromise")
    assert {IncidentKind.BRUTEFORCE, IncidentKind.SUCCESS_AFTER_ATTACK} <= kinds_by_ip[ip]


def test_generated_scanners_are_not_login_attacks(
    generated: GeneratedLog, kinds_by_ip: dict[str, set[IncidentKind]]
) -> None:
    for ip in ips_with_scenario(generated, "scanner"):
        assert kinds_by_ip[ip] <= {IncidentKind.REPEATED}


def test_generated_legit_users_are_clean(kinds_by_ip: dict[str, set[IncidentKind]]) -> None:
    for ip in (*ALICE_IPS, BOB_IP, CI_IP):
        assert ip not in kinds_by_ip
