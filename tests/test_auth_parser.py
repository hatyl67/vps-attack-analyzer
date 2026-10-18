"""Тесты парсера auth.log: отдельные форматы строк и сверка с генератором."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo

import pytest

from attack_analyzer.generator import generate
from attack_analyzer.models import AuthEvent, EventType
from attack_analyzer.parsers import ParseStats, events_to_dataframe, parse_lines
from attack_analyzer.parsers.auth_log import parse_auth_log


def parse_one(line: str, tz: Optional[str] = None) -> AuthEvent:
    events = list(parse_lines([line], year=2026, tz=tz))
    assert len(events) == 1, f"ожидали одно событие из: {line}"
    return events[0]


def test_failed_password_existing_user() -> None:
    event = parse_one("Oct 18 03:14:15 vps sshd[1234]: Failed password for root from 203.0.113.5 port 52144 ssh2")
    assert event.event_type is EventType.FAILED_LOGIN
    assert event.username == "root"
    assert event.ip == "203.0.113.5"
    assert event.port == 52144
    assert event.auth_method == "password"
    assert event.invalid_user is False
    assert event.host == "vps"
    assert event.timestamp == datetime(2026, 10, 18, 3, 14, 15, tzinfo=timezone.utc)


def test_failed_password_invalid_user() -> None:
    event = parse_one("Oct 18 03:14:15 vps sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 1 ssh2")
    assert event.event_type is EventType.FAILED_LOGIN
    assert event.username == "admin"
    assert event.invalid_user is True


@pytest.mark.parametrize(
    ("line", "user", "port"),
    [
        ("Oct 18 03:14:15 vps sshd[1]: Invalid user oracle from 203.0.113.5 port 40000", "oracle", 40000),
        ("Oct 18 03:14:15 vps sshd[1]: Invalid user oracle from 203.0.113.5", "oracle", None),  # старый OpenSSH
        ("Oct 18 03:14:15 vps sshd[1]: Invalid user  from 203.0.113.5 port 1", "", 1),  # пустой логин
        ("Oct 18 03:14:15 vps sshd[1]: Invalid user test user from 203.0.113.5 port 1", "test user", 1),
    ],
)
def test_invalid_user(line: str, user: str, port: Optional[int]) -> None:
    event = parse_one(line)
    assert event.event_type is EventType.INVALID_USER
    assert event.username == user
    assert event.port == port
    assert event.invalid_user is True


def test_accepted_publickey() -> None:
    event = parse_one(
        "Oct 18 09:00:01 vps sshd[77]: Accepted publickey for alice from 198.51.100.23 port 50022 ssh2: "
        "ED25519 SHA256:abcDEF123"
    )
    assert event.event_type is EventType.ACCEPTED
    assert event.username == "alice"
    assert event.auth_method == "publickey"


@pytest.mark.parametrize(
    "message",
    [
        "Did not receive identification string from 192.0.2.44 port 61000",
        "banner exchange: Connection from 192.0.2.44 port 61000: invalid format",
        "Unable to negotiate with 192.0.2.44 port 61000: no matching key exchange method found. Their offer: x",
    ],
)
def test_scanners(message: str) -> None:
    event = parse_one(f"Oct 18 03:14:15 vps sshd[1]: {message}")
    assert event.event_type is EventType.SCANNER
    assert event.ip == "192.0.2.44"
    assert event.username is None


def test_ipv6_is_normalized() -> None:
    event = parse_one("Oct 18 03:14:15 vps sshd[1]: Failed password for root from 2001:DB8:0:0::1 port 1 ssh2")
    assert event.ip == "2001:db8::1"


def test_ipv4_mapped_ipv6_becomes_ipv4() -> None:
    event = parse_one("Oct 18 03:14:15 vps sshd[1]: Failed password for root from ::ffff:203.0.113.5 port 1 ssh2")
    assert event.ip == "203.0.113.5"


def test_garbage_ip_is_not_an_event() -> None:
    stats = ParseStats()
    events = list(parse_lines(["Oct 18 03:14:15 vps sshd[1]: Invalid user x from 999.1.1.1 port 1"], stats=stats))
    assert events == []
    assert stats.unmatched == 1


def test_sshd_session_process_debian13() -> None:
    event = parse_one("Oct 18 03:14:15 vps sshd-session[1]: Failed password for root from 203.0.113.5 port 1 ssh2")
    assert event.event_type is EventType.FAILED_LOGIN


def test_iso_timestamp_with_offset() -> None:
    event = parse_one(
        "2026-10-18T03:14:15.123456+03:00 vps sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
    )
    assert event.timestamp == datetime(2026, 10, 18, 0, 14, 15, 123456, tzinfo=timezone.utc)


def test_journalctl_short_iso() -> None:
    # journalctl -o short-iso: смещение без двоеточия, без долей секунды
    event = parse_one("2026-10-18T03:14:15+0300 vps sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2")
    assert event.timestamp == datetime(2026, 10, 18, 0, 14, 15, tzinfo=timezone.utc)


def test_bsd_timestamp_uses_server_timezone() -> None:
    event = parse_one(
        "Oct  5 03:14:15 vps sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        tz="Europe/Moscow",
    )
    assert event.timestamp == datetime(2026, 10, 5, 0, 14, 15, tzinfo=timezone.utc)


def test_year_rollover() -> None:
    lines = [
        "Dec 31 23:59:58 vps sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        "Jan  1 00:00:03 vps sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
    ]
    first, second = parse_lines(lines, year=2025)
    assert first.timestamp.year == 2025
    assert second.timestamp.year == 2026


def test_message_repeated() -> None:
    line = "Oct 18 03:14:15 vps sshd[1]: message repeated 3 times: [ Failed password for root from 203.0.113.5 port 1 ssh2]"
    events = list(parse_lines([line], year=2026))
    assert len(events) == 3


def test_other_processes_and_noise_are_skipped() -> None:
    stats = ParseStats()
    lines = [
        "Oct 18 03:17:01 vps CRON[100]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        "Oct 18 03:17:01 vps sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
        "Oct 18 03:17:02 vps sshd[1]: Connection closed by authenticating user root 203.0.113.5 port 1 [preauth]",
        "Oct 18 03:17:02 vps sshd[1]: Something brand new from sshd",
        "это вообще не строка syslog",
    ]
    assert list(parse_lines(lines, year=2026, stats=stats)) == []
    assert stats.total_lines == 5
    assert stats.bad_header == 1
    assert stats.sshd_lines == 2
    assert stats.ignored == 1
    assert stats.unmatched == 1
    assert stats.unmatched_samples == ["Something brand new from sshd"]


def test_dataframe_columns_and_types() -> None:
    lines = [
        "Oct 18 03:14:15 vps sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        "Oct 18 03:14:16 vps sshd[1]: Did not receive identification string from 192.0.2.44",
    ]
    df = events_to_dataframe(parse_lines(lines, year=2026))
    assert list(df["event_type"]) == ["failed_login", "scanner"]
    assert str(df["timestamp"].dt.tz) == "UTC"
    assert df["port"].isna().tolist() == [False, True]


def test_empty_dataframe_has_columns() -> None:
    df = events_to_dataframe([])
    assert df.empty
    assert "timestamp" in df.columns and "ip" in df.columns


@pytest.mark.parametrize("fmt", ["bsd", "iso"])
def test_parser_finds_everything_generator_wrote(fmt: str, tmp_path: Path) -> None:
    tz = ZoneInfo("Europe/Moscow")
    # Период специально пересекает Новый год — проверяем угадывание года.
    log = generate(datetime(2025, 12, 28, tzinfo=tz), days=7, seed=1, fmt=fmt)
    path = tmp_path / "auth.log"
    path.write_text("\n".join(log.lines) + "\n", encoding="utf-8")

    stats = ParseStats()
    df = parse_auth_log(path, year=2025, tz=tz, stats=stats)

    found = Counter(EventType(value) for value in df["event_type"])
    assert found == log.expected
    assert stats.unmatched == 0
    assert set(log.attackers) <= set(df["ip"])
    assert df["timestamp"].min() >= datetime(2025, 12, 27, 21, tzinfo=timezone.utc)
    assert df["timestamp"].max() < datetime(2026, 1, 4, 21, tzinfo=timezone.utc)
