"""Детектор атак по DataFrame событий (из парсера или из базы).

Виды атак:
- брутфорс: не меньше N неудачных входов с одного IP за окно T;
- перебор логинов: не меньше K разных логинов с одного IP за окно T;
- повторные атаки: IP проявлял враждебность в D разных дней;
- успешный вход после атаки: Accepted с IP, который до этого много раз ошибался.
"""

from __future__ import annotations

from bisect import bisect_left
from collections import Counter
from datetime import datetime, timedelta
from typing import Hashable, Iterator, Optional, Sequence

import pandas as pd

from attack_analyzer.config import DetectorConfig
from attack_analyzer.models import EventType, Incident, IncidentKind

HOSTILE_EVENT_TYPES = [EventType.FAILED_LOGIN.value, EventType.INVALID_USER.value, EventType.SCANNER.value]
LOGIN_ATTEMPT_TYPES = [EventType.FAILED_LOGIN.value, EventType.INVALID_USER.value]

INCIDENT_COLUMNS = ["kind", "ip", "start", "end", "event_count", "distinct_usernames", "details"]


def _split_into_series(times: Sequence[datetime], window: timedelta) -> Iterator[slice]:
    # Любые события, попавшие в одно окно длины window, отстоят друг от друга
    # не больше чем на window. Значит, разрезав поток там, где пауза длиннее окна,
    # мы ни одно окно не разрежем, а каждая серия станет одним инцидентом.
    start = 0
    for index in range(1, len(times)):
        if times[index] - times[index - 1] > window:
            yield slice(start, index)
            start = index
    if times:
        yield slice(start, len(times))


def _max_distinct_in_window(times: Sequence[datetime], values: Sequence[Hashable], window: timedelta) -> int:
    # Скользящее окно двумя указателями: правый добавляет событие, левый
    # выбрасывает те, что старше window. Один проход, O(n).
    in_window: Counter[Hashable] = Counter()
    left = 0
    best = 0
    for right, moment in enumerate(times):
        in_window[values[right]] += 1
        while moment - times[left] > window:
            expired = values[left]
            in_window[expired] -= 1
            if in_window[expired] == 0:
                del in_window[expired]
            left += 1
        best = max(best, len(in_window))
    return best


def _known_usernames(usernames: Sequence[Optional[str]]) -> set[str]:
    return {name for name in usernames if isinstance(name, str)}


def _detect_in_windows(
    events: pd.DataFrame,
    kind: IncidentKind,
    window: timedelta,
    threshold: int,
    *,
    count_distinct_usernames: bool,
) -> list[Incident]:
    incidents = []
    for ip, group in events.groupby("ip", sort=False):
        times = [moment.to_pydatetime() for moment in group["timestamp"]]
        usernames = group["username"].tolist()
        for series in _split_into_series(times, window):
            series_times = times[series]
            series_usernames = usernames[series]
            # Для брутфорса считаем события: каждое получает уникальную метку.
            values = series_usernames if count_distinct_usernames else list(range(len(series_times)))
            peak = _max_distinct_in_window(series_times, values, window)
            if peak < threshold:
                continue
            unit = "разных логинов" if count_distinct_usernames else "попыток"
            incidents.append(
                Incident(
                    kind=kind,
                    ip=str(ip),
                    start=series_times[0],
                    end=series_times[-1],
                    event_count=len(series_times),
                    distinct_usernames=len(_known_usernames(series_usernames)),
                    details=f"до {peak} {unit} за {int(window.total_seconds() // 60)} мин",
                )
            )
    return incidents


def detect_bruteforce(events: pd.DataFrame, config: DetectorConfig) -> list[Incident]:
    """Принимает события, возвращает инциденты брутфорса."""
    failed = events[events["event_type"] == EventType.FAILED_LOGIN.value]
    rule = config.bruteforce
    return _detect_in_windows(
        failed, IncidentKind.BRUTEFORCE, rule.window, rule.threshold, count_distinct_usernames=False
    )


def detect_enumeration(events: pd.DataFrame, config: DetectorConfig) -> list[Incident]:
    """Принимает события, возвращает инциденты перебора логинов."""
    attempts = events[events["event_type"].isin(LOGIN_ATTEMPT_TYPES)]
    rule = config.enumeration
    return _detect_in_windows(
        attempts, IncidentKind.ENUMERATION, rule.window, rule.distinct_usernames, count_distinct_usernames=True
    )


def detect_repeated(events: pd.DataFrame, config: DetectorConfig) -> list[Incident]:
    """Принимает события, возвращает инциденты повторных атак (враждебность в разные дни)."""
    hostile = events[events["event_type"].isin(HOSTILE_EVENT_TYPES)]
    if hostile.empty:
        return []
    per_ip = (
        hostile.assign(day=hostile["timestamp"].dt.date)
        .groupby("ip")
        .agg(
            start=("timestamp", "min"),
            end=("timestamp", "max"),
            event_count=("timestamp", "size"),
            distinct_usernames=("username", "nunique"),
            active_days=("day", "nunique"),
        )
    )
    repeated = per_ip[per_ip["active_days"] >= config.repeated.min_active_days]
    return [
        Incident(
            kind=IncidentKind.REPEATED,
            ip=str(ip),
            start=row.start.to_pydatetime(),
            end=row.end.to_pydatetime(),
            event_count=int(row.event_count),
            distinct_usernames=int(row.distinct_usernames),
            details=f"активен {row.active_days} дн.",
        )
        for ip, row in repeated.iterrows()
    ]


def detect_success_after_attack(events: pd.DataFrame, config: DetectorConfig) -> list[Incident]:
    """Принимает события, возвращает успешные входы с IP, которые перед этим много раз ошибались."""
    rule = config.success_after_attack
    failed = events[events["event_type"] == EventType.FAILED_LOGIN.value]
    failed_by_ip = {
        ip: ([moment.to_pydatetime() for moment in group["timestamp"]], group["username"].tolist())
        for ip, group in failed.groupby("ip", sort=False)
    }

    incidents = []
    accepted = events[events["event_type"] == EventType.ACCEPTED.value]
    for login in accepted.itertuples(index=False):
        if login.ip not in failed_by_ip:
            continue
        failed_times, failed_usernames = failed_by_ip[login.ip]
        moment = login.timestamp.to_pydatetime()
        # Списки отсортированы по времени, поэтому границы окна ищем бинарным поиском.
        first = bisect_left(failed_times, moment - rule.lookback)
        last = bisect_left(failed_times, moment)
        failed_before = last - first
        if failed_before < rule.min_failed_before:
            continue
        incidents.append(
            Incident(
                kind=IncidentKind.SUCCESS_AFTER_ATTACK,
                ip=login.ip,
                start=failed_times[first],
                end=moment,
                event_count=failed_before + 1,
                distinct_usernames=len(_known_usernames(failed_usernames[first:last])),
                details=f"вход как {login.username} после {failed_before} неудачных попыток",
            )
        )
    return incidents


def detect(events: pd.DataFrame, config: Optional[DetectorConfig] = None) -> list[Incident]:
    """Принимает DataFrame событий и пороги, возвращает все инциденты, отсортированные по началу."""
    config = config or DetectorConfig()
    events = events.sort_values("timestamp", kind="stable")
    incidents = [
        *detect_bruteforce(events, config),
        *detect_enumeration(events, config),
        *detect_repeated(events, config),
        *detect_success_after_attack(events, config),
    ]
    return sorted(incidents, key=lambda incident: (incident.start, incident.ip, incident.kind.value))


def incidents_to_dataframe(incidents: Sequence[Incident]) -> pd.DataFrame:
    """Принимает инциденты, возвращает DataFrame с колонками INCIDENT_COLUMNS."""
    df = pd.DataFrame(
        [
            {
                "kind": incident.kind.value,
                "ip": incident.ip,
                "start": incident.start,
                "end": incident.end,
                "event_count": incident.event_count,
                "distinct_usernames": incident.distinct_usernames,
                "details": incident.details,
            }
            for incident in incidents
        ],
        columns=INCIDENT_COLUMNS,
    )
    df["start"] = pd.to_datetime(df["start"], utc=True)
    df["end"] = pd.to_datetime(df["end"], utc=True)
    return df
