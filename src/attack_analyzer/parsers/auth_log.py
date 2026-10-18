"""Парсер SSH-событий из auth.log и вывода journalctl.

Разбор в два шага: HEADER_RE отделяет syslog-шапку (время, хост, процесс)
от текста, затем текст сообщений sshd сверяется с MESSAGE_PATTERNS.

Форматы времени:
- классический syslog "Oct 18 03:14:15" (старый rsyslog, journalctl по умолчанию);
- ISO 8601 "2026-10-18T03:14:15.123456+03:00" (rsyslog в Debian 12+,
  journalctl -o short-iso).
"""

from __future__ import annotations

import gzip
import ipaddress
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Iterable, Iterator, Optional, TextIO, Union
from zoneinfo import ZoneInfo

import pandas as pd

from attack_analyzer.models import AuthEvent, EventType

HEADER_RE = re.compile(
    r"""
    ^
    (?:
        (?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}
                (?:\.\d+)?
                (?:Z|[+-]\d{2}:?\d{2})?)               # journalctl пишет +0300, rsyslog +03:00
      |
        (?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})   # день дополняется пробелом: "Oct  5"
    )
    \s+(?P<host>\S+)
    \s+(?P<process>[^\s\[:]+)
    (?:\[(?P<pid>\d+)\])?                              # у sudo и kernel PID нет
    :\s
    (?P<message>.*)
    $
    """,
    re.VERBOSE,
)

# OpenSSH 9.8+ (Debian 13) пишет сообщения от sshd-session, а не от sshd.
SSHD_PROCESSES = frozenset({"sshd", "sshd-session", "sshd-auth"})

# Нарочно широкий класс символов: подходит и IPv4, и IPv6. Проверять
# корректность адреса регуляркой громоздко, это делает ipaddress после совпадения.
IP = r"(?P<ip>[0-9A-Fa-f:.]+)"

# Ленивый .*?, а не \S+: боты присылают логины с пробелами и пустые
# ("Invalid user  from ..."). Обязательный хвост " from <ip>" не даёт
# ленивому квантификатору захватить лишнее.
USER = r"(?P<user>.*?)"

MESSAGE_PATTERNS: list[tuple[EventType, re.Pattern[str]]] = [
    (
        EventType.FAILED_LOGIN,
        # Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2
        re.compile(
            rf"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?{USER} "
            rf"from {IP} port (?P<port>\d+)"
        ),
    ),
    (
        EventType.INVALID_USER,
        # Порт в этом сообщении появился только в OpenSSH 7.5.
        re.compile(rf"^Invalid user {USER} from {IP}(?: port (?P<port>\d+))?$"),
    ),
    (
        EventType.ACCEPTED,
        # Accepted publickey for alice from 198.51.100.23 port 50022 ssh2: ED25519 SHA256:...
        re.compile(rf"^Accepted (?P<method>\S+) for {USER} from {IP} port (?P<port>\d+)"),
    ),
    (
        EventType.SCANNER,
        re.compile(rf"^Did not receive identification string from {IP}(?: port (?P<port>\d+))?"),
    ),
    (
        EventType.SCANNER,
        re.compile(rf"^banner exchange: Connection from {IP} port (?P<port>\d+): invalid format"),
    ),
    (
        EventType.SCANNER,
        re.compile(rf"^Unable to negotiate with {IP} port (?P<port>\d+): no matching"),
    ),
]

# rsyslog схлопывает одинаковые строки подряд в одну с счётчиком:
#   message repeated 3 times: [ Failed password for root from 1.2.3.4 port 22 ssh2]
REPEATED_RE = re.compile(r"^message repeated (?P<count>\d+) times: \[\s*(?P<inner>.*?)\s*\]$")

# Известные сообщения sshd, которые дублируют уже учтённые события или не про атаки.
# Отделяем их от действительно незнакомых, чтобы на настоящих логах
# ParseStats.unmatched показывал только то, чего парсер ещё не умеет.
IGNORED_PREFIXES = (
    "pam_unix(",
    "Connection closed by",
    "Connection reset by",
    "Disconnected from",
    "Disconnecting ",
    "Received disconnect from",
    "error: ",
    "fatal: ",
    "Server listening on",
    "Received signal",
    "PAM ",
    "Postponed ",
    "Timeout before authentication",
    "drop connection",
    "srclimit_penalise",
    "Starting session",
    "User child is on pid",
    "Close session",
    "Transferred:",
    "Read error from",
    "Exiting on signal",
)

# Свой словарь вместо strptime("%b"): %b зависит от локали системы.
_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

# datetime.fromisoformat в Python 3.9 не понимает "Z", "+0300"
# и долей секунды длиной не 3 и не 6 знаков, поэтому разбираем сами.
_ISO_PARTS_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|(?P<sign>[+-])(?P<hh>\d{2}):?(?P<mm>\d{2}))?$"
)

PathLike = Union[str, Path]
TimezoneLike = Union[str, tzinfo, None]


@dataclass
class ParseStats:
    """Счётчики разбора: сколько строк прочитано, понято и пропущено."""

    total_lines: int = 0
    bad_header: int = 0
    sshd_lines: int = 0
    events: int = 0
    ignored: int = 0
    unmatched: int = 0
    unmatched_samples: list[str] = field(default_factory=list)

    _MAX_SAMPLES = 20

    def add_unmatched(self, message: str) -> None:
        self.unmatched += 1
        if len(self.unmatched_samples) < self._MAX_SAMPLES:
            self.unmatched_samples.append(message)


class _YearResolver:
    """Восстанавливает год для времени без года ("Oct 18 03:14:15")."""

    def __init__(self, year: Optional[int], tz: tzinfo) -> None:
        self._year = year
        self._tz = tz
        self._previous: Optional[datetime] = None

    def resolve(self, value: str) -> datetime:
        month_name, day, clock = value.split()
        month = _MONTHS[month_name]
        hour, minute, second = (int(part) for part in clock.split(":"))
        if self._year is None:
            now = datetime.now(self._tz)
            # Месяц позже текущего возможен только у прошлогоднего лога.
            self._year = now.year if month <= now.month else now.year - 1

        moment = datetime(self._year, month, int(day), hour, minute, second, tzinfo=self._tz)
        # Скачок назад больше чем на сутки значит переход Dec 31 -> Jan 1.
        # Сутки запаса, потому что строки в логе бывают слегка не по порядку.
        if self._previous is not None and moment < self._previous - timedelta(days=1):
            self._year += 1
            moment = moment.replace(year=self._year)
        self._previous = moment
        return moment.astimezone(timezone.utc)


def _parse_iso(value: str, default_tz: tzinfo) -> datetime:
    parts = _ISO_PARTS_RE.match(value)
    if parts is None:
        raise ValueError(f"не ISO-время: {value!r}")
    moment = datetime.strptime(parts["base"], "%Y-%m-%dT%H:%M:%S")
    microseconds = int((parts["frac"] or "").ljust(6, "0")[:6])
    moment = moment.replace(microsecond=microseconds)

    if parts["tz"] is None:
        tz: tzinfo = default_tz
    elif parts["tz"] == "Z":
        tz = timezone.utc
    else:
        offset = timedelta(hours=int(parts["hh"]), minutes=int(parts["mm"]))
        tz = timezone(offset if parts["sign"] == "+" else -offset)
    return moment.replace(tzinfo=tz).astimezone(timezone.utc)


def _resolve_tz(tz: TimezoneLike) -> tzinfo:
    if tz is None:
        return timezone.utc
    if isinstance(tz, str):
        return ZoneInfo(tz)
    return tz


def _match_message(message: str) -> Optional[tuple[EventType, re.Match[str]]]:
    for event_type, pattern in MESSAGE_PATTERNS:
        match = pattern.match(message)
        if match is not None:
            return event_type, match
    return None


def _normalize_ip(raw_ip: str) -> Optional[str]:
    try:
        address = ipaddress.ip_address(raw_ip)
    except ValueError:
        return None
    # "::ffff:1.2.3.4" приходит, когда sshd слушает IPv6-сокет; это тот же IPv4-адрес.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def _build_event(
    event_type: EventType, match: re.Match[str], timestamp: datetime, host: str
) -> Optional[AuthEvent]:
    groups = match.groupdict()
    ip = _normalize_ip(groups["ip"])
    if ip is None:
        return None
    port = groups.get("port")
    return AuthEvent(
        timestamp=timestamp,
        event_type=event_type,
        ip=ip,
        host=host,
        username=groups.get("user"),
        port=int(port) if port else None,
        auth_method=groups.get("method"),
        invalid_user=event_type is EventType.INVALID_USER or bool(groups.get("invalid")),
    )


def parse_lines(
    lines: Iterable[str],
    *,
    year: Optional[int] = None,
    tz: TimezoneLike = None,
    stats: Optional[ParseStats] = None,
) -> Iterator[AuthEvent]:
    """Принимает строки лога, возвращает итератор SSH-событий.

    year — год для строк без года (None — угадать), tz — пояс сервера
    для строк без смещения (по умолчанию UTC), stats — заполняется счётчиками.
    Время событий всегда в UTC.
    """
    zone = _resolve_tz(tz)
    years = _YearResolver(year, zone)
    stats = stats if stats is not None else ParseStats()

    for raw_line in lines:
        stats.total_lines += 1
        header = HEADER_RE.match(raw_line.rstrip("\r\n"))
        if header is None:
            stats.bad_header += 1
            continue
        if header["process"] not in SSHD_PROCESSES:
            continue
        stats.sshd_lines += 1

        try:
            if header["iso"] is not None:
                timestamp = _parse_iso(header["iso"], zone)
            else:
                timestamp = years.resolve(header["bsd"])
        except ValueError:
            stats.bad_header += 1
            continue

        message = header["message"]
        repeat_count = 1
        repeated = REPEATED_RE.match(message)
        if repeated is not None:
            repeat_count = int(repeated["count"])
            message = repeated["inner"]

        found = _match_message(message)
        if found is None:
            if message.startswith(IGNORED_PREFIXES):
                stats.ignored += 1
            else:
                stats.add_unmatched(message)
            continue

        event = _build_event(found[0], found[1], timestamp, header["host"])
        if event is None:
            stats.add_unmatched(message)
            continue
        for _ in range(repeat_count):
            stats.events += 1
            yield event


def _open_text(path: PathLike) -> TextIO:
    if str(path) == "-":
        return sys.stdin
    path = Path(path)
    # errors="replace": боты шлют в логин произвольные байты, не-UTF-8 не должен ронять разбор.
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def parse_file(
    path: PathLike,
    *,
    year: Optional[int] = None,
    tz: TimezoneLike = None,
    stats: Optional[ParseStats] = None,
) -> Iterator[AuthEvent]:
    """Принимает путь к логу (*.gz или "-" для stdin), возвращает итератор событий."""
    handle = _open_text(path)
    try:
        yield from parse_lines(handle, year=year, tz=tz, stats=stats)
    finally:
        if handle is not sys.stdin:
            handle.close()


COLUMNS = [
    "timestamp",
    "event_type",
    "ip",
    "username",
    "port",
    "auth_method",
    "invalid_user",
    "host",
    "source",
]


def events_to_dataframe(events: Iterable[AuthEvent]) -> pd.DataFrame:
    """Принимает события, возвращает DataFrame с колонками COLUMNS, отсортированный по времени."""
    df = pd.DataFrame([asdict(event) for event in events], columns=COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    event_types = pd.CategoricalDtype([member.value for member in EventType])
    df["event_type"] = df["event_type"].map(lambda value: EventType(value).value).astype(event_types)
    # Int64 с большой буквы: целые с пропусками (у части сканеров порта нет).
    df["port"] = df["port"].astype("Int64")
    df["invalid_user"] = df["invalid_user"].astype(bool)
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


def parse_auth_log(
    path: PathLike,
    *,
    year: Optional[int] = None,
    tz: TimezoneLike = None,
    stats: Optional[ParseStats] = None,
) -> pd.DataFrame:
    """Принимает путь к auth.log, возвращает DataFrame событий (см. events_to_dataframe)."""
    return events_to_dataframe(parse_file(path, year=year, tz=tz, stats=stats))
