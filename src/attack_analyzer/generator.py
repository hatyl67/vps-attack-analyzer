"""Генератор реалистичного auth.log с атаками для разработки без настоящего сервера.

Сценарии:
- фон: CRON каждый час, sudo администратора;
- нормальные входы: alice (ключ, днём), deploy (ключ, каждую ночь из CI),
  bob (пароль, иногда с опечаткой);
- брутфорс: сотни "Failed password for root" с одного IP за минуты;
- перебор логинов: один IP пробует admin, test, oracle, ...;
- сканеры: соединились и ушли, не начав SSH;
- медленные атакующие: каждый день по 2-4 попытки, ниже порога брутфорса;
- взлом: подбор пароля bob, закончившийся "Accepted password" с IP атакующего.

Адреса взяты из диапазонов для документации (RFC 5737, RFC 3849): они
гарантированно не принадлежат реальным хостам.
"""

from __future__ import annotations

import base64
import random
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, tzinfo
from pathlib import Path
from typing import Optional

from attack_analyzer.models import EventType

MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# Пустой логин в словаре не ошибка: боты действительно его присылают.
USERNAME_WORDLIST = (
    "admin", "test", "user", "oracle", "postgres", "ubuntu", "git", "ftpuser",
    "guest", "support", "jenkins", "hadoop", "minecraft", "pi", "debian",
    "administrator", "mysql", "www", "nagios", "ts3", "steam", "odoo", "test1",
    "dev", "backup", "vagrant", "ansible", "elastic", "kafka", "sol", "validator",
    "es", "user1", "centos", "", "Admin",
)

ALICE_IPS = ("198.51.100.23", "198.51.100.77")
BOB_IP = "198.51.100.140"
CI_IP = "192.0.2.10"
USER_UIDS = {"alice": 1000, "bob": 1001, "deploy": 1002}
LOGIND_PID = 612

# Ночью ботов больше: так на тепловой карте «день недели x час» будет что увидеть.
ATTACK_HOUR_WEIGHTS = [6, 7, 8, 8, 7, 6, 5, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6]


@dataclass
class GeneratedLog:
    """Строки лога и правильные ответы для тестов парсера и детектора."""

    lines: list[str]
    expected: Counter[EventType]
    attackers: dict[str, str]  # ip -> сценарий


@dataclass(order=True)
class _Record:
    timestamp: datetime
    # Номер добавления: при одинаковом времени строки одного соединения не меняются местами.
    seq: int
    process: str = field(compare=False)
    pid: Optional[int] = field(compare=False)
    message: str = field(compare=False)


class _LogBuilder:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.records: list[_Record] = []
        self.expected: Counter[EventType] = Counter()
        self.attackers: dict[str, str] = {}
        self._last_session_id = 0

    def add(
        self,
        timestamp: datetime,
        process: str,
        message: str,
        pid: Optional[int] = None,
        event: Optional[EventType] = None,
    ) -> None:
        self.records.append(_Record(timestamp, len(self.records), process, pid, message))
        if event is not None:
            self.expected[event] += 1

    def random_pid(self) -> int:
        return self.rng.randint(1000, 999_999)

    def random_port(self) -> int:
        return self.rng.randint(1024, 65535)

    def pause(self, low_seconds: float, high_seconds: float) -> timedelta:
        return timedelta(seconds=self.rng.uniform(low_seconds, high_seconds))

    def key_fingerprint(self) -> str:
        raw = bytes(self.rng.getrandbits(8) for _ in range(32))
        return "SHA256:" + base64.b64encode(raw).decode().rstrip("=")

    def session(
        self,
        start: datetime,
        user: str,
        ip: str,
        method: str,
        duration: timedelta,
        typos: int = 0,
    ) -> None:
        pid, port, t = self.random_pid(), self.random_port(), start
        for _ in range(typos):
            self.add(t, "sshd", pam_auth_failure(ip, user), pid)
            t += self.pause(1.5, 3)
            failed = f"Failed password for {user} from {ip} port {port} ssh2"
            self.add(t, "sshd", failed, pid, EventType.FAILED_LOGIN)
            t += self.pause(3, 10)

        accepted = f"Accepted {method} for {user} from {ip} port {port} ssh2"
        if method == "publickey":
            accepted += f": ED25519 {self.key_fingerprint()}"
        self.add(t, "sshd", accepted, pid, EventType.ACCEPTED)
        opened = f"pam_unix(sshd:session): session opened for user {user}(uid={USER_UIDS[user]}) by (uid=0)"
        self.add(t, "sshd", opened, pid)
        self._last_session_id += 1
        session_id = self._last_session_id
        self.add(t + self.pause(0.01, 0.1), "systemd-logind", f"New session {session_id} of user {user}.", LOGIND_PID)

        end = t + duration
        self.add(end, "sshd", f"Received disconnect from {ip} port {port}:11: disconnected by user", pid)
        self.add(end, "sshd", f"Disconnected from user {user} {ip} port {port}", pid)
        self.add(end, "sshd", f"pam_unix(sshd:session): session closed for user {user}", pid)
        logged_out = f"Session {session_id} logged out. Waiting for processes to exit."
        self.add(end + self.pause(0.01, 0.1), "systemd-logind", logged_out, LOGIND_PID)
        self.add(end + self.pause(0.1, 0.3), "systemd-logind", f"Removed session {session_id}.", LOGIND_PID)

    def cron(self, t: datetime) -> None:
        pid = self.random_pid()
        self.add(t, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", pid)
        self.add(t, "CRON", "pam_unix(cron:session): session closed for user root", pid)

    def sudo(self, t: datetime, command: str) -> None:
        self.add(t, "sudo", f"   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND={command}")
        pid = self.random_pid()
        self.add(t, "sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)", pid)
        self.add(t + self.pause(1, 30), "sudo", "pam_unix(sudo:session): session closed for user root", pid)

    def bruteforce(self, ip: str, start: datetime, attempts: int, user: str = "root") -> datetime:
        """Подбор пароля к одному логину; возвращает время окончания атаки."""
        t, done = start, 0
        while done < attempts:
            pid, port = self.random_pid(), self.random_port()
            # Боты делают 1-3 попытки на соединение, а не все MaxAuthTries=6:
            # так меньше шанс попасть под "maximum authentication attempts exceeded".
            per_connection = min(self.rng.randint(1, 3), attempts - done)
            for _ in range(per_connection):
                self.add(t, "sshd", pam_auth_failure(ip, user), pid)
                t += self.pause(1.5, 2.5)
                failed = f"Failed password for {user} from {ip} port {port} ssh2"
                self.add(t, "sshd", failed, pid, EventType.FAILED_LOGIN)
                t += self.pause(0.2, 1.5)
            closed = f"Connection closed by authenticating user {user} {ip} port {port} [preauth]"
            self.add(t, "sshd", closed, pid)
            done += per_connection
            t += self.pause(0.1, 3)
        return t

    def enumeration(self, ip: str, start: datetime, logins_to_try: int) -> None:
        t = start
        logins = self.rng.sample(USERNAME_WORDLIST, k=min(logins_to_try, len(USERNAME_WORDLIST)))
        for user in logins:
            pid, port = self.random_pid(), self.random_port()
            self.add(t, "sshd", f"Invalid user {user} from {ip} port {port}", pid, EventType.INVALID_USER)
            # Часть ботов уходит, не пробуя пароль: на серверах с PasswordAuthentication no
            # после "Invalid user" бывает только "Connection closed".
            if self.rng.random() < 0.8:
                self.add(t, "sshd", "pam_unix(sshd:auth): check pass; user unknown", pid)
                self.add(t, "sshd", pam_auth_failure(ip), pid)
                t += self.pause(1.5, 2.5)
                failed = f"Failed password for invalid user {user} from {ip} port {port} ssh2"
                self.add(t, "sshd", failed, pid, EventType.FAILED_LOGIN)
                self.add(t, "sshd", f"Received disconnect from {ip} port {port}:11: Bye Bye [preauth]", pid)
                self.add(t, "sshd", f"Disconnected from invalid user {user} {ip} port {port} [preauth]", pid)
            else:
                self.add(t, "sshd", f"Connection closed by invalid user {user} {ip} port {port} [preauth]", pid)
            t += self.pause(0.5, 15)

    def scan(self, ip: str, t: datetime) -> None:
        port = self.random_port()
        message = self.rng.choice(
            (
                f"Did not receive identification string from {ip} port {port}",
                f"banner exchange: Connection from {ip} port {port}: invalid format",
                f"Unable to negotiate with {ip} port {port}: no matching key exchange method found. "
                "Their offer: diffie-hellman-group1-sha1,diffie-hellman-group14-sha1 [preauth]",
            )
        )
        self.add(t, "sshd", message, self.random_pid(), EventType.SCANNER)


def pam_auth_failure(ip: str, user: Optional[str] = None) -> str:
    message = f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}"
    # Двойной пробел перед user= есть в настоящем выводе pam_unix.
    return f"{message}  user={user}" if user is not None else message


def _new_attacker_ip(rng: random.Random, used_ips: set[str]) -> str:
    while True:
        if rng.random() < 0.1:
            ip = f"2001:db8:{rng.randint(1, 0xFFFF):x}::{rng.randint(1, 0xFFFF):x}"
        else:
            # С .20: младшие адреса 192.0.2.x заняты легитимным CI.
            ip = f"{rng.choice(('203.0.113', '192.0.2'))}.{rng.randint(20, 254)}"
        if ip not in used_ips:
            used_ips.add(ip)
            return ip


def _attack_time(rng: random.Random, day: datetime) -> datetime:
    hour = rng.choices(range(24), weights=ATTACK_HOUR_WEIGHTS)[0]
    return _time_between(rng, day, hour, hour)


def _time_between(rng: random.Random, day: datetime, first_hour: int, last_hour: int) -> datetime:
    return day.replace(
        hour=rng.randint(first_hour, last_hour),
        minute=rng.randrange(60),
        second=rng.randrange(60),
        microsecond=rng.randrange(1_000_000),
    )


def _add_background(log: _LogBuilder, day: datetime) -> None:
    for hour in range(24):
        log.cron(day.replace(hour=hour, minute=17, second=1))
    commands = ("/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u ssh")
    for _ in range(log.rng.randint(0, 3)):
        log.sudo(_time_between(log.rng, day, 9, 22), log.rng.choice(commands))


def _add_legit_logins(log: _LogBuilder, day: datetime) -> None:
    rng = log.rng
    for _ in range(rng.randint(1, 3)):
        start = _time_between(rng, day, 9, 22)
        log.session(start, "alice", rng.choice(ALICE_IPS), "publickey", log.pause(60, 3 * 3600))
    deploy_start = day.replace(hour=3, minute=0, second=rng.randint(1, 20))
    log.session(deploy_start, "deploy", CI_IP, "publickey", log.pause(15, 90))
    if rng.random() < 0.6:
        typos = 1 if rng.random() < 0.3 else 0
        log.session(_time_between(rng, day, 12, 21), "bob", BOB_IP, "password", log.pause(120, 1800), typos)


def _add_daily_attacks(
    log: _LogBuilder, day: datetime, used_ips: set[str], scanner_pool: list[str], slow_ips: list[str]
) -> None:
    rng = log.rng
    for _ in range(rng.randint(1, 2)):
        ip = _new_attacker_ip(rng, used_ips)
        log.attackers[ip] = "bruteforce"
        log.bruteforce(ip, _attack_time(rng, day), rng.randint(40, 300))

    for _ in range(rng.randint(0, 2)):
        ip = _new_attacker_ip(rng, used_ips)
        log.attackers[ip] = "enumeration"
        log.enumeration(ip, _attack_time(rng, day), rng.randint(10, 30))

    for _ in range(rng.randint(10, 30)):
        ip = rng.choice(scanner_pool)
        log.attackers.setdefault(ip, "scanner")
        log.scan(ip, _attack_time(rng, day))

    for ip in slow_ips:
        if rng.random() < 0.8:
            log.bruteforce(ip, _attack_time(rng, day), rng.randint(2, 4), user=rng.choice(("root", "bob")))


def _add_compromise(log: _LogBuilder, day: datetime, used_ips: set[str]) -> None:
    ip = _new_attacker_ip(log.rng, used_ips)
    log.attackers[ip] = "compromise"
    attack_end = log.bruteforce(ip, day.replace(hour=4, minute=12, second=5), 40, user="bob")
    log.session(attack_end + log.pause(1, 3), "bob", ip, "password", log.pause(30, 300))


def generate(
    start: datetime,
    days: int = 7,
    *,
    seed: int = 42,
    host: str = "vps",
    fmt: str = "bsd",
) -> GeneratedLog:
    """Принимает aware-datetime первого дня, число суток и формат времени ("bsd" или "iso").

    Возвращает GeneratedLog; при одинаковом seed результат одинаковый.
    """
    if start.tzinfo is None:
        raise ValueError("start должен быть timezone-aware (например, с ZoneInfo)")
    if fmt not in ("bsd", "iso"):
        raise ValueError("fmt должен быть 'bsd' или 'iso'")

    rng = random.Random(seed)
    log = _LogBuilder(rng)
    used_ips = set(ALICE_IPS) | {BOB_IP, CI_IP}
    slow_ips = [_new_attacker_ip(rng, used_ips) for _ in range(3)]
    for ip in slow_ips:
        log.attackers[ip] = "slow"
    # Пул меньше числа сканирований: часть сканеров возвращается, как в жизни.
    scanner_pool = [_new_attacker_ip(rng, used_ips) for _ in range(max(10, days * 6))]

    first_day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    for day_index in range(days):
        day = first_day + timedelta(days=day_index)
        _add_background(log, day)
        _add_legit_logins(log, day)
        _add_daily_attacks(log, day, used_ips, scanner_pool, slow_ips)
        if day_index == days // 2:
            _add_compromise(log, day, used_ips)

    log.records.sort()
    lines = [_format_line(record, host, fmt) for record in log.records]
    return GeneratedLog(lines=lines, expected=log.expected, attackers=log.attackers)


def _format_line(record: _Record, host: str, fmt: str) -> str:
    t = record.timestamp
    if fmt == "iso":
        stamp = t.isoformat(timespec="microseconds")
    else:
        stamp = f"{MONTH_NAMES[t.month - 1]} {t.day:>2} {t:%H:%M:%S}"
    process = f"{record.process}[{record.pid}]" if record.pid is not None else record.process
    return f"{stamp} {host} {process}: {record.message}"


def write_log(log: GeneratedLog, path: Path) -> None:
    """Записывает строки лога в файл, создавая папки."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unix-переводы строк даже на Windows: файл должен выглядеть как настоящий auth.log.
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for line in log.lines:
            handle.write(line + "\n")


def default_start(days: int, tz: tzinfo) -> datetime:
    """Возвращает полночь `days` суток назад в поясе tz, чтобы лог заканчивался сегодня."""
    today = datetime.now(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    return today - timedelta(days=days)
