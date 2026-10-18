"""Командная строка: `python -m attack_analyzer <команда>`.

    generate   сгенерировать тестовый auth.log
    parse      разобрать лог и показать сводку
    import     разобрать лог и сохранить события в базу
    attackers  показать топ атакующих IP из базы
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence
from zoneinfo import ZoneInfo

import pandas as pd

from attack_analyzer.generator import default_start, generate, write_log
from attack_analyzer.parsers import ParseStats, parse_auth_log
from attack_analyzer.storage import (
    count_events,
    database_url,
    make_engine,
    make_session_factory,
    refresh_attackers,
    save_events,
    top_attackers,
)


def _cmd_generate(args: argparse.Namespace) -> int:
    tz = ZoneInfo(args.tz)
    if args.start:
        start = datetime.strptime(args.start, "%Y-%m-%d").replace(tzinfo=tz)
    else:
        start = default_start(args.days, tz)
    log = generate(start, args.days, seed=args.seed, host=args.host, fmt=args.format)
    write_log(log, args.out)

    print(f"Записано {len(log.lines)} строк в {args.out}")
    print(f"Период: {start:%Y-%m-%d} + {args.days} сут., пояс {args.tz}, формат {args.format}")
    print("Ожидаемые события:", {event.value: n for event, n in sorted(log.expected.items())})
    scenarios = pd.Series(log.attackers).value_counts()
    print("Атакующих IP по сценариям:", scenarios.to_dict())
    return 0


def _print_parse_stats(stats: ParseStats, show_unmatched: int) -> None:
    print(
        f"Строк: {stats.total_lines}, из них sshd: {stats.sshd_lines}, "
        f"событий: {stats.events}, пропущено известных: {stats.ignored}, "
        f"нераспознано: {stats.unmatched}, без syslog-шапки: {stats.bad_header}"
    )
    if show_unmatched and stats.unmatched_samples:
        print("\nПримеры нераспознанных сообщений sshd:")
        for message in stats.unmatched_samples[:show_unmatched]:
            print("  ", message)


def _cmd_parse(args: argparse.Namespace) -> int:
    stats = ParseStats()
    df = parse_auth_log(args.path, year=args.year, tz=args.tz, stats=stats)
    _print_parse_stats(stats, args.show_unmatched)
    if df.empty:
        print("SSH-событий не найдено.")
        return 0

    print(f"\nПериод: {df['timestamp'].min()} — {df['timestamp'].max()} (UTC)")
    print("\nСобытия по типам:")
    print(df["event_type"].value_counts().to_string())
    print("\nТоп-10 IP по числу событий:")
    print(df["ip"].value_counts().head(10).to_string())
    print("\nТоп-10 логинов в неудачных попытках:")
    failed = df[df["event_type"] == "failed_login"]
    print(failed["username"].value_counts().head(10).to_string())

    if args.csv:
        df.to_csv(args.csv, index=False)
        print(f"\nDataFrame сохранён в {args.csv}")
    return 0


def _cmd_import(args: argparse.Namespace) -> int:
    stats = ParseStats()
    df = parse_auth_log(args.path, year=args.year, tz=args.tz, stats=stats)
    _print_parse_stats(stats, args.show_unmatched)

    session_factory = make_session_factory(make_engine(args.db))
    # begin(): один коммит на весь импорт; при ошибке не останется половины событий.
    with session_factory.begin() as session:
        added = save_events(session, df)
        attackers = refresh_attackers(session)
        total = count_events(session)

    print(f"\nБаза: {database_url(args.db)}")
    print(f"Добавлено событий: {added}, уже были в базе: {len(df) - added}, всего в базе: {total}")
    print(f"Атакующих IP: {attackers}")
    return 0


def _cmd_attackers(args: argparse.Namespace) -> int:
    session_factory = make_session_factory(make_engine(args.db))
    with session_factory() as session:
        attackers = top_attackers(session, args.limit)
    if not attackers:
        print("В базе нет атакующих IP. Сначала выполните import.")
        return 0

    table = pd.DataFrame(
        {
            "ip": attacker.ip,
            "failed": attacker.failed_logins,
            "invalid": attacker.invalid_users,
            "scanner": attacker.scanner_hits,
            "accepted": attacker.successful_logins,
            "logins": attacker.distinct_usernames,
            "first_seen": f"{attacker.first_seen:%Y-%m-%d %H:%M}",
            "last_seen": f"{attacker.last_seen:%Y-%m-%d %H:%M}",
        }
        for attacker in attackers
    )
    print(table.to_string(index=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Возвращает argparse-парсер со всеми подкомандами."""
    parser = argparse.ArgumentParser(
        prog="attack-analyzer",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    # Общие опции выносим в «родительские» парсеры, чтобы не повторять их в каждой команде.
    log_options = argparse.ArgumentParser(add_help=False)
    log_options.add_argument("path", help="путь к логу, *.gz или '-' для stdin")
    log_options.add_argument("--year", type=int, help="год для строк без года (по умолчанию угадывается)")
    log_options.add_argument("--tz", default="UTC", help="часовой пояс сервера для строк без смещения")
    log_options.add_argument(
        "--show-unmatched",
        type=int,
        default=5,
        metavar="N",
        help="показать N нераспознанных сообщений sshd (0 — не показывать)",
    )
    db_options = argparse.ArgumentParser(add_help=False)
    db_options.add_argument("--db", help="адрес базы SQLAlchemy (по умолчанию sqlite:///data/attacks.db)")

    gen = commands.add_parser("generate", help="сгенерировать тестовый auth.log")
    gen.add_argument("--out", type=Path, default=Path("data/generated/auth.log"))
    gen.add_argument("--days", type=int, default=14)
    gen.add_argument("--start", help="первый день, YYYY-MM-DD (по умолчанию: days суток назад)")
    gen.add_argument("--seed", type=int, default=42)
    gen.add_argument("--host", default="vps")
    gen.add_argument("--tz", default="Europe/Moscow", help="часовой пояс «сервера»")
    gen.add_argument(
        "--format",
        choices=("bsd", "iso"),
        default="bsd",
        help="bsd: 'Oct 18 03:14:15'; iso: '2026-10-18T03:14:15.123456+03:00'",
    )
    gen.set_defaults(handler=_cmd_generate)

    parse = commands.add_parser("parse", parents=[log_options], help="разобрать лог и показать сводку")
    parse.add_argument("--csv", type=Path, help="сохранить DataFrame в CSV")
    parse.set_defaults(handler=_cmd_parse)

    load = commands.add_parser("import", parents=[log_options, db_options], help="сохранить события лога в базу")
    load.set_defaults(handler=_cmd_import)

    top = commands.add_parser("attackers", parents=[db_options], help="топ атакующих IP из базы")
    top.add_argument("--limit", type=int, default=10)
    top.set_defaults(handler=_cmd_attackers)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Принимает аргументы командной строки (None — sys.argv), возвращает код выхода."""
    args = build_parser().parse_args(argv)
    return args.handler(args)
