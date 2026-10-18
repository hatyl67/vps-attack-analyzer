"""Командная строка: `python -m attack_analyzer <команда>`.

    generate   сгенерировать тестовый auth.log
    parse      разобрать лог и показать сводку
    import     разобрать лог, сохранить события в базу и найти атаки
    detect     заново найти атаки по событиям в базе (после смены порогов)
    attackers  показать топ атакующих IP из базы
    charts     нарисовать графики атак в PNG
    serve      запустить HTTP API
    dashboard  запустить дашборд (нужен работающий API)
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence
from zoneinfo import ZoneInfo

import pandas as pd
from sqlalchemy.orm import Session, sessionmaker

from attack_analyzer.config import ConfigError, DetectorConfig, load_settings
from attack_analyzer.detector import detect, incidents_to_dataframe
from attack_analyzer.generator import default_start, generate, write_log
from attack_analyzer.models import Incident
from attack_analyzer.parsers import ParseStats, parse_auth_log
from attack_analyzer.storage import (
    count_events,
    database_url,
    make_engine,
    make_session_factory,
    read_events,
    refresh_attackers,
    replace_incidents,
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


def _open_database(args: argparse.Namespace) -> tuple[str, sessionmaker[Session], DetectorConfig]:
    settings = load_settings(args.config)
    # Приоритет адреса базы: --db, затем ATTACK_ANALYZER_DB, затем config.toml.
    url = database_url(args.db or settings.database_url)
    return url, make_session_factory(make_engine(url)), settings.detector


def _run_detector(session: Session, config: DetectorConfig) -> list[Incident]:
    incidents = detect(read_events(session), config)
    replace_incidents(session, incidents)
    return incidents


def _print_incidents(incidents: Sequence[Incident], limit: int) -> None:
    if not incidents:
        print("Атак не найдено.")
        return
    table = incidents_to_dataframe(incidents)
    print("Инциденты по видам:")
    print(table["kind"].value_counts().to_string())
    print(f"\nПоследние {min(limit, len(table))}:")
    recent = table.sort_values("start", ascending=False).head(limit)
    recent = recent.assign(start=recent["start"].dt.strftime("%Y-%m-%d %H:%M"))
    print(recent[["start", "kind", "ip", "event_count", "details"]].to_string(index=False))


def _cmd_import(args: argparse.Namespace) -> int:
    stats = ParseStats()
    df = parse_auth_log(args.path, year=args.year, tz=args.tz, stats=stats)
    _print_parse_stats(stats, args.show_unmatched)

    url, session_factory, detector_config = _open_database(args)
    # begin(): один коммит на весь импорт; при ошибке не останется половины событий.
    with session_factory.begin() as session:
        added = save_events(session, df)
        attackers = refresh_attackers(session)
        total = count_events(session)
        incidents = _run_detector(session, detector_config)

    print(f"\nБаза: {url}")
    print(f"Добавлено событий: {added}, уже были в базе: {len(df) - added}, всего в базе: {total}")
    print(f"Атакующих IP: {attackers}\n")
    _print_incidents(incidents, args.limit)
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    _, session_factory, detector_config = _open_database(args)
    with session_factory.begin() as session:
        incidents = _run_detector(session, detector_config)
    _print_incidents(incidents, args.limit)
    return 0


def _cmd_attackers(args: argparse.Namespace) -> int:
    _, session_factory, _ = _open_database(args)
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


def _cmd_charts(args: argparse.Namespace) -> int:
    # Импорт внутри команды: matplotlib загружается заметно дольше остальных модулей.
    from attack_analyzer.charts import save_charts

    _, session_factory, _ = _open_database(args)
    with session_factory() as session:
        events = read_events(session)
    if events.empty:
        print("В базе нет событий. Сначала выполните import.")
        return 1
    for path in save_charts(events, args.out, tz=args.tz, bucket=args.bucket, limit=args.limit):
        print(f"Сохранён {path}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    # Импорт внутри команды: остальным командам не нужно тянуть FastAPI и uvicorn.
    import uvicorn

    from attack_analyzer.api import create_app

    uvicorn.run(create_app(args.db, args.config), host=args.host, port=args.port)
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    from shiny import run_app

    from attack_analyzer.dashboard.app import create_dashboard

    run_app(create_dashboard(args.api, args.tz), host=args.host, port=args.port, launch_browser=False)
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
    db_options.add_argument("--db", help="адрес базы SQLAlchemy (по умолчанию из config.toml)")
    db_options.add_argument("--config", type=Path, help="файл настроек (по умолчанию ./config.toml)")
    incident_options = argparse.ArgumentParser(add_help=False)
    incident_options.add_argument("--limit", type=int, default=15, help="сколько последних инцидентов показать")

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

    load = commands.add_parser(
        "import", parents=[log_options, db_options, incident_options], help="сохранить события лога в базу"
    )
    load.set_defaults(handler=_cmd_import)

    find = commands.add_parser("detect", parents=[db_options, incident_options], help="найти атаки заново")
    find.set_defaults(handler=_cmd_detect)

    top = commands.add_parser("attackers", parents=[db_options], help="топ атакующих IP из базы")
    top.add_argument("--limit", type=int, default=10)
    top.set_defaults(handler=_cmd_attackers)

    charts = commands.add_parser("charts", parents=[db_options], help="нарисовать графики атак в PNG")
    charts.add_argument("--out", type=Path, default=Path("data/charts"))
    charts.add_argument("--tz", default="UTC", help="пояс для подписей времени, например Europe/Moscow")
    charts.add_argument("--bucket", choices=("hour", "day"), default="day")
    charts.add_argument("--limit", type=int, default=10, help="размер топов IP и логинов")
    charts.set_defaults(handler=_cmd_charts)

    serve = commands.add_parser("serve", parents=[db_options], help="запустить HTTP API")
    # 127.0.0.1 по умолчанию: в API IP-адреса и логины, наружу его открывать незачем.
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(handler=_cmd_serve)

    board = commands.add_parser("dashboard", help="запустить дашборд Shiny")
    board.add_argument("--api", help="адрес API (по умолчанию ATTACK_ANALYZER_API или http://127.0.0.1:8000)")
    board.add_argument("--tz", default="UTC", help="часовой пояс, выбранный при открытии")
    board.add_argument("--host", default="127.0.0.1")
    board.add_argument("--port", type=int, default=8001)
    board.set_defaults(handler=_cmd_dashboard)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Принимает аргументы командной строки (None — sys.argv), возвращает код выхода."""
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except ConfigError as error:
        print(f"Ошибка в настройках: {error}", file=sys.stderr)
        return 2
