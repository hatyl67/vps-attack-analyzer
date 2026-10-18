"""Командная строка: `python -m attack_analyzer <команда>`.

    generate  — сгенерировать тестовый auth.log
    parse     — разобрать лог и показать сводку
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


def _cmd_parse(args: argparse.Namespace) -> int:
    stats = ParseStats()
    df = parse_auth_log(args.path, year=args.year, tz=args.tz, stats=stats)

    print(f"Строк: {stats.total_lines}, из них sshd: {stats.sshd_lines}, "
          f"событий: {stats.events}, пропущено известных: {stats.ignored}, "
          f"нераспознано: {stats.unmatched}, без syslog-шапки: {stats.bad_header}")
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

    if args.show_unmatched and stats.unmatched_samples:
        print("\nПримеры нераспознанных сообщений sshd:")
        for message in stats.unmatched_samples[: args.show_unmatched]:
            print("  ", message)
    if args.csv:
        df.to_csv(args.csv, index=False)
        print(f"\nDataFrame сохранён в {args.csv}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Возвращает argparse-парсер с подкомандами generate и parse."""
    parser = argparse.ArgumentParser(prog="attack-analyzer", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    gen = commands.add_parser("generate", help="сгенерировать тестовый auth.log")
    gen.add_argument("--out", type=Path, default=Path("data/generated/auth.log"))
    gen.add_argument("--days", type=int, default=14)
    gen.add_argument("--start", help="первый день, YYYY-MM-DD (по умолчанию: days суток назад)")
    gen.add_argument("--seed", type=int, default=42)
    gen.add_argument("--host", default="vps")
    gen.add_argument("--tz", default="Europe/Moscow", help="часовой пояс «сервера»")
    gen.add_argument("--format", choices=("bsd", "iso"), default="bsd",
                     help="bsd: 'Oct 18 03:14:15'; iso: '2026-10-18T03:14:15.123456+03:00'")
    gen.set_defaults(handler=_cmd_generate)

    prs = commands.add_parser("parse", help="разобрать auth.log / вывод journalctl")
    prs.add_argument("path", help="путь к логу, *.gz или '-' для stdin")
    prs.add_argument("--year", type=int, help="год для строк без года (по умолчанию угадывается)")
    prs.add_argument("--tz", default="UTC", help="часовой пояс сервера для строк без смещения")
    prs.add_argument("--csv", type=Path, help="сохранить DataFrame в CSV")
    prs.add_argument("--show-unmatched", type=int, default=5, metavar="N",
                     help="показать N нераспознанных сообщений sshd (0 — не показывать)")
    prs.set_defaults(handler=_cmd_parse)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Принимает аргументы командной строки (None — sys.argv), возвращает код выхода."""
    args = build_parser().parse_args(argv)
    return args.handler(args)
