"""Тесты графиков: картинки сохраняются, данные на графиках совпадают с событиями."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import pytest
from matplotlib.patches import Rectangle

from attack_analyzer import charts
from attack_analyzer.generator import generate
from attack_analyzer.parsers import events_to_dataframe, parse_lines

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@pytest.fixture(scope="module")
def events() -> pd.DataFrame:
    log = generate(datetime(2026, 10, 5, tzinfo=ZoneInfo("Europe/Moscow")), days=3, seed=5)
    return events_to_dataframe(parse_lines(log.lines, year=2026, tz="Europe/Moscow"))


def hostile_count(events: pd.DataFrame) -> int:
    return int(events["event_type"].isin(charts.HOSTILE_TYPES).sum())


def bar_heights(figure) -> float:
    axes = figure.axes[0]
    return sum(patch.get_height() for patch in axes.patches if isinstance(patch, Rectangle))


@pytest.mark.parametrize("bucket", ["day", "hour"])
def test_timeline_bars_sum_to_hostile_events(events: pd.DataFrame, bucket: str) -> None:
    figure = charts.plot_timeline(events, bucket, "Europe/Moscow")
    assert bar_heights(figure) == hostile_count(events)


def test_heatmap_sums_to_hostile_events(events: pd.DataFrame) -> None:
    figure = charts.plot_heatmap(events, "Europe/Moscow")
    mesh = figure.axes[0].collections[0]
    assert mesh.get_array().sum() == hostile_count(events)


def test_top_ips_sorted_from_top(events: pd.DataFrame) -> None:
    figure = charts.plot_top_ips(events, limit=5)
    axes = figure.axes[0]
    widths = [patch.get_width() for patch in axes.patches]
    # barh рисует снизу вверх, поэтому снизу вверх значения должны расти.
    assert widths == sorted(widths)
    assert len(widths) == 5


def test_top_usernames_marks_empty_login(events: pd.DataFrame) -> None:
    figure = charts.plot_top_usernames(events, limit=50)
    labels = [label.get_text() for label in figure.axes[0].get_yticklabels()]
    assert labels[-1] == "root"
    assert "" not in labels


def test_empty_events_do_not_crash(tmp_path: Path) -> None:
    paths = charts.save_charts(events_to_dataframe([]), tmp_path)
    assert len(paths) == 4


def test_save_charts_writes_png_files(events: pd.DataFrame, tmp_path: Path) -> None:
    paths = charts.save_charts(events, tmp_path / "out", tz="Europe/Moscow")
    assert [path.name for path in paths] == ["timeline.png", "heatmap.png", "top_ips.png", "top_usernames.png"]
    for path in paths:
        assert path.read_bytes().startswith(PNG_SIGNATURE)
