"""Графики атак на matplotlib: по времени, тепловая карта, топ IP, топ логинов.

Используется объектный API (Figure и Axes) без pyplot: pyplot хранит
глобальное «текущее окно» и пытается открыть GUI, а здесь нужны только
картинки в файлах, в том числе из API и тестов.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union
from zoneinfo import ZoneInfo

import pandas as pd
from matplotlib.axes import Axes
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.figure import Figure

from attack_analyzer import analytics
from attack_analyzer.models import EventType

TimezoneName = Union[str, ZoneInfo]

SURFACE = "#fcfcfb"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#e4e3df"

# Цвета типов закреплены за типом, а не за местом в легенде: на всех графиках
# неудачный вход синий, даже если на графике нет других типов. Первые три слота
# палитры проверены на различимость при дальтонизме все со всеми.
EVENT_COLORS = {
    EventType.FAILED_LOGIN.value: "#2a78d6",
    EventType.INVALID_USER.value: "#eb6834",
    EventType.SCANNER.value: "#1baf7a",
}
EVENT_LABELS = {
    EventType.FAILED_LOGIN.value: "Неудачный вход",
    EventType.INVALID_USER.value: "Несуществующий логин",
    EventType.SCANNER.value: "Сканер",
}
BAR_COLOR = EVENT_COLORS[EventType.FAILED_LOGIN.value]

# Последовательная шкала одного оттенка от светлого к тёмному: больше событий —
# темнее. Радуга здесь врала бы: её цвета не упорядочены для глаза.
HEATMAP_CMAP = LinearSegmentedColormap.from_list(
    "attacks",
    ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"],
)

HOSTILE_TYPES = list(EVENT_COLORS)


def _new_axes(width: float, height: float) -> tuple[Figure, Axes]:
    figure = Figure(figsize=(width, height), dpi=150, facecolor=SURFACE, layout="constrained")
    axes = figure.add_subplot()
    axes.set_facecolor(SURFACE)
    for side in ("top", "right", "left"):
        axes.spines[side].set_visible(False)
    axes.spines["bottom"].set_color(GRID)
    axes.tick_params(colors=TEXT_SECONDARY, labelsize=8, length=0)
    axes.set_axisbelow(True)
    return figure, axes


def _title(axes: Axes, title: str, subtitle: str) -> None:
    axes.set_title(f"{title}\n", loc="left", fontsize=11, color=TEXT_PRIMARY, fontweight="bold")
    axes.text(0, 1.02, subtitle, transform=axes.transAxes, fontsize=8, color=TEXT_SECONDARY, va="bottom")


def _no_data(axes: Axes) -> None:
    axes.text(0.5, 0.5, "Нет данных за период", transform=axes.transAxes, ha="center", color=TEXT_SECONDARY)
    axes.set_xticks([])
    axes.set_yticks([])


def plot_timeline(events: pd.DataFrame, bucket: str = "day", tz: TimezoneName = "UTC") -> Figure:
    """Принимает события, корзину ("hour"/"day") и пояс; возвращает столбчатый график атак по типам."""
    figure, axes = _new_axes(9, 3.6)
    unit = "дням" if bucket == "day" else "часам"
    _title(axes, f"Атаки по {unit}", f"Враждебные события по типам, время {tz}")
    hostile = events[events["event_type"].isin(HOSTILE_TYPES)]
    if hostile.empty:
        _no_data(axes)
        return figure

    table = analytics.timeline(hostile, bucket, tz)
    # Столбцы ставим по порядковым номерам, а не по датам: так подпись дня
    # стоит точно под своим столбцом, а не на границе суток.
    positions = list(range(len(table)))
    # При сотнях узких столбцов обводка съела бы их целиком.
    gap_width = 0.8 if len(table) <= 60 else 0
    bottom = pd.Series(0, index=table.index)
    for event_type in HOSTILE_TYPES:
        axes.bar(
            positions,
            table[event_type],
            width=0.8,
            bottom=bottom,
            color=EVENT_COLORS[event_type],
            # Тонкая обводка цветом фона даёт зазор между сегментами стопки.
            edgecolor=SURFACE,
            linewidth=gap_width,
            label=EVENT_LABELS[event_type],
        )
        bottom = bottom + table[event_type]

    if bucket == "day":
        step = max(1, len(table) // 14)
        ticks = positions[::step]
        labels = [f"{start:%d.%m}" for start in table.index[::step]]
    else:
        midnights = [index for index, start in enumerate(table.index) if start.hour == 0]
        step = max(1, len(midnights) // 14)
        ticks = midnights[::step]
        labels = [f"{table.index[index]:%d.%m}" for index in ticks]
    axes.set_xticks(ticks, labels)
    axes.set_xlim(-0.6, len(table) - 0.4)

    axes.yaxis.grid(True, color=GRID, linewidth=0.8)
    axes.set_ylabel("событий", color=TEXT_SECONDARY, fontsize=8)
    axes.legend(loc="upper left", frameon=False, fontsize=8, ncols=3, labelcolor=TEXT_PRIMARY)
    axes.set_ylim(0, bottom.max() * 1.15)
    return figure


def plot_heatmap(events: pd.DataFrame, tz: TimezoneName = "UTC") -> Figure:
    """Принимает события и пояс, возвращает тепловую карту «день недели x час» по враждебным событиям."""
    figure, axes = _new_axes(9, 3.4)
    _title(axes, "Когда атакуют", f"Враждебные события по дням недели и часам, время {tz}")
    hostile = events[events["event_type"].isin(HOSTILE_TYPES)]
    if hostile.empty:
        _no_data(axes)
        return figure

    table = analytics.weekday_hour_heatmap(hostile, tz)
    mesh = axes.pcolormesh(table.values, cmap=HEATMAP_CMAP, edgecolors=SURFACE, linewidth=1.5)
    axes.invert_yaxis()
    axes.set_yticks([row + 0.5 for row in range(7)], list(table.index))
    axes.set_xticks([hour + 0.5 for hour in range(0, 24, 2)], [f"{hour:02d}" for hour in range(0, 24, 2)])
    axes.spines["bottom"].set_visible(False)
    colorbar = figure.colorbar(mesh, ax=axes, pad=0.01, aspect=30)
    colorbar.outline.set_visible(False)
    colorbar.ax.tick_params(colors=TEXT_SECONDARY, labelsize=8, length=0)
    colorbar.set_label("событий", color=TEXT_SECONDARY, fontsize=8)
    return figure


def _plot_ranking(series: pd.Series, title: str, subtitle: str, value_label: str) -> Figure:
    figure, axes = _new_axes(7, 0.35 * max(len(series), 3) + 1.2)
    _title(axes, title, subtitle)
    if series.empty:
        _no_data(axes)
        return figure

    # Сверху самое большое значение: barh рисует снизу вверх, поэтому разворачиваем.
    ordered = series.iloc[::-1]
    labels = [str(value) if str(value) else "(пустой)" for value in ordered.index]
    bars = axes.barh(labels, ordered.values, color=BAR_COLOR, height=0.6)
    axes.bar_label(bars, padding=3, fontsize=8, color=TEXT_SECONDARY)
    axes.xaxis.grid(True, color=GRID, linewidth=0.8)
    axes.spines["bottom"].set_visible(False)
    axes.tick_params(axis="y", labelcolor=TEXT_PRIMARY)
    axes.set_xlabel(value_label, color=TEXT_SECONDARY, fontsize=8)
    axes.set_xlim(0, ordered.max() * 1.12)
    return figure


def plot_top_ips(events: pd.DataFrame, limit: int = 10) -> Figure:
    """Принимает события, возвращает горизонтальный рейтинг IP по числу враждебных событий."""
    hostile = events[events["event_type"].isin(HOSTILE_TYPES)]
    counts = analytics.top_values(hostile, "ip", limit)
    return _plot_ranking(counts, f"Топ-{limit} атакующих IP", "Неудачные входы, неверные логины и сканирование", "событий")


def plot_top_usernames(events: pd.DataFrame, limit: int = 10) -> Figure:
    """Принимает события, возвращает рейтинг логинов в неудачных попытках входа."""
    failed = events[events["event_type"] == EventType.FAILED_LOGIN.value]
    counts = analytics.top_values(failed, "username", limit)
    return _plot_ranking(counts, f"Топ-{limit} логинов", "Под какими логинами пытались войти", "неудачных попыток")


def save_charts(
    events: pd.DataFrame,
    out_dir: Union[str, Path],
    *,
    tz: TimezoneName = "UTC",
    bucket: str = "day",
    limit: int = 10,
) -> list[Path]:
    """Сохраняет все четыре графика в out_dir как PNG, возвращает пути к файлам."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    figures = {
        "timeline.png": plot_timeline(events, bucket, tz),
        "heatmap.png": plot_heatmap(events, tz),
        "top_ips.png": plot_top_ips(events, limit),
        "top_usernames.png": plot_top_usernames(events, limit),
    }
    paths = []
    for name, figure in figures.items():
        path = out_dir / name
        figure.savefig(path, facecolor=SURFACE)
        paths.append(path)
    return paths
