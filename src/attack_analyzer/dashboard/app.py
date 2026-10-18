"""Дашборд на Shiny for Python. Все данные берутся из HTTP API, к базе он не обращается."""

from __future__ import annotations

import base64
from typing import Any, Callable, Optional, TypeVar

import pandas as pd
from matplotlib.figure import Figure
from shiny import App, Inputs, Outputs, Session, reactive, render, req, ui

from attack_analyzer import charts
from attack_analyzer.dashboard.client import ApiClient, ApiError, DashboardFilters
from attack_analyzer.models import EventType, IncidentKind

TIMEZONES = [
    "UTC",
    "Europe/Kaliningrad",
    "Europe/Moscow",
    "Europe/Samara",
    "Asia/Yekaterinburg",
    "Asia/Novosibirsk",
    "Asia/Vladivostok",
    "Europe/Berlin",
    "Europe/London",
    "America/New_York",
]
EVENT_TYPE_CHOICES = {
    **{event_type: label for event_type, label in charts.EVENT_LABELS.items()},
    EventType.ACCEPTED.value: "Успешный вход",
}
INCIDENT_LABELS = {
    IncidentKind.BRUTEFORCE.value: "Брутфорс",
    IncidentKind.ENUMERATION.value: "Перебор логинов",
    IncidentKind.REPEATED.value: "Повторные атаки",
    IncidentKind.SUCCESS_AFTER_ATTACK.value: "Вход после атаки",
}
ATTACKER_SORT_CHOICES = {
    "failed_logins": "неудачным входам",
    "invalid_users": "неверным логинам",
    "scanner_hits": "сканированию",
    "distinct_usernames": "разным логинам",
    "last_seen": "последней активности",
}
ATTACKER_COLUMNS = {
    "ip": "IP",
    "failed_logins": "Неудачных",
    "invalid_users": "Неверный логин",
    "scanner_hits": "Сканирование",
    "successful_logins": "Успешных входов",
    "distinct_usernames": "Разных логинов",
    "first_seen": "Впервые",
    "last_seen": "Последний раз",
}
EVENT_COLUMNS = {
    "timestamp": "Время",
    "event_type": "Тип",
    "ip": "IP",
    "username": "Логин",
    "auth_method": "Способ",
    "port": "Порт",
}

T = TypeVar("T")


def _local_time(values: pd.Series, tz: str, fmt: str = "%Y-%m-%d %H:%M:%S") -> pd.Series:
    return values.dt.tz_convert(tz).dt.strftime(fmt)


def _figure_tag(figure: Figure, alt: str) -> Any:
    # Картинку отдаём сами, а не через render.plot: тот перестраивает фигуру
    # под размер блока и несовместим с layout="constrained" из charts.py.
    # Так дашборд показывает ровно те же графики, что и команда charts.
    encoded = base64.b64encode(charts.figure_to_png(figure)).decode("ascii")
    return ui.img(src=f"data:image/png;base64,{encoded}", alt=alt, style="width: 100%; height: auto;")


def build_ui(default_tz: str) -> Any:
    """Возвращает разметку страницы дашборда."""
    sidebar = ui.sidebar(
        ui.input_date_range("period", "Период", language="ru", weekstart=1, separator="—"),
        ui.input_select("tz", "Часовой пояс", choices=TIMEZONES, selected=default_tz),
        ui.input_checkbox_group(
            "event_types",
            "Типы событий",
            choices=EVENT_TYPE_CHOICES,
            selected=list(charts.EVENT_LABELS),
        ),
        ui.input_radio_buttons("bucket", "Группировка", {"day": "По дням", "hour": "По часам"}),
        ui.input_action_button("refresh", "Обновить данные"),
        ui.input_action_link("all_time", "Показать весь период"),
        width=280,
    )
    numbers = ui.layout_column_wrap(
        ui.value_box("Событий за период", ui.output_text("total_events")),
        ui.value_box("Уникальных IP", ui.output_text("unique_ips")),
        ui.value_box("Атакующих IP (всего)", ui.output_text("attackers_count")),
        ui.value_box("Входов после атаки", ui.output_text("compromises")),
        fill=False,
    )
    tables = ui.navset_card_tab(
        ui.nav_panel(
            "Атакующие IP",
            ui.layout_columns(
                ui.input_select("order_by", "Сортировать по", ATTACKER_SORT_CHOICES),
                ui.input_numeric("top_limit", "Сколько показать", value=20, min=5, max=200, step=5),
                col_widths=[4, 3],
            ),
            ui.output_data_frame("attackers"),
            ui.output_ui("selected_ip_header"),
            ui.output_data_frame("selected_ip_events"),
        ),
        ui.nav_panel("Инциденты", ui.output_data_frame("incidents")),
        ui.nav_panel("Последние события", ui.output_data_frame("events")),
    )
    return ui.page_sidebar(
        sidebar,
        numbers,
        ui.card(ui.output_ui("timeline"), full_screen=True),
        ui.card(ui.output_ui("heatmap"), full_screen=True),
        ui.card(ui.output_ui("top_usernames"), full_screen=True),
        tables,
        title="Анализатор атак на VPS",
        fillable=False,
    )


def build_server(client: ApiClient) -> Callable[[Inputs, Outputs, Session], None]:
    """Принимает клиент API, возвращает серверную функцию Shiny."""

    def server(input: Inputs, output: Outputs, session: Session) -> None:
        def fetch(call: Callable[[], T]) -> T:
            # Ошибку API показываем всплывающим сообщением, а выводы просто
            # остаются пустыми (req(False)), вместо красного трейсбэка в каждом блоке.
            try:
                return call()
            except ApiError as error:
                ui.notification_show(str(error), type="error", duration=8, id="api-error")
                req(False)
                raise  # недостижимо: req(False) уже выбросил исключение

        def show_whole_period() -> None:
            summary = fetch(lambda: client.summary(DashboardFilters()))
            if summary["first_event"] is None:
                ui.notification_show("В базе нет событий. Выполните import.", type="warning", duration=8)
                return
            tz = input.tz()
            first = pd.Timestamp(summary["first_event"]).tz_convert(tz).date()
            last = pd.Timestamp(summary["last_event"]).tz_convert(tz).date()
            ui.update_date_range("period", start=first, end=last, min=first, max=last)

        @reactive.effect
        def _initial_period() -> None:
            # Без зависимостей эффект выполнится один раз при открытии страницы.
            with reactive.isolate():
                show_whole_period()

        @reactive.effect
        @reactive.event(input.all_time)
        def _all_time() -> None:
            show_whole_period()

        @reactive.calc
        def filters() -> DashboardFilters:
            input.refresh()
            start, end = input.period()
            req(start, end)
            return DashboardFilters(start=start, end=end, tz=input.tz(), event_types=tuple(input.event_types()))

        @reactive.calc
        def summary() -> dict[str, Any]:
            return fetch(lambda: client.summary(filters()))

        @render.text
        def total_events() -> str:
            return f"{summary()['total_events']:,}".replace(",", " ")

        @render.text
        def unique_ips() -> str:
            return str(summary()["unique_ips"])

        @render.text
        def attackers_count() -> str:
            return str(summary()["attackers"])

        @render.text
        def compromises() -> str:
            count = summary()["incidents"].get(IncidentKind.SUCCESS_AFTER_ATTACK.value, 0)
            return str(count) if count else "нет"

        @render.ui
        def timeline() -> Any:
            current = filters()
            table = fetch(lambda: client.timeline(current, input.bucket()))
            return _figure_tag(charts.draw_timeline(table, input.bucket(), current.tz), "Атаки по времени")

        @render.ui
        def heatmap() -> Any:
            current = filters()
            figure = charts.draw_heatmap(fetch(lambda: client.heatmap(current)), current.tz)
            return _figure_tag(figure, "Тепловая карта: день недели и час")

        @render.ui
        def top_usernames() -> Any:
            counts = fetch(lambda: client.top_usernames(filters(), 10))
            figure = charts.draw_ranking(counts, "Топ-10 логинов", "В неудачных попытках входа", "попыток", width=9)
            return _figure_tag(figure, "Топ логинов")

        @reactive.calc
        def attackers_table() -> pd.DataFrame:
            input.refresh()
            limit = input.top_limit() or 20
            return fetch(lambda: client.top_attackers(int(limit), input.order_by()))

        @render.data_frame
        def attackers() -> render.DataGrid:
            table = attackers_table()
            if table.empty:
                return render.DataGrid(pd.DataFrame(columns=list(ATTACKER_COLUMNS.values())))
            shown = table[list(ATTACKER_COLUMNS)].copy()
            for column in ("first_seen", "last_seen"):
                # Короткий формат: в широкой таблице полная дата переносится на три строки.
                shown[column] = _local_time(shown[column], input.tz(), "%d.%m %H:%M")
            return render.DataGrid(
                shown.rename(columns=ATTACKER_COLUMNS),
                selection_mode="row",
                width="100%",
                height="360px",
            )

        @reactive.calc
        def selected_ip() -> Optional[str]:
            rows = attackers.cell_selection()["rows"]
            table = attackers_table()
            if not rows or table.empty:
                return None
            return str(table.iloc[rows[0]]["ip"])

        @render.ui
        def selected_ip_header() -> Any:
            ip = selected_ip()
            if ip is None:
                return ui.p("Выберите строку, чтобы увидеть события этого IP за период.", class_="text-muted mt-2")
            return ui.h6(f"События {ip} за период", class_="mt-3")

        def events_grid(events: pd.DataFrame, tz: str) -> render.DataGrid:
            if events.empty:
                return render.DataGrid(pd.DataFrame(columns=list(EVENT_COLUMNS.values())))
            shown = events[list(EVENT_COLUMNS)].copy()
            shown["timestamp"] = _local_time(shown["timestamp"], tz)
            shown["event_type"] = shown["event_type"].map(EVENT_TYPE_CHOICES)
            return render.DataGrid(shown.rename(columns=EVENT_COLUMNS), width="100%", height="360px")

        @render.data_frame
        def selected_ip_events() -> render.DataGrid:
            ip = selected_ip()
            req(ip)
            current = filters()
            return events_grid(fetch(lambda: client.events(current, ip=ip, limit=500)), current.tz)

        @render.data_frame
        def incidents() -> render.DataGrid:
            current = filters()
            table = fetch(lambda: client.incidents(current))
            columns = {"start": "Начало", "kind": "Вид", "ip": "IP", "event_count": "Событий", "details": "Подробности"}
            if table.empty:
                return render.DataGrid(pd.DataFrame(columns=list(columns.values())))
            table = table.sort_values("start", ascending=False).reset_index(drop=True)
            shown = table[list(columns)].copy()
            shown["start"] = _local_time(shown["start"], current.tz)
            shown["kind"] = shown["kind"].map(INCIDENT_LABELS)
            # Возможный взлом выделяем фоном: это самое важное в списке.
            compromised = table.index[table["kind"] == IncidentKind.SUCCESS_AFTER_ATTACK.value].tolist()
            return render.DataGrid(
                shown.rename(columns=columns),
                width="100%",
                height="420px",
                styles=[{"rows": compromised, "style": {"background-color": "#fde2e1"}}] if compromised else None,
            )

        @render.data_frame
        def events() -> render.DataGrid:
            current = filters()
            return events_grid(fetch(lambda: client.events(current, limit=200)), current.tz)

    return server


def create_dashboard(api_url: Optional[str] = None, default_tz: str = "UTC", client: Optional[ApiClient] = None) -> App:
    """Принимает адрес API (или готовый клиент) и пояс по умолчанию, возвращает приложение Shiny."""
    return App(build_ui(default_tz), build_server(client or ApiClient(api_url)))

