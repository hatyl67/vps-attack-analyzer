# Анализатор атак на VPS

Учебный проект: разбор логов SSH с Debian-сервера, поиск брутфорса,
перебора логинов и сканеров, аналитика и дашборд.

Статус: **этап 1** — структура проекта, генератор тестового `auth.log`, парсер.

## Установка

Нужен Python 3.9+. Всё ставится через pip в виртуальное окружение.

```powershell
py -3.9 -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
```

На Linux/macOS: `python3 -m venv .venv && source .venv/bin/activate`.

## Генерация тестового лога

```bash
python -m attack_analyzer generate --days 14 --seed 42 --tz Europe/Moscow
```

Лог пишется в `data/generated/auth.log` (папка `data/` в git не попадает).
Опция `--format iso` даёт время как у rsyslog в Debian 12+:
`2026-10-18T03:14:15.123456+03:00`.

## Разбор лога

```bash
python -m attack_analyzer parse data/generated/auth.log --tz Europe/Moscow
python -m attack_analyzer parse data/generated/auth.log --csv data/events.csv
```

Из Python:

```python
from attack_analyzer.parsers import parse_auth_log

df = parse_auth_log("data/generated/auth.log", tz="Europe/Moscow")
```

Колонки DataFrame: `timestamp` (UTC), `event_type` (`failed_login`,
`invalid_user`, `accepted`, `scanner`), `ip`, `username`, `port`,
`auth_method`, `invalid_user`, `host`, `source`.

### Настоящие логи сервера

Скопируйте лог в `data/raw/` (не коммитится) и укажите пояс сервера:

```bash
# на сервере
sudo cp /var/log/auth.log ~/auth.log && sudo chown $USER ~/auth.log
# или, если rsyslog не установлен (Debian 12+ по умолчанию):
journalctl -u ssh -o short-iso --since "30 days ago" > ~/ssh.log
```

```bash
python -m attack_analyzer parse data/raw/auth.log --tz Europe/Moscow --year 2026
python -m attack_analyzer parse data/raw/auth.log.2.gz --tz Europe/Moscow
```

Сводка показывает число нераспознанных сообщений sshd и примеры: по ним
видно, какие форматы ещё стоит добавить в парсер.

## Тесты

```bash
pytest
```

## Структура

```
src/attack_analyzer/
    models.py           EventType, AuthEvent
    parsers/auth_log.py парсер auth.log / journalctl
    generator.py        генератор тестового лога
    cli.py              команды generate и parse
tests/                  pytest
data/                   логи и база (в .gitignore)
```
