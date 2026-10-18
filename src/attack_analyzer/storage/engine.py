"""Подключение к базе: адрес, движок, фабрика сессий."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from attack_analyzer.storage.schema import Base

DEFAULT_DATABASE_URL = "sqlite:///data/attacks.db"
DATABASE_URL_ENV = "ATTACK_ANALYZER_DB"


def database_url(url: Optional[str] = None) -> str:
    """Возвращает адрес базы: аргумент, иначе переменная ATTACK_ANALYZER_DB, иначе data/attacks.db."""
    return url or os.environ.get(DATABASE_URL_ENV, DEFAULT_DATABASE_URL)


def make_engine(url: Optional[str] = None) -> Engine:
    """Принимает адрес базы, возвращает движок SQLAlchemy с уже созданными таблицами."""
    parsed = make_url(database_url(url))
    if parsed.get_backend_name() == "sqlite" and parsed.database not in (None, "", ":memory:"):
        Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(parsed)
    # create_all создаёт только отсутствующие таблицы и не меняет существующие.
    # Пока схема не меняется, этого хватает; при изменениях понадобятся миграции (Alembic).
    Base.metadata.create_all(engine)
    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Возвращает фабрику сессий для движка."""
    # expire_on_commit=False: объекты остаются читаемыми после commit,
    # их можно спокойно отдать в CLI или API уже после закрытия сессии.
    return sessionmaker(engine, expire_on_commit=False)
