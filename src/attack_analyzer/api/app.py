"""Сборка приложения FastAPI.

Запуск: `python -m attack_analyzer serve` или
`uvicorn attack_analyzer.api.app:create_app --factory --reload`.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Optional, Union

from fastapi import FastAPI

from attack_analyzer import __version__
from attack_analyzer.api.routes import router
from attack_analyzer.config import load_settings
from attack_analyzer.storage import database_url, make_engine, make_session_factory


def create_app(database: Optional[str] = None, config_path: Union[str, Path, None] = None) -> FastAPI:
    """Принимает адрес базы и путь к конфигу (None — как в CLI), возвращает приложение FastAPI."""
    # Фабрика вместо глобального app = FastAPI(): при импорте модуля ничего
    # не подключается к базе, а тесты легко создают приложение со своей базой.
    settings = load_settings(config_path)
    engine = make_engine(database_url(database or settings.database_url))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        title="Анализатор атак на VPS",
        version=__version__,
        description="События SSH, атакующие IP, инциденты и статистика.",
        lifespan=lifespan,
    )
    app.state.session_factory = make_session_factory(engine)
    app.include_router(router)
    return app
