# Один образ на все сервисы: API, дашборд и разовые команды CLI отличаются только командой запуска.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Сначала ставим только зависимости, с пустым пакетом-заглушкой. Этот слой
# Docker кэширует и пересобирает лишь при изменении pyproject.toml, а не при
# каждой правке кода: иначе каждая сборка заново качала бы pandas и matplotlib.
COPY pyproject.toml README.md ./
RUN mkdir -p src/attack_analyzer \
    && touch src/attack_analyzer/__init__.py \
    && pip install . \
    && pip uninstall -y attack-analyzer

COPY src ./src
COPY config.toml ./
RUN pip install --no-deps .

# Не root: если в приложении найдётся уязвимость, у процесса будет меньше прав.
# uid 1000 обычно совпадает с первым пользователем Linux-хоста, поэтому
# смонтированная папка data/ остаётся доступной на запись.
RUN useradd --create-home --uid 1000 analyzer \
    && mkdir -p /app/data \
    && chown analyzer:analyzer /app/data
USER analyzer

ENV ATTACK_ANALYZER_DB=sqlite:////app/data/attacks.db

EXPOSE 8000 8001
ENTRYPOINT ["attack-analyzer"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
