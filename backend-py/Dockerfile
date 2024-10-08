FROM python:bookworm AS build

# Disable cache dir, disable upgrade message, create .venv in project dir
ARG PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    POETRY_VIRTUALENVS_IN_PROJECT=1

# Install poetry, then dependencies
WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install poetry==1.6.1
RUN poetry install --no-root -vvv --without dev --sync


# Deploy
FROM python:slim-bookworm AS deploy

# Output to stdout/stderr, don't create .pyc files, etc.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

# Packages
RUN apt update && \
    apt install -y --no-install-recommends curl libpq-dev

# Dependencies, config and app
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY logger.conf ./
COPY ./src ./src

# Startup script
RUN ( \
        echo 'uvicorn src.main:app --host 0.0.0.0 --port 3000 --workers 1 --server-header --date-header --limit-concurrency 1000 --log-config ./logger.conf'; \
    ) >> ./entrypoint.sh; \
    chmod +x ./entrypoint.sh

# Start with non-privileged user
HEALTHCHECK --interval=300s --timeout=10s CMD curl -f http://localhost:3000
USER 1001

# Entrypoint
CMD ["./entrypoint.sh"]
