FROM python:3.13.3@sha256:653b0cf8fc50366277a21657209ddd54edd125499d20f3520c6b277eb8c828d3 AS build

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
FROM python:3.13.3-slim@sha256:914bf5c12ea40a97a78b2bff97fbdb766cc36ec903bfb4358faf2b74d73b555b  AS deploy

# Output to stdout/stderr, don't create .pyc files, etc.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    PORT=3000

# Packages
RUN apt update && \
    apt install -y --no-install-recommends libpq-dev

# Dependencies, config and app
COPY --from=build /app/.venv /app/.venv
COPY logger.conf ./
COPY ./src ./src

HEALTHCHECK --interval=300s --timeout=10s CMD timeout 10s sh -c 'true > http://localhost:${PORT} || exit 1'

# Start with non-privileged user
USER 1001
SHELL ["/bin/bash", "-c"]
ENTRYPOINT uvicorn src.main:app --host 0.0.0.0 --port ${PORT} --workers 1 --server-header --date-header --limit-concurrency 1000 --log-config ./logger.conf
