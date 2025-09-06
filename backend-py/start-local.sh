#!/bin/bash

# Change to script dir
cd $(dirname ${BASH_SOURCE[0]})

# Install UV if not available
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

# Install dependencies and sync environment
uv sync --group dev

# Start app
echo "Starting uvicorn at $(date +'%Y-%m-%d %H:%M:%S.%3N')"
uv run uvicorn src.main:app --host 0.0.0.0 --port 3000 --workers 1 --server-header --date-header --limit-concurrency 100 --reload --log-config ./logger.conf || sleep 300
