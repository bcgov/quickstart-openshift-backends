#!/bin/bash

# Change to script dir
cd $(dirname ${BASH_SOURCE[0]})

# Install UV if not available
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

# Install dependencies including dev dependencies
uv sync --group dev

# Start app
echo "Starting unit tests at $(date +'%Y-%m-%d %H:%M:%S.%3N')"
uv run coverage run --source=src -m pytest ./test -x -o log_cli=true --disable-warnings -vvv
uv run coverage report
uv run coverage xml -o coverage-reports/coverage-report.xml
