FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ANTICELLS_RED_MCP_STATE_DIR=/app/data \
    ANTICELLS_RED_MCP_REPORTS_DIR=/app/data/reports

WORKDIR /app

# Install the package, including its bundled catalog and SQLite migrations.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip install --no-cache-dir . \
    && groupadd --gid 10001 mcp \
    && useradd --uid 10001 --gid mcp --create-home mcp \
    && mkdir -p /app/data \
    && chown mcp:mcp /app/data

USER mcp

# Glama connects over stdio; stdout is reserved for MCP protocol messages.
CMD ["anticells_red_mcp"]
