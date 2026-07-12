FROM python:3.12-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-default-groups --extra mcp --extra tmp --no-install-project

COPY src ./src
RUN uv sync --frozen --no-default-groups --extra mcp --extra tmp --no-editable

FROM python:3.12-slim-bookworm

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 deco-mcp \
    && useradd --uid 10001 --gid deco-mcp --no-create-home --shell /usr/sbin/nologin deco-mcp

WORKDIR /app
COPY --from=builder --chown=deco-mcp:deco-mcp /app/.venv /app/.venv

USER 10001:10001

EXPOSE 8000

ENTRYPOINT ["tplink-deco-mcp"]
