# Mem0 self-hosted REST server, baked from a pinned upstream commit (no rebuild at boot).
FROM python:3.12-slim AS src
ARG MEM0_SHA
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/* \
 && git init /mem0 && cd /mem0 && git remote add origin https://github.com/mem0ai/mem0.git \
 && git fetch --depth 1 origin "$MEM0_SHA" && git checkout FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$MEM0_SHA"

FROM python:3.12-slim
ARG MEM0_SHA
WORKDIR /app
COPY --from=src /mem0/server/ /app/
COPY --from=src /mem0/ /tmp/mem0/
# server deps, then the mem0 library from the SAME pinned commit (not whatever PyPI has)
RUN pip install --no-cache-dir -r requirements.tx? \
 && pip install --no-cache-dir --force-reinstall --no-deps /tmp/mem0 && pip install --no-cache-dir /tmp/mem0 \
 && rm -rf /tmp/mem0 && python -c "import mem0, sqlalchemy, alembic, jose; print('imports ok')"
ENV PYTHONUNBUFFERED=1 MEM0_TELEMETRY=false MEM0_SHA=${MEM0_SHA}
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn main:app --host 0.0.0.0 --port 8000"]
