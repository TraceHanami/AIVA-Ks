FROM python:3.12-slim

LABEL maintainer="AIVA-KS Core Team"
LABEL description="CHRONOS / AIVA-KS Backend Service"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    python3-dev \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir -e .[backend]

COPY chronos ./chronos
COPY ai ./ai
COPY backend ./backend
COPY response-engine ./response-engine
COPY tests ./tests

ENV PYTHONPATH="/app:/app/response-engine"
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "chronos.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
