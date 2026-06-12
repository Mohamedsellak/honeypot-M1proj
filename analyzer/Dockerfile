# Analyzer (API + classifier + enrichers + exports)
FROM python:3.12-slim

RUN useradd -u 1000 -m honey
WORKDIR /app

COPY common/ /app/common/
COPY schemas/ /app/schemas/
COPY analyzer/ /app/analyzer/
RUN pip install --no-cache-dir "fastapi" "uvicorn[standard]" jsonschema maxminddb httpx

ENV PYTHONPATH=/app/common HP_LOG_DIR=/logs HP_DB=/data/events.db HP_API_PORT=8000
# Les volumes /logs (lecture) et /data (SQLite) doivent appartenir a uid 1000
RUN mkdir -p /logs /data && chown 1000:1000 /logs /data
WORKDIR /app/analyzer
USER 1000:1000
EXPOSE 8000
CMD ["python", "api.py"]
