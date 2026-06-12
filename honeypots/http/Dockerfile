# Honeypot HTTP - image durcie (B12)
FROM python:3.12-slim

RUN useradd -u 1000 -m honey
WORKDIR /app

COPY common/ /app/common/
COPY schemas/ /app/schemas/
COPY honeypots/http/ /app/honeypots/http/
RUN pip install --no-cache-dir "fastapi" "uvicorn[standard]" jsonschema

ENV PYTHONPATH=/app/common HP_LOG_DIR=/logs HP_HTTP_PORT=8080
# Le volume /logs doit appartenir a l'utilisateur non-root (uid 1000)
RUN mkdir -p /logs && chown 1000:1000 /logs
WORKDIR /app/honeypots/http
USER 1000:1000
EXPOSE 8080
CMD ["python", "app.py"]
