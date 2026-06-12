# Honeypot SSH - image durcie (B12)
FROM python:3.12-slim

RUN useradd -u 1000 -m honey
WORKDIR /app

COPY common/ /app/common/
COPY schemas/ /app/schemas/
COPY honeypots/ssh/ /app/honeypots/ssh/
RUN pip install --no-cache-dir asyncssh jsonschema

ENV PYTHONPATH=/app/common HP_LOG_DIR=/logs HP_SSH_PORT=2222
# Le volume /logs doit appartenir a l'utilisateur non-root (uid 1000)
RUN mkdir -p /logs && chown 1000:1000 /logs
WORKDIR /app/honeypots/ssh
USER 1000:1000
EXPOSE 2222
CMD ["python", "server.py"]
