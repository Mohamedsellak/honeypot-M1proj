# Honeypot FTP - image durcie (B12)
FROM python:3.12-slim

RUN useradd -u 1000 -m honey
WORKDIR /app

COPY common/ /app/common/
COPY schemas/ /app/schemas/
COPY honeypots/ftp/ /app/honeypots/ftp/
RUN pip install --no-cache-dir pyftpdlib jsonschema

ENV PYTHONPATH=/app/common HP_LOG_DIR=/logs HP_FTP_PORT=2121
# Le volume /logs doit appartenir a l'utilisateur non-root (uid 1000)
RUN mkdir -p /logs && chown 1000:1000 /logs
WORKDIR /app/honeypots/ftp
USER 1000:1000
EXPOSE 2121 60000-60010
CMD ["python", "server.py"]
