# Log shipper (B11)
FROM python:3.12-slim
RUN useradd -u 1000 -m honey
WORKDIR /app
COPY shipper/ /app/shipper/
ENV HP_LOG_DIR=/logs
RUN mkdir -p /logs && chown 1000:1000 /logs
USER 1000:1000
CMD ["python", "shipper/shipper.py"]
