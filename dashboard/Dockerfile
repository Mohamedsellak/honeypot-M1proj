# Dashboard live (B16)
FROM python:3.12-slim
RUN useradd -u 1000 -m honey
WORKDIR /app
COPY dashboard/ /app/dashboard/
# plotly.express IMPORTE pandas : sans pandas, `import plotly.express` plante.
RUN pip install --no-cache-dir dash plotly pandas httpx
ENV HP_API_URL=http://analyzer:8000 HP_DASH_PORT=8050
WORKDIR /app/dashboard
USER 1000:1000
EXPOSE 8050
CMD ["python", "app.py"]
