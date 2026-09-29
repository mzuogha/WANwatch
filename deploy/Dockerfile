# Optional container build: docker build -f deploy/Dockerfile -t wanwatch .
FROM python:3.12-slim
RUN useradd --system --create-home wanwatch
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY wanwatch ./wanwatch
RUN mkdir -p /app/data /app/logs /app/reports && chown -R wanwatch /app/data /app/logs /app/reports
USER wanwatch
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
# mount config.yaml (and wanwatch.env) at /app
CMD ["python", "-m", "wanwatch", "run", "-c", "/app/config.yaml"]
