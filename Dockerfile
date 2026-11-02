FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/jbkunama1/hAI.PeeDHCP"
LABEL org.opencontainers.image.description="hAI.PeeDHCP - Pi-hole DHCP administration"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/app/data
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && pip check
COPY backend/ ./backend/
COPY frontend/ ./frontend/
RUN adduser --disabled-password --gecos '' --uid 1000 appuser \
    && mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl --fail --silent --max-time 5 http://localhost:8080/ || exit 1
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--access-logfile", "-", "--error-logfile", "-", "backend.app:app"]
