FROM python:3.11-slim

LABEL maintainer="jbkunama1"
LABEL description="hAI.PeeDHCP – DHCP Admin Dashboard für PiHole"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

RUN adduser --disabled-password --gecos '' appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/health || exit 1

CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "backend.app:app"]
