FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git \
    && rm -rf /var/lib/apt/lists/*

# Copy source — deps installed explicitly so this layer is cached on code-only changes
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir \
    "fastapi>=0.110" "uvicorn[standard]>=0.27" \
    "fastmcp>=2.0" \
    "pydantic>=2.0" "pydantic-settings>=2.0" \
    "aiosqlite>=0.19" "kuzu>=0.3" "duckdb>=0.10" \
    "apscheduler>=3.10" "watchdog>=3.0" \
    "pyyaml>=6.0" \
    "click>=8.0" "rich>=13.0" "httpx>=0.27" \
    "opentelemetry-sdk>=1.20" \
    "opentelemetry-exporter-otlp-proto-grpc>=1.20" \
    "grpcio>=1.60" \
    "rapidfuzz>=3.0" \
    "cryptography>=42.0" \
    "prometheus-client>=0.20" \
    "aiobotocore>=2.0"

# src/ is importable without a package install
ENV PYTHONPATH=/app/src

EXPOSE 8080

# Runtime config is expected at /app/ctxfw.yaml via volume mount.
# Falls back to built-in defaults if the file is absent.
CMD ["python", "-m", "context_firewall.daemon.main"]
