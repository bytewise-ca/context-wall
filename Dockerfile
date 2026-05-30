FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git \
    && rm -rf /var/lib/apt/lists/*

# Install deps before copying source so the layer is cached on code-only changes
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir .

EXPOSE 8080

# Runtime config is expected at /app/ctxfw.yaml via volume mount.
# Falls back to built-in defaults if the file is absent.
CMD ["ctxfwd"]
