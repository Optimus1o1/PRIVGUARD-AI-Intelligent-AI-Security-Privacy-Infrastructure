# ==============================================================================
# PRIVGUARD AI - Backend Production Multi-Stage Dockerfile
# Moon Sanctum Labs - Decode. Build. Evolve.
# ==============================================================================

# Stage 1: Build & Dependencies
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install production dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# Stage 2: Minimal Production Runtime
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="PRIVGUARD AI Backend Gateway" \
      org.opencontainers.image.description="Independent Security & Privacy Enforcement Layer for AI Agents" \
      org.opencontainers.image.vendor="Moon Sanctum Labs" \
      org.opencontainers.image.version="0.1.0"

WORKDIR /app

# Install minimal runtime utilities (curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user and group
RUN groupadd -g 10001 privguard && \
    useradd -u 10001 -g privguard -s /sbin/nologin -M privguard

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source code and migration assets
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini

# Assign strict ownership to non-root user
RUN chown -R privguard:privguard /app

# Switch to non-root execution
USER privguard:privguard

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=production \
    PORT=8000 \
    HOST=0.0.0.0

EXPOSE 8000

# Liveness probe ensuring process is running without leaking details
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/health/live || exit 1

# Default ASGI entrypoint with proxy header handling
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
