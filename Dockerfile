# =============================================================================
#  PentestAI — Production Multi-Stage Dockerfile
# =============================================================================
#  Stages:
#    1. python-builder  — Build Python dependencies
#    2. nuclei-builder  — Compile nuclei binary from source
#    3. node-builder    — Install promptfoo and other Node.js tools
#    4. runner          — Minimal runtime image with all artifacts
# =============================================================================

# =============================================================================
#  Stage 1: Python Builder
# =============================================================================
FROM python:3.12-slim AS python-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install build system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 \
        libffi-dev \
        libcairo2 \
        libpangoft2-1.0-0 \
        libpq-dev \
        libxml2-dev \
        libxslt1-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for Docker layer caching
COPY requirements.txt .

# Create a virtual environment and install all dependencies
RUN python -m venv /build/venv && \
    /build/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /build/venv/bin/pip install --no-cache-dir -r requirements.txt

# =============================================================================
#  Stage 2: Nuclei Builder (Go)
# =============================================================================
FROM golang:1.22 AS nuclei-builder

# Install nuclei and related tools
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# =============================================================================
#  Stage 3: Node.js Builder (promptfoo)
# =============================================================================
FROM node:20-slim AS node-builder

RUN npm install -g promptfoo@0.72.0 && \
    npm cache clean --force

# =============================================================================
#  Stage 4: Runner (Final Image)
# =============================================================================
FROM python:3.12-slim AS runner

# ── Labels ──────────────────────────────────────────────────────────────────
LABEL maintainer="PentestAI Team <dev@pentestai.com>" \
      description="PentestAI — Automated Penetration Testing Platform" \
      version="1.0.0" \
      org.opencontainers.image.source="https://github.com/pentestai/pentestai" \
      org.opencontainers.image.description="Automated Penetration Testing Platform"

# ── Environment ─────────────────────────────────────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/venv/bin:/home/pentestai/.local/bin:$PATH" \
    PIP_NO_CACHE_DIR=1 \
    NUCLEI_PATH="/home/pentestai/.local/bin/nuclei"

# ── Runtime system libraries ────────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 \
        libcairo2 \
        libpangoft2-1.0-0 \
        libpq5 \
        libxml2 \
        libxslt1.1 \
        ca-certificates \
        curl \
        procps \
    && rm -rf /var/lib/apt/lists/*

# ── Copy virtual environment from Python builder ────────────────────────────
COPY --from=python-builder /build/venv /venv

# ── Copy nuclei and other Go binaries ────────────────────────────────────────
COPY --from=nuclei-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=nuclei-builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=nuclei-builder /go/bin/subfinder /usr/local/bin/subfinder

# ── Copy promptfoo from Node builder ────────────────────────────────────────
COPY --from=node-builder /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -sf /usr/local/lib/node_modules/promptfoo/bin/promptfoo.js /usr/local/bin/promptfoo

# ── Initialize nuclei templates ─────────────────────────────────────────────
RUN nuclei -update-templates 2>/dev/null || true

# ── Create non-root user ────────────────────────────────────────────────────
RUN groupadd -r pentestai && \
    useradd -r -g pentestai -d /home/pentestai -s /sbin/nologin -m pentestai && \
    mkdir -p /app /data /var/log/pentestai && \
    chown -R pentestai:pentestai /app /data /var/log/pentestai /home/pentestai

WORKDIR /app

# ── Copy application code ───────────────────────────────────────────────────
COPY --chown=pentestai:pentestai alembic.ini .
COPY --chown=pentestai:pentestai alembic/       alembic/
COPY --chown=pentestai:pentestai app/           app/

# ── Copy scripts ────────────────────────────────────────────────────────────
COPY --chown=pentestai:pentestai scripts/       scripts/ 2>/dev/null || true

# ── Switch to non-root user ─────────────────────────────────────────────────
USER pentestai

# ── Expose ports ────────────────────────────────────────────────────────────
EXPOSE 8000

# ── Health check ────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl --fail --silent --show-error http://localhost:8000/health || exit 1

# ── Default command ─────────────────────────────────────────────────────────
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--limit-concurrency", "100", "--timeout-graceful-shutdown", "30"]
