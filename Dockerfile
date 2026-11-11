# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.13-slim AS builder

WORKDIR /build

# Only needed when a dependency has no wheel for the target platform.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.13-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Only the application code, the API description and the default
# configuration: no tests or docs. Mount another configuration and point
# CONFIG_PATH at it (e.g. /etc/status_validator_config/config.yaml).
COPY app/ ./app/
COPY swagger.json config.yaml ./

# Unprivileged user (fixed UID, like the other EUDIW services). The service
# keeps its cache in memory and writes nothing to disk.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin statusvalidator \
 && mkdir -p /etc/status_validator_config

USER statusvalidator

ENV FLASK_APP="app:create_app"

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]
