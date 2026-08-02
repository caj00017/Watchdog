FROM ghcr.io/google/osv-scanner:v2.4.0@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475 AS osv-scanner

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG WATCHDOG_BUILD_EPOCH=1785628800
ENV SOURCE_DATE_EPOCH=${WATCHDOG_BUILD_EPOCH}

WORKDIR /build

COPY requirements/release.lock requirements/release.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements/release.lock

COPY pyproject.toml MANIFEST.in README.md LICENSE CHANGELOG.md SECURITY.md ./
COPY apps ./apps
COPY watchdog ./watchdog

RUN python -m build --wheel --no-isolation --outdir /wheelhouse

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ARG WATCHDOG_REVISION=unknown

LABEL org.opencontainers.image.title="Nexura Watchdog" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.revision="${WATCHDOG_REVISION}" \
      org.opencontainers.image.source="https://github.com/caj00017/Watchdog" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements/runtime.lock requirements/runtime.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements/runtime.lock

COPY --from=builder /wheelhouse/nexura_watchdog-0.1.0-py3-none-any.whl /tmp/nexura_watchdog-0.1.0-py3-none-any.whl
RUN python -m pip install --no-cache-dir --no-deps /tmp/nexura_watchdog-0.1.0-py3-none-any.whl && \
    python -c "from pathlib import Path; Path('/tmp/nexura_watchdog-0.1.0-py3-none-any.whl').unlink()"

COPY --from=osv-scanner /osv-scanner /usr/local/bin/osv-scanner

EXPOSE 8000

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
