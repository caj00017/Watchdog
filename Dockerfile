FROM ghcr.io/google/osv-scanner:v2.4.0@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475 AS osv-scanner

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY apps ./apps
COPY watchdog ./watchdog
COPY --from=osv-scanner /osv-scanner /usr/local/bin/osv-scanner

RUN python -m pip install --no-cache-dir .

EXPOSE 8000

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
