# syntax=docker/dockerfile:1.7
# Migration / provisioning / seed job image (runs as a one-shot Job with the owner role).
FROM python:3.13-slim-bookworm
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home app
WORKDIR /app
COPY pyproject.toml scripts/print_requirements.py ./
RUN --mount=type=secret,id=pip_conf,target=/etc/pip.conf,required=false \
    --mount=type=secret,id=extra_ca,target=/run/secrets/extra_ca,required=false \
    python print_requirements.py pyproject.toml "" > requirements.txt && pip install -r requirements.txt
COPY packages /app/packages
COPY services/knowledge/src /app/services/knowledge/src
COPY scripts /app/scripts
ENV PYTHONPATH=/app/packages/platform-core/src:/app/services/knowledge/src
USER 10001:10001
CMD ["python", "-m", "alembic", "-c", "packages/database/alembic.ini", "upgrade", "head"]
