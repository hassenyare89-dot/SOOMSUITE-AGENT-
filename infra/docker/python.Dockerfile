# syntax=docker/dockerfile:1.7
# One hardened image per service. Each image contains ONLY platform-core and its own
# service package (e.g. the SAMIIR image contains no FATMA, scanner or approval code).
#
#   docker build -f infra/docker/python.Dockerfile \
#     --build-arg SERVICE_DIR=samiir-agent --build-arg EXTRAS=agents \
#     --build-arg APP=samiir_agent.main:create -t samiir-agent .
ARG PYTHON_IMAGE=python:3.13-slim-bookworm

FROM ${PYTHON_IMAGE} AS deps
ARG EXTRAS=""
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY pyproject.toml scripts/print_requirements.py ./
# Optional build secrets for private package indexes / corporate TLS proxies. They are
# mounted only for this step and never stored in image layers.
RUN --mount=type=secret,id=pip_conf,target=/etc/pip.conf,required=false \
    --mount=type=secret,id=extra_ca,target=/run/secrets/extra_ca,required=false \
    python print_requirements.py pyproject.toml "${EXTRAS}" > requirements.txt \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install -r requirements.txt

FROM ${PYTHON_IMAGE} AS runtime
ARG SERVICE_DIR
ARG APP
ARG PORT=8000
# Apply OS security updates at build time (disable only in air-gapped builders that use a
# pre-patched base image).
ARG APT_UPGRADE=true
LABEL org.opencontainers.image.source="https://github.com/hassenyare89-dot/SOOMSUITE-AGENT-" \
      org.opencontainers.image.title="samiir-fatma-${SERVICE_DIR}"
RUN if [ "$APT_UPGRADE" = "true" ]; then apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*; fi \
 && groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
COPY --from=deps /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root packages/platform-core/src /app/core
COPY --chown=root:root services/${SERVICE_DIR}/src /app/service
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app/core:/app/service \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    APP=${APP} PORT=${PORT}
USER 10001:10001
EXPOSE ${PORT}
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/healthz',timeout=2)"
# --proxy-headers only honoured from the mesh sidecar / ingress on localhost.
CMD ["sh", "-c", "exec uvicorn --factory \"$APP\" --host 0.0.0.0 --port \"$PORT\" --no-server-header --proxy-headers --forwarded-allow-ips 127.0.0.1 --timeout-graceful-shutdown 20"]
