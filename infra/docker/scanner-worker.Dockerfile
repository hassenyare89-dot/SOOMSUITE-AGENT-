# syntax=docker/dockerfile:1.7
# Isolated scanner / malware worker. Contains ZAP (Automation Framework) and Nuclei, plus
# only platform-core + scanner-worker Python code. No database drivers are configured,
# no platform secrets are mounted (the malware role gets only the quarantine key file).
ARG ZAP_IMAGE=ghcr.io/zaproxy/zaproxy:stable
FROM ${ZAP_IMAGE}
USER root
ARG NUCLEI_VERSION=3.4.10
ARG NUCLEI_SHA256=""
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv python3-dev \
      build-essential libssl-dev unzip curl ca-certificates \
 && curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
 && if [ -n "${NUCLEI_SHA256}" ]; then echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum -c -; fi \
 && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin && chmod 0755 /usr/local/bin/nuclei && rm /tmp/nuclei.zip \
 && ln -sf /zap/zap.sh /usr/local/bin/zap.sh \
 && apt-get purge -y build-essential && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/worker
COPY pyproject.toml scripts/print_requirements.py ./
RUN python3 -m venv /opt/venv && /opt/venv/bin/python print_requirements.py pyproject.toml scanner > req.txt \
 && /opt/venv/bin/pip install --no-cache-dir -r req.txt
COPY packages/platform-core/src /opt/worker/core
COPY services/scanner-worker/src /opt/worker/service
ENV PATH=/opt/venv/bin:/usr/local/bin:$PATH PYTHONPATH=/opt/worker/core:/opt/worker/service \
    PYTHONUNBUFFERED=1 HOME=/tmp
# Nuclei templates are fetched at build time of a pinned template bundle in CI in production;
# here they are downloaded on first use into the writable /tmp.
USER 1000:1000
CMD ["python", "-m", "scanner_worker.main"]
