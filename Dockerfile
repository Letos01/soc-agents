# Agents need Python (ADK) and Node (they spawn the mcp-wazuh server over stdio).
FROM node:26-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN python3 -m venv /venv
ENV PATH=/venv/bin:$PATH PYTHONUNBUFFERED=1
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[litellm]"
RUN useradd --create-home --uid 10001 soc && mkdir -p /data && chown soc /data
USER soc
ENV AUDIT_LOG_PATH=/data/audit/audit.jsonl INCIDENTS_DIR=/data/incidents MCP_WAZUH_PATH=/opt/mcp-wazuh/dist/index.js
ENTRYPOINT ["soc-agents"]
