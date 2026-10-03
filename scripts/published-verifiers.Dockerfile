FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app/
RUN mkdir /app/npm && printf '{"private":true}' > /app/npm/package.json && npm install --prefix /app/npm --ignore-scripts --omit=dev --no-audit --no-fund /app/verifier.tgz
RUN python3 -m venv /app/venv && /app/venv/bin/pip install --only-binary=:all: --no-cache-dir /app/aga_governance-*.whl
ENV PYTHONDONTWRITEBYTECODE=1
USER node
CMD ["node", "/app/check.mjs"]
