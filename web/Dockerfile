# syntax=docker/dockerfile:1.6

FROM --platform=$BUILDPLATFORM oven/bun:1.3.14 AS builder

ARG PRICE_ORACLE_REF
RUN printf '%s\n' "$PRICE_ORACLE_REF" | grep -Eq '^[0-9a-fA-F]{40}$' \
    || { echo "PRICE_ORACLE_REF must be a full oracle commit SHA" >&2; exit 1; }
ADD https://github.com/BlockstreamResearch/price-oracle.git#${PRICE_ORACLE_REF} /workspace/price-oracle

WORKDIR /workspace/price-oracle/web/sdk
RUN bun install --frozen-lockfile && bun run build

WORKDIR /workspace/prediction-demo/web
COPY web/package.json web/bun.lock ./
COPY web/patches ./patches
RUN bun install --frozen-lockfile
COPY web ./
ARG VITE_SERVER_API=
ENV VITE_SERVER_API=${VITE_SERVER_API}
RUN bun run build

FROM nginxinc/nginx-unprivileged:1.29-alpine

ENV PREDICTION_API_UPSTREAM=http://127.0.0.1:3100
COPY web/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=builder /workspace/prediction-demo/web/dist /usr/share/nginx/html
USER 101
EXPOSE 8080