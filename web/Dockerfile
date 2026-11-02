FROM --platform=$BUILDPLATFORM oven/bun:1.3.14 AS builder

WORKDIR /workspace/price-oracle/web/sdk
COPY price-oracle/web/sdk ./
RUN bun install --frozen-lockfile && bun run build

WORKDIR /workspace/prediction-demo/web
COPY prediction-demo/web/package.json prediction-demo/web/bun.lock ./
COPY prediction-demo/web/patches ./patches
RUN bun install --frozen-lockfile
COPY prediction-demo/web ./
ARG VITE_SERVER_API=
ENV VITE_SERVER_API=${VITE_SERVER_API}
RUN bun run build

FROM nginx:1.29-alpine

ENV PREDICTION_API_UPSTREAM=http://127.0.0.1:3100
COPY prediction-demo/web/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=builder /workspace/prediction-demo/web/dist /usr/share/nginx/html
EXPOSE 80