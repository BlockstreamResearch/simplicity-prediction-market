# syntax=docker/dockerfile:1.6

FROM rust:1.97.1-bookworm AS builder

ARG SIMPLEX_VERSION=0.1.1
ARG PRICE_ORACLE_REF

RUN printf '%s\n' "$PRICE_ORACLE_REF" | grep -Eq '^[0-9a-fA-F]{40}$' \
    || { echo "PRICE_ORACLE_REF must be a full oracle commit SHA" >&2; exit 1; }

WORKDIR /workspace
ADD https://github.com/BlockstreamResearch/price-oracle.git#${PRICE_ORACLE_REF} ./price-oracle
RUN cargo install --locked \
    --git https://github.com/BlockstreamResearch/smplx.git \
    --tag "v${SIMPLEX_VERSION}" smplx-cli
COPY . ./prediction-demo
RUN cd price-oracle/contracts && simplex install && simplex build
RUN cd prediction-demo/contracts && simplex install && simplex build
RUN cargo build --locked --release \
    --manifest-path prediction-demo/Cargo.toml --package prediction-demo-server

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 prediction-demo \
    && install -d -o prediction-demo -g prediction-demo /var/lib/prediction-demo
COPY --from=builder /workspace/prediction-demo/target/release/prediction-demo-server /usr/local/bin/prediction-demo-server

USER prediction-demo
WORKDIR /var/lib/prediction-demo
EXPOSE 3100
ENTRYPOINT ["prediction-demo-server"]
CMD ["/etc/prediction-demo/config.toml"]