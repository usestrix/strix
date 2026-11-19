FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL \
    https://dl.min.io/client/mc/release/linux-amd64/archive/mc.RELEASE.2025-08-13T08-35-41Z \
    -o /usr/local/bin/mc \
    && chmod +x /usr/local/bin/mc

ENTRYPOINT ["mc"]
