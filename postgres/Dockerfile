FROM postgres:16-bookworm

ARG PGSODIUM_VERSION=3.1.9

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl unzip libsodium-dev postgresql-server-dev-16 \
    && curl -fsSL "https://api.pgxn.org/dist/pgsodium/${PGSODIUM_VERSION}/pgsodium-${PGSODIUM_VERSION}.zip" -o /tmp/pgsodium.zip \
    && unzip -q /tmp/pgsodium.zip -d /tmp/pgsodium-src \
    && cd /tmp/pgsodium-src/pgsodium-${PGSODIUM_VERSION} \
    && make \
    && make install \
    && apt-mark manual libsodium23 \
    && apt-get purge -y --auto-remove build-essential curl unzip libsodium-dev postgresql-server-dev-16 \
    && rm -rf /var/lib/apt/lists/* /tmp/pgsodium.zip /tmp/pgsodium-src