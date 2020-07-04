# Copyright (c) The dgc.network
# SPDX-License-Identifier: Apache-2.0

FROM hyperledger/grid-dev:v2 as grid-cli-builder

# Copy over Cargo.toml files
COPY Cargo.toml /build/Cargo.toml
COPY api/Cargo.toml /build/api/Cargo.toml
COPY cli/Cargo.toml /build/cli/Cargo.toml
COPY daemon/Cargo.toml /build/daemon/Cargo.toml
COPY sdk/Cargo.toml /build/sdk/Cargo.toml

COPY contracts/pike/Cargo.toml /build/contracts/pike/Cargo.toml
COPY contracts/product/Cargo.toml /build/contracts/product/Cargo.toml
COPY contracts/schema/Cargo.toml /build/contracts/schema/Cargo.toml
COPY contracts/track_and_trace/Cargo.toml /build/contracts/track_and_trace/Cargo.toml

# Copy over build files
COPY api /build/api
COPY cli /build/cli
COPY daemon /build/daemon
COPY sdk /build/sdk

# Build the grid-cli package
WORKDIR /build/cli
ARG CARGO_ARGS
ARG REPO_VERSION
RUN sed -i -e "0,/version.*$/ s/version.*$/version\ =\ \"${REPO_VERSION}\"/" Cargo.toml
RUN cargo deb --deb-version $REPO_VERSION $CARGO_ARGS

# -------------=== grid-cli docker build ===-------------
FROM hyperledger/sawtooth-sabre-cli

ARG CARGO_ARGS
RUN echo "CARGO_ARGS = '$CARGO_ARGS'" > CARGO_ARGS

COPY --from=grid-cli-builder /build/target/debian/grid-cli_*.deb /tmp

RUN apt-get update \
 && dpkg --unpack /tmp/grid-cli*.deb \
 && apt-get -f -y install

CMD ["tail -f /dev/null"]
