# Copyright (c) The dgc.network
# SPDX-License-Identifier: Apache-2.0

FROM hyperledger/grid-dev:v2 as gridd-builder

# Copy over Cargo.toml files
COPY Cargo.toml /build/Cargo.toml
COPY api/Cargo.toml /build/api/Cargo.toml
COPY config/Cargo.toml /build/config/Cargo.toml

COPY contracts/pike/Cargo.toml /build/contracts/pike/Cargo.toml
COPY contracts/product/Cargo.toml /build/contracts/product/Cargo.toml
COPY contracts/schema/Cargo.toml /build/contracts/schema/Cargo.toml
COPY contracts/track_and_trace/Cargo.toml /build/contracts/track_and_trace/Cargo.toml

# Copy over build files
COPY api /build/api
COPY config /build/config

# Build the dgc-api package
WORKDIR /build/api
ARG CARGO_ARGS
ARG REPO_VERSION
RUN sed -i -e "0,/version.*$/ s/version.*$/version\ =\ \"${REPO_VERSION}\"/" Cargo.toml
RUN cargo deb --deb-version $REPO_VERSION $CARGO_ARGS

# -------------=== dgc-api docker build ===-------------
FROM ubuntu:bionic

ARG CARGO_ARGS
RUN echo "CARGO_ARGS = '$CARGO_ARGS'" > CARGO_ARGS

COPY --from=gridd-builder /build/target/debian/*.deb /tmp

RUN apt-get update \
 && dpkg --unpack /tmp/*.deb \
 && apt-get -f -y install

#CMD ["dgc"]
