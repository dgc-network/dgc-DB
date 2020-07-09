# Copyright (c) The dgc.network
# SPDX-License-Identifier: Apache-2.0

FROM hyperledger/grid-dev:v2 as grid-pike-builder

# Copy over Cargo.toml files
COPY Cargo.toml /build/Cargo.toml
COPY api/Cargo.toml /build/api/Cargo.toml
#COPY cli/Cargo.toml /build/cli/Cargo.toml
#COPY daemon/Cargo.toml /build/daemon/Cargo.toml
COPY sdk/Cargo.toml /build/sdk/Cargo.toml

COPY contracts/pike/Cargo.toml /build/contracts/pike/Cargo.toml
COPY contracts/product/Cargo.toml /build/contracts/product/Cargo.toml
COPY contracts/schema/Cargo.toml /build/contracts/schema/Cargo.toml
COPY contracts/track_and_trace/Cargo.toml /build/contracts/track_and_trace/Cargo.toml

# Copy over build files
COPY contracts/pike /build/contracts/pike
COPY sdk/ /build/sdk/

WORKDIR /build/contracts/pike

# Build the contract
ARG REPO_VERSION
RUN sed -i -e "0,/version.*$/ s/version.*$/version\ =\ \"${REPO_VERSION}\"/" Cargo.toml
RUN cargo build --target wasm32-unknown-unknown --release

# Build a scar file
# Copy the packaging directory
COPY contracts/pike/packaging/scar/* \
     /build/contracts/pike/packaging/scar/

# Copy the contract to the packaging directory
RUN cp /build/target/wasm32-unknown-unknown/release/grid-pike-tp.wasm \
    packaging/scar

WORKDIR /build/contracts/pike/packaging/scar

# Create .scar file
RUN tar -jcvf /tmp/grid-pike_${REPO_VERSION}.scar .

# -------------=== pike submitter build ===-------------

FROM hyperledger/sawtooth-sabre-cli

COPY --from=grid-pike-builder \
     /build/target/wasm32-unknown-unknown/release/grid-pike-tp.wasm /tmp

# Copy the contract definition
COPY contracts/pike/pike.yaml /tmp

COPY --from=grid-pike-builder \
    /tmp/grid-pike*.scar /tmp
