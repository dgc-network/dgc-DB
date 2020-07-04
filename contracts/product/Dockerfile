# Copyright (c) The dgc.network
# SPDX-License-Identifier: Apache-2.0

FROM hyperledger/grid-dev:v2 as grid-product-builder

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
COPY contracts/product /build/contracts/product
COPY sdk/ /build/sdk/

WORKDIR /build/contracts/product

# Build the contract
ARG REPO_VERSION
RUN sed -i -e "0,/version.*$/ s/version.*$/version\ =\ \"${REPO_VERSION}\"/" Cargo.toml
RUN cargo build --target wasm32-unknown-unknown --release

# Build a scar file
# Copy the packaging directory
COPY contracts/product/packaging/scar/* \
     /build/contracts/product/packaging/scar/

# Copy the contract to the packaging directory
RUN cp /build/target/wasm32-unknown-unknown/release/grid-product-tp.wasm \
    packaging/scar

WORKDIR /build/contracts/product/packaging/scar

# Create .scar file
RUN tar -jcvf /tmp/grid-product_${REPO_VERSION}.scar .

# -------------=== product submitter build ===-------------

FROM hyperledger/sawtooth-sabre-cli

COPY --from=grid-product-builder \
     /build/target/wasm32-unknown-unknown/release/grid-product-tp.wasm /tmp

# Copy the contract definition
COPY contracts/product/product.yaml /tmp

COPY --from=grid-product-builder \
    /tmp/grid-product*.scar /tmp
