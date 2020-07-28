// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

// Required due to a bug in rust-protobuf: https://github.com/stepancheg/rust-protobuf/issues/331
#![allow(renamed_and_removed_lints)]

#[macro_use]
extern crate cfg_if;

pub mod permissions;
pub mod protocol;
pub mod protos;
pub mod addressing;
