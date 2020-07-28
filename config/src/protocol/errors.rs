// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug)]
pub enum BuilderError {
    MissingField(String),
}

impl std::fmt::Display for BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            BuilderError::MissingField(ref s) => write!(f, "MissingField: {}", s),
        }
    }
}
