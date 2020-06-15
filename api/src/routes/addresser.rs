// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

/// Represents part of address that designates resource type
#[derive(Debug)]
pub enum Resource {
    AGENT,
    ORG,
}

/// Convert resource part to byte value in hex
pub fn resource_to_byte(part: Resource) -> String {
    match part {
        Resource::AGENT => String::from("00"),
        Resource::ORG => String::from("01"),
    }
}

/// Convert byte string to Resource
pub fn byte_to_resource(bytes: &str) -> Result<Resource, ResourceError> {
    match bytes {
        "00" => Ok(Resource::AGENT),
        "01" => Ok(Resource::ORG),
        _ => Err(ResourceError::UnknownResource(format!(
            "No resource found matching byte pattern {}",
            bytes
        ))),
    }
}

#[derive(Debug)]
pub enum ResourceError {
    UnknownResource(String),
}
