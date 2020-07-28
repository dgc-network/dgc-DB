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

use crypto::digest::Digest;
use crypto::sha2::Sha512;

const GRID_ADDRESS_LEN: usize = 70;
const GS1_NAMESPACE: &str = "01"; // Indicates GS1 standard
const PRODUCT_NAMESPACE: &str = "02"; // Indicates product under GS1 standard
const GRID_NAMESPACE: &str = "621dee"; // Grid prefix
pub const PIKE_NAMESPACE: &str = "cad11d";
pub const PIKE_AGENT_NAMESPACE: &str = "00";
pub const PIKE_ORG_NAMESPACE: &str = "01";

pub fn get_product_prefix() -> String {
    GRID_NAMESPACE.to_string()
}

pub fn hash(to_hash: &str, num: usize) -> String {
    let mut sha = Sha512::new();
    sha.input_str(to_hash);
    let temp = sha.result_str();
    let hash = temp.get(..num).expect("PANIC! Hashing Out of Bounds Error");
    hash.to_string()
}

pub fn make_product_address(product_id: &str) -> String {
    let grid_product_gs1_prefix = get_product_prefix() + PRODUCT_NAMESPACE + GS1_NAMESPACE;
    let grid_product_gs1_prefix_len = grid_product_gs1_prefix.chars().count();
    let hash_len = GRID_ADDRESS_LEN - grid_product_gs1_prefix_len;

    grid_product_gs1_prefix + &hash(product_id, hash_len)
}

/// Computes the address a Pike Agent is stored at based on its public_key
pub fn compute_agent_address(public_key: &str) -> String {
    let mut sha = Sha512::new();
    sha.input(public_key.as_bytes());

    String::from(PIKE_NAMESPACE) + PIKE_AGENT_NAMESPACE + &sha.result_str()[..62]
}

/// Computes the address a Pike Organization is stored at based on its identifier
pub fn compute_org_address(identifier: &str) -> String {
    let mut sha = Sha512::new();
    sha.input(identifier.as_bytes());

    String::from(PIKE_NAMESPACE) + PIKE_ORG_NAMESPACE + &sha.result_str()[..62]
}

const FAMILY_NAME: &str = "grid_track_and_trace";
const PROPERTY: &str = "ea";
const PROPOSAL: &str = "aa";
const RECORD: &str = "ec";
const GRID_NAMESPACE: &str = "621dee";
const GRID_SCHEMA_NAMESPACE: &str = "01";
const PIKE_NAMESPACE: &str = "cad11d";
const PIKE_AGENT_NAMESPACE: &str = "00";

pub fn get_track_and_trace_prefix() -> String {
    let mut sha = Sha512::new();
    sha.input_str(&FAMILY_NAME);
    sha.result_str()[..6].to_string()
}

pub fn get_grid_prefix() -> String {
    GRID_NAMESPACE.to_string()
}

pub fn get_pike_prefix() -> String {
    PIKE_NAMESPACE.to_string()
}

pub fn hash(to_hash: &str, num: usize) -> String {
    let mut sha = Sha512::new();
    sha.input_str(to_hash);
    let temp = sha.result_str();
    let hash = match temp.get(..num) {
        Some(x) => x,
        None => "",
    };
    hash.to_string()
}

pub fn make_record_address(record_id: &str) -> String {
    get_track_and_trace_prefix() + RECORD + &hash(record_id, 62)
}

pub fn make_property_address(record_id: &str, property_name: &str, page: u32) -> String {
    make_property_address_range(record_id) + &hash(property_name, 22) + &num_to_page_number(page)
}

pub fn make_property_address_range(record_id: &str) -> String {
    get_track_and_trace_prefix() + PROPERTY + &hash(record_id, 36)
}

/// Computes the address a Grid Schema is stored at based on its name
pub fn make_schema_address(name: &str) -> String {
    let mut sha = Sha512::new();
    sha.input(name.as_bytes());
    String::from(GRID_NAMESPACE) + GRID_SCHEMA_NAMESPACE + &sha.result_str()[..62].to_string()
}

/// Computes the address a Pike Agent is stored at based on its public_key
pub fn make_agent_address(public_key: &str) -> String {
    let mut sha = Sha512::new();
    sha.input(public_key.as_bytes());

    String::from(PIKE_NAMESPACE) + PIKE_AGENT_NAMESPACE + &sha.result_str()[..62].to_string()
}

pub fn num_to_page_number(page: u32) -> String {
    format!("{:01$x}", page, 4)
}

pub fn make_proposal_address(record_id: &str, agent_id: &str) -> String {
    get_track_and_trace_prefix() + PROPOSAL + &hash(record_id, 36) + &hash(agent_id, 26)
}
