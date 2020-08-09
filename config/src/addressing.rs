// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use crypto::digest::Digest;
use crypto::sha2::Sha512;

pub const SABRE_FAMILY_NAME: &str = "sabre";
pub const SABRE_FAMILY_VERSION: &str = "0.5";
pub const SABRE_NAMESPACE_REGISTRY_PREFIX: &str = "00ec00";
pub const SABRE_CONTRACT_REGISTRY_PREFIX: &str = "00ec01";
pub const SABRE_CONTRACT_PREFIX: &str = "00ec02";

//const GRID_ADDRESS_LEN: usize = 70;
pub const GRID_NAMESPACE: &str = "621dee";

pub const PIKE_FAMILY_NAME: &str = "pike";
pub const PIKE_FAMILY_VERSION: &str = "0.1";
//pub const PIKE_NAMESPACE: &str = "cad11d";
pub const PIKE_AGENT_NAMESPACE: &str = "00";
pub const PIKE_ORG_NAMESPACE: &str = "01";

pub const PRODUCT_FAMILY_NAME: &str = "grid_product";
pub const PRODUCT_FAMILY_VERSION: &str = "1.0";
pub const PRODUCT_GS1_NAMESPACE: &str = "01"; // Indicates GS1 standard
//pub const PRODUCT_NAMESPACE: &str = "02"; // Indicates product under GS1 standard

pub const SCHEMA_FAMILY_NAME: &str = "grid_schema";
pub const SCHEMA_FAMILY_VERSION: &str = "1.0";
const GRID_SCHEMA_NAMESPACE: &str = "01";

pub const TNT_FAMILY_NAME: &str = "grid_track_and_trace";
pub const TNT_FAMILY_VERSION: &str = "1.0";
const PROPERTY: &str = "ea";
const PROPOSAL: &str = "aa";
const RECORD: &str = "ec";

pub fn hash(to_hash: &str, num: usize) -> String {
    let mut sha = Sha512::new();
    sha.input_str(to_hash);
    let temp = sha.result_str();
    let hash = temp.get(..num).expect("PANIC! Hashing Out of Bounds Error");
    hash.to_string()
}

pub fn get_pike_prefix() -> String {
    hash(&PIKE_FAMILY_NAME, 6)
}

pub fn get_agent_prefix() -> String {
    get_pike_prefix() + PIKE_AGENT_NAMESPACE
}

pub fn make_agent_address(public_key: &str) -> String {
    get_agent_prefix() + &hash(public_key, 62)
}

pub fn get_org_prefix() -> String {
    get_pike_prefix() + PIKE_ORG_NAMESPACE
}

pub fn make_org_address(identifier: &str) -> String {
    get_org_prefix() + &hash(identifier, 62)
}

pub fn get_product_prefix() -> String {
    hash(&PRODUCT_FAMILY_NAME, 6) + PRODUCT_GS1_NAMESPACE
}

pub fn make_product_address(product_id: &str) -> String {
    get_product_prefix() + &hash(product_id, 62)
}

pub fn get_schema_prefix() -> String {
    hash(&SCHEMA_FAMILY_NAME, 6) + GRID_SCHEMA_NAMESPACE
}

pub fn make_schema_address(name: &str) -> String {
    get_schema_prefix() + &hash(name, 62)
}

pub fn get_track_and_trace_prefix() -> String {
    hash(&TNT_FAMILY_NAME, 6)
}

pub fn get_record_prefix() -> String {
    get_track_and_trace_prefix() + RECORD
}

pub fn make_record_address(record_id: &str) -> String {
    get_record_prefix() + &hash(record_id, 62)
}

pub fn make_property_address_range(record_id: &str) -> String {
    get_track_and_trace_prefix() + PROPERTY + &hash(record_id, 36)
}

pub fn num_to_page_number(page: u32) -> String {
    format!("{:01$x}", page, 4)
}

pub fn make_property_address(record_id: &str, property_name: &str, page: u32) -> String {
    make_property_address_range(record_id) + &hash(property_name, 22) + &num_to_page_number(page)
}

pub fn get_proposal_prefix() -> String {
    get_track_and_trace_prefix() + PROPOSAL
}

pub fn make_proposal_address(record_id: &str, agent_id: &str) -> String {
    get_proposal_prefix() + &hash(record_id, 36) + &hash(agent_id, 26)
}
