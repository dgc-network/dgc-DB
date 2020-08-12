// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::*;
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use sawtooth_sdk::signing::PrivateKey;
use sawtooth_sdk::processor::handler::ApplyError;
use serde::{Deserialize, Serialize};
use protobuf::Message;
use reqwest;
use base64;

use crate::transaction::BatchBuilder;
use crate::error::RestApiResponseError;
use crate::{List, Fetch};

use dgc_config::protos::*;
use dgc_config::addressing::*;
use dgc_config::protocol::pike::state::*;
use dgc_config::protocol::pike::payload::*;

//#[derive(Deserialize)]
#[derive(Serialize, Deserialize)]
pub struct OrgData {
    private_key: String,
    org_id: String,
    name: String,
    address: String,
    metadata: String,
}

pub async fn list_orgs(
) -> Result<HttpResponse, RestApiResponseError> {

    let url = format!("http://rest-api:8008/state?address={}", &get_org_prefix());
    let list = reqwest::get(&url).await?.json::<List>().await?;
    let mut response_data = "[".to_owned();
    for sub in list.data {
        let msg = base64::decode(&sub.data).unwrap();
        let orgs: pike_state::OrganizationList = match protobuf::parse_from_bytes(&msg){
            Ok(orgs) => orgs,
            Err(err) => {
                return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                    "Cannot deserialize data: {:?}",
                    err,
                ))))
            }
        };

        for org in orgs.get_organizations() {
            println!("!dgc-network! response_data: ");
            println!("    org_id: {:?},", org.org_id);
            println!("    name: {:?},", org.name);
            println!("    address: {:?},", org.address);
            println!("    metadata: {:?}", org.metadata);
            
            response_data = response_data + &format!("\n  {{\n    org_id: {:?}, \n    name: {:?}, \n    address: {:?}, \n    metadata: {:?} \n  }},\n", org.org_id, org.name, org.address, org.metadata);
        }
    }
    response_data = response_data + &format!("]");
    Ok(HttpResponse::Ok().body(response_data))
}

pub async fn fetch_org(
    org_id: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    println!("!dgc-network! org_id = {:?}", org_id);
    println!("============ fetch_org_1 ============");
    let address = make_org_address(&org_id);
    let url = format!("http://rest-api:8008/state/{}", address);
    let res = reqwest::get(&url).await?.json::<Fetch>().await?;
    let msg = base64::decode(&res.data).unwrap();
    let agents: pike_state::OrganizationList = match protobuf::parse_from_bytes(&msg){
        Ok(orgs) => orgs,
        Err(err) => {
            return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                "Cannot deserialize agent: {:?}",
                err,
            ))))
        }
    };
    let mut response_data = "".to_owned();
    for org in orgs.get_orgs() {
        println!("!dgc-network! response_data: ");
        println!("    org_id: {:?},", org.org_id);
        println!("    name: {:?},", org.name);
        println!("    address: {:?},", org.address);
        println!("    metadata: {:?}", org.metadata);
        
        response_data = response_data + &format!("{{\n  org_id: {:?}, \n  name: {:?}, \n  address: {:?}, \n  metadata: {:?} \n}}", org.org_id, org.name, org.address, org.metadata);
    }
    Ok(HttpResponse::Ok().body(response_data))
}

pub async fn create_org(
    input_data: web::Json<OrgData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Creating a Private Key and Signer //
    let private_key_as_hex = &input_data.private_key;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
        .expect("Error generating a new Private Key");

    // Creating the Payload //
    let org_id = &input_data.org_id;
    let name = &input_data.name;
    let address = &input_data.address;
    let metadata_as_string = &input_data.metadata;

    let mut metadata = Vec::<KeyValueEntry>::new();
    for meta in metadata_as_string.chars() {
        let meta_as_string = meta.to_string();
        let key_val: Vec<&str> = meta_as_string.split(",").collect();
        if key_val.len() != 2 {
            "Metadata is formated incorrectly".to_string();            
        }
        let key = match key_val.get(0) {
            Some(key) => key.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };
        let value = match key_val.get(1) {
            Some(value) => value.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };

        let key_value = KeyValueEntryBuilder::new()
            .with_key(key.to_string())
            .with_value(value.to_string())
            .build()
            .unwrap();

        metadata.push(key_value.clone());
    }

    let action = CreateOrganizationActionBuilder::new()
        .with_org_id(org_id.to_string())
        .with_name(name.to_string())
        .with_address(address.to_string())
        .with_metadata(metadata)
        .build()
        .unwrap();

    let payload = PikePayloadBuilder::new()
        .with_action(Action::CreateOrganization)
        .with_create_organization(action)
        .build()
        .map_err(|err| RestApiResponseError::UserError(format!("{}", err)))?;

    // Building the Transaction and Batch //
    let batch_list = BatchBuilder::new(
        PIKE_FAMILY_NAME, 
        PIKE_FAMILY_VERSION, 
        &private_key.as_hex()
    )
    .add_transaction(
        &payload.into_proto()?,
        &[get_pike_prefix()],
        &[get_pike_prefix()],
    )?
    .create_batch_list();

    let batch_list_bytes = batch_list
        .write_to_bytes()
        .expect("Error converting batch list to bytes");

    // Submitting Batches to the Validator //
    let res = reqwest::Client::new()
        .post("http://rest-api:8008/batches")
        .header("Content-Type", "application/octet-stream")
        .body(batch_list_bytes)
        .send().await?
        .text().await?;

    println!("============ create_organization ============");
    println!("!dgc-network! res = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

pub async fn update_org(
    input_data: web::Json<OrgData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Creating a Private Key and Signer //
    let private_key_as_hex = &input_data.private_key;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
        .expect("Error generating a new Private Key");

    // Creating the Payload //
    let org_id = &input_data.org_id;
    let name = &input_data.name;
    let address = &input_data.address;
    let metadata_as_string = &input_data.metadata;

    let mut metadata = Vec::<KeyValueEntry>::new();
    for meta in metadata_as_string.chars() {
        let meta_as_string = meta.to_string();
        let key_val: Vec<&str> = meta_as_string.split(",").collect();
        if key_val.len() != 2 {
            "Metadata is formated incorrectly".to_string();            
        }
        let key = match key_val.get(0) {
            Some(key) => key.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };
        let value = match key_val.get(1) {
            Some(value) => value.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };

        let key_value = KeyValueEntryBuilder::new()
            .with_key(key.to_string())
            .with_value(value.to_string())
            .build()
            .unwrap();

        metadata.push(key_value.clone());
    }

    let action = UpdateOrganizationActionBuilder::new()
        .with_org_id(org_id.to_string())
        .with_name(name.to_string())
        .with_address(address.to_string())
        .with_metadata(metadata)
        .build()
        .unwrap();

    let payload = PikePayloadBuilder::new()
        .with_action(Action::UpdateOrganization)
        .with_update_organization(action)
        .build()
        .map_err(|err| RestApiResponseError::UserError(format!("{}", err)))?;

    // Building the Transaction and Batch //
    let batch_list = BatchBuilder::new(
        PIKE_FAMILY_NAME, 
        PIKE_FAMILY_VERSION, 
        &private_key.as_hex()
    )
    .add_transaction(
        &payload.into_proto()?,
        &[get_pike_prefix()],
        &[get_pike_prefix()],
    )?
    .create_batch_list();

    let batch_list_bytes = batch_list
        .write_to_bytes()
        .expect("Error converting batch list to bytes");

    // Submitting Batches to the Validator //
    let res = reqwest::Client::new()
        .post("http://rest-api:8008/batches")
        .header("Content-Type", "application/octet-stream")
        .body(batch_list_bytes)
        .send().await?
        .text().await?;

    println!("============ update_organization ============");
    println!("!dgc-network! res = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}
