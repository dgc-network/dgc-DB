// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::*;
use sawtooth_sdk::signing::CryptoFactory;
use sawtooth_sdk::signing::create_context;
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use sawtooth_sdk::signing::PrivateKey;
use sawtooth_sdk::processor::handler::ApplyError;
use serde::Deserialize;
use protobuf::Message;
use reqwest;

use crate::transaction::BatchBuilder;
use crate::error::RestApiResponseError;
use crate::{List, Fetch, split_vec};

use dgc_config::protos::*;
use dgc_config::addressing::*;
use dgc_config::protocol::pike::state::*;
use dgc_config::protocol::pike::payload::*;

#[derive(Deserialize)]
pub struct AgentData {
    private_key: String,
    org_id: String,
    active: String,
    roles: String,
    metadata: String,
}

pub struct JsonAgentData {
    org_id: String,
    //public_key: String,
    active: bool,
    roles: Vec<String>,
    metadata: Vec<KeyValueEntry>,
    //private_key: String,
}

pub async fn keygen(
) -> Result<HttpResponse, RestApiResponseError> {
    // Creating a Private Key and Signer //
    let context = create_context("secp256k1")
        .expect("Error creating the right context");
    let private_key = context.new_random_private_key()
        .expect("Error generating a new Private Key");
    let crypto_factory = CryptoFactory::new(context.as_ref());
    let signer = crypto_factory.new_signer(private_key.as_ref());
    let public_key = signer.get_public_key()
        .expect("Error retrieving Public Key");
    println!("============ create_key ============");
    println!("!dgc-network! private_key = {:?}", private_key.as_hex());
    println!("!dgc-network! public_key = {:?}", public_key.as_hex());

    let mut response_data = "".to_owned();
    response_data = response_data + &format!("{{\n  public_key: {:?}, \n  private_key: {:?}\n}}", public_key.as_hex(), private_key.as_hex());
    Ok(HttpResponse::Ok().body(response_data))
}

pub async fn list_agents(
) -> Result<HttpResponse, RestApiResponseError> {

    let url = format!("http://rest-api:8008/state?address={}", &get_agent_prefix());
    let list = reqwest::get(&url).await?.json::<List>().await?;
    let mut response_data = "[".to_owned();
    for sub in list.data {
        let msg = base64::decode(&sub.data).unwrap();
        let agents: pike_state::AgentList = match protobuf::parse_from_bytes(&msg){
            Ok(agents) => agents,
            Err(err) => {
                return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                    "Cannot deserialize data: {:?}",
                    err,
                ))))
            }
        };

        for agent in agents.get_agents() {
            println!("!dgc-network! response_data: ");
            println!("    public_key: {:?},", agent.public_key);
            println!("    org_id: {:?},", agent.org_id);
            println!("    roles: {:?},", agent.roles);
            println!("    metadata: {:?}", agent.metadata);
            
            response_data = response_data + &format!("\n  {{\n    public_key: {:?}, \n    org_id: {:?}, \n    roles: {:?}, \n    metadata: {:?} \n  }},\n", agent.public_key, agent.org_id, agent.roles, agent.metadata);
        }
    }
    response_data = response_data + &format!("]");
    Ok(HttpResponse::Ok().body(response_data))
}

pub async fn fetch_agent(
    public_key: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    let address = make_agent_address(&public_key);
    let url = format!("http://rest-api:8008/state/{}", address);
    let res = reqwest::get(&url).await?.json::<Fetch>().await?;
    let msg = base64::decode(&res.data).unwrap();
    let agents: pike_state::AgentList = match protobuf::parse_from_bytes(&msg){
        Ok(agents) => agents,
        Err(err) => {
            return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                "Cannot deserialize data: {:?}",
                err,
            ))))
        }
    };
    let mut response_data = "".to_owned();
    for agent in agents.get_agents() {
        println!("!dgc-network! response_data: ");
        println!("    public_key: {:?},", agent.public_key);
        println!("    org_id: {:?},", agent.org_id);
        println!("    roles: {:?},", agent.roles);
        println!("    metadata: {:?}", agent.metadata);
        
        response_data = response_data + &format!("{{\n  public_key: {:?}, \n  org_id: {:?}, \n  roles: {:?}, \n  metadata: {:?} \n}}", agent.public_key, agent.org_id, agent.roles, agent.metadata);
    }
    Ok(HttpResponse::Ok().body(response_data))
}

pub async fn create_agent(
    input_data: web::Json<AgentData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Creating the Payload //
    let private_key = &input_data.private_key;
    let public_key = retrieve_public_key(input_data);
    let org_id = &input_data.org_id;
    let roles = retrieve_roles(input_data);
    let metadata = retrieve_metadata(input_data);
/*
    org_id: String,
    public_key: String,
    active: bool,
    roles: Vec<String>,
    metadata: Vec<KeyValueEntry>,
*/
    // Building the Action and Payload//
    let action = CreateAgentActionBuilder::new()
        //.with_org_id(org_id.to_string())
        //.with_public_key(public_key.as_hex())
        //.with_active(true)
        //.with_roles(roles)
        //.with_metadata(metadata)
        .with_org_id(input_data.org_id)
        .with_public_key(public_key)
        .with_active(true)
        .with_roles(roles)
        .with_metadata(metadata)
        .build()
        .unwrap();

    let payload = PikePayloadBuilder::new()
        .with_action(Action::CreateAgent)
        .with_create_agent(action)
        .build()
        .map_err(|err| RestApiResponseError::UserError(format!("{}", err)))?;

        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            PIKE_FAMILY_NAME, 
            PIKE_FAMILY_VERSION, 
            //&private_key.as_hex(),
            private_key,
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

        //return Ok(batch_list_bytes);

        // Create batch_list_bytes //
    //let batch_list_bytes = match do_batches(input_data, Action::CreateAgent){
    //    Ok(agent) => agent,
    //    Err(err) => {
    //        return Err(RestApiResponseError::UserError(format!(
    //            "Cannot deserialize agent: {:?}",
    //            err,
    //        )))
    //    }
    //};

    // Submitting Batches to the Validator //
    let res = reqwest::Client::new()
        .post("http://rest-api:8008/batches")
        .header("Content-Type", "application/octet-stream")
        .body(batch_list_bytes)
        .send().await?
        .text().await?;

    println!("============ create_agent_link ============");
    println!("!dgc-network! submit_status = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

pub async fn update_agent(
    input_data: web::Json<AgentData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // create batch_list //
    let batch_list_bytes = match do_batches(input_data, Action::UpdateAgent){
        Ok(agent) => agent,
        Err(err) => {
            return Err(RestApiResponseError::UserError(format!(
                "Cannot deserialize agent: {:?}",
                err,
            )))
        }
    };

    // Submitting Batches to the Validator //
    let res = reqwest::Client::new()
        .post("http://rest-api:8008/batches")
        .header("Content-Type", "application/octet-stream")
        .body(batch_list_bytes)
        .send().await?
        .text().await?;

    println!("============ update_agent_link ============");
    println!("!dgc-network! submit_status = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

fn retrieve_public_key(
    input_data: web::Json<AgentData>,
) -> String {    
    // Retrieving a Private Key from the input_data //
    let private_key_as_hex = &input_data.private_key;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
    .expect("Error generating a Private Key");
    let context = create_context("secp256k1")
    .expect("Error creating the right context");
    let public_key = context.get_public_key(&private_key)
    .expect("Error retrieving a Public Key");
    return public_key.as_hex()
}

fn retrieve_roles(
    input_data: web::Json<AgentData>,
) -> Vec<String> {
    let roles_as_string = &input_data.roles;
    let roles: Vec<String> = roles_as_string.split(",").map(String::from).collect();
    return roles
}

fn retrieve_metadata(
    input_data: web::Json<AgentData>,
) -> Vec::<KeyValueEntry> {
    
    // Retrieving a Private Key from the input_data //
    let private_key_as_hex = &input_data.private_key;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
    .expect("Error generating a Private Key");
    let context = create_context("secp256k1")
    .expect("Error creating the right context");
    let public_key = context.get_public_key(&private_key)
    .expect("Error retrieving a Public Key");

    // Creating the Payload //
    let org_id = &input_data.org_id;
    let roles_as_string = &input_data.roles;
    let metadata_as_string = &input_data.metadata;

    let roles: Vec<String> = roles_as_string.split(",").map(String::from).collect();

    let mut metadata = Vec::<KeyValueEntry>::new();
    let vec: Vec<&str> = metadata_as_string.split(",").collect();
    let key_val_vec = split_vec(vec, 2);
    for key_val in key_val_vec {
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
    return metadata
}


fn do_batches(
    input_data: web::Json<AgentData>,
    action_plan: Action,
) -> Result<Vec<u8>, RestApiResponseError> {

    // Retrieving a Private Key from the input_data //
    let private_key_as_hex = &input_data.private_key;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
    .expect("Error generating a Private Key");
    let context = create_context("secp256k1")
    .expect("Error creating the right context");
    let public_key = context.get_public_key(&private_key)
    .expect("Error retrieving a Public Key");

    // Creating the Payload //
    let org_id = &input_data.org_id;
    let roles_as_string = &input_data.roles;
    let metadata_as_string = &input_data.metadata;

    let roles: Vec<String> = roles_as_string.split(",").map(String::from).collect();

    let mut metadata = Vec::<KeyValueEntry>::new();
    let vec: Vec<&str> = metadata_as_string.split(",").collect();
    let key_val_vec = split_vec(vec, 2);
    for key_val in key_val_vec {
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

    if action_plan == Action::CreateAgent {

        // Building the Action and Payload//
        let action = CreateAgentActionBuilder::new()
        .with_org_id(org_id.to_string())
        .with_public_key(public_key.as_hex())
        .with_active(true)
        .with_roles(roles)
        .with_metadata(metadata)
        .build()
        .unwrap();

        let payload = PikePayloadBuilder::new()
        .with_action(Action::CreateAgent)
        .with_create_agent(action)
        .build()
        .map_err(|err| RestApiResponseError::UserError(format!("{}", err)))?;

        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            PIKE_FAMILY_NAME, 
            PIKE_FAMILY_VERSION, 
            &private_key.as_hex(),
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

        return Ok(batch_list_bytes);

    } else {

        // Building the Action and Payload//
        let action = UpdateAgentActionBuilder::new()
        .with_org_id(org_id.to_string())
        .with_public_key(public_key.as_hex())
        .with_active(true)
        .with_roles(roles)
        .with_metadata(metadata)
        .build()
        .unwrap();

        let payload = PikePayloadBuilder::new()
        .with_action(Action::UpdateAgent)
        .with_update_agent(action)
        .build()
        .map_err(|err| RestApiResponseError::UserError(format!("{}", err)))?;

        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            PIKE_FAMILY_NAME, 
            PIKE_FAMILY_VERSION, 
            &private_key.as_hex(),
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

        return Ok(batch_list_bytes);
    }
}
