// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::{web, HttpRequest, HttpResponse};
use sawtooth_sdk::signing::create_context;
use sawtooth_sdk::processor::handler::ApplyError;
use crypto::digest::Digest;
use crypto::sha2::Sha512;
use serde::Deserialize;
use protobuf::Message;
use reqwest;

use crate::transaction::BatchBuilder;
use crate::error::RestApiResponseError;
use crate::{List, Res};

use dgc_config::protocol::pike::{
    PIKE_NAMESPACE, PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION, PIKE_AGENT_NAMESPACE, 
    state::{
        KeyValueEntry, KeyValueEntryBuilder,
    },
    payload::{
        Action, PikePayloadBuilder, 
        CreateAgentActionBuilder, UpdateAgentActionBuilder, 
    },
};
use dgc_config::protos;
use dgc_config::protos::IntoProto;

#[derive(Deserialize)]
pub struct AgentInput {
    private_key: String,
    org_id: String,
    roles: String,
    metadata: String,
}

/// Computes the address a Pike Agent is stored at based on its public_key
pub fn compute_agent_address(public_key: &str) -> String {
    let mut sha = Sha512::new();
    sha.input(public_key.as_bytes());

    String::from(PIKE_NAMESPACE) + PIKE_AGENT_NAMESPACE + &sha.result_str()[..62]
}

pub async fn list_agents(
    //req: HttpRequest,
) -> Result<HttpResponse, RestApiResponseError> {

    let url = format!("http://rest-api:8008/state?address={}{}", PIKE_NAMESPACE, PIKE_AGENT_NAMESPACE);
    let list = reqwest::get(&url).await?.json::<List>().await?;
    for sub in list.data.iter() {
        let msg = base64::decode(&sub.data).unwrap();
        println!("============ list_org_1 ============");
        println!("!dgc-network! data = {:?}", sub.data);
        println!("!dgc-network! bytes = {:?}", msg);

        let agent: protos::pike_state::Agent = match protobuf::parse_from_bytes(&msg){
            Ok(agent) => agent,
            Err(err) => {
                return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                    "Cannot deserialize organization: {:?}",
                    err,
                ))))
            }
        };
        println!("serialized: {:?}", agent);
        //println!("!dgc-network! org = {:?}", org);
    }

    println!("============ list_org ============");
    println!("!dgc-network! link = {:?}", list.link);
    Ok(HttpResponse::Ok().body(list.link))
    
    //Ok(HttpResponse::Ok().body("Hello world! list_agent"))

}

pub async fn fetch_agent(
    public_key: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    println!("!dgc-network! public_key = {:?}", public_key);
    let address = compute_agent_address(&public_key);
    let url = format!("http://rest-api:8008/state/{}", address);
    let res = reqwest::get(&url).await?.json::<Res>().await?;
    let msg = base64::decode(&res.data).unwrap();
    println!("============ fetch_org_2 ============");
    println!("!dgc-network! data = {:?}", res.data);
    println!("!dgc-network! bytes = {:?}", msg);

    let agent: protos::pike_state::Agent = match protobuf::parse_from_bytes(&msg){
        Ok(agent) => agent,
        Err(err) => {
            return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                "Cannot deserialize organization: {:?}",
                err,
            ))))
        }
    };
    println!("serialized: {:?}", agent);
    //println!("!dgc-network! org = {:?}", org);

    println!("============ fetch_org ============");
    println!("!dgc-network! link = {:?}", res.link);
    Ok(HttpResponse::Ok().body(res.link))

    //Ok(HttpResponse::Ok().body("Hello world! fetch_agent"))

}

pub async fn create_agent(
    //req: HttpRequest,
    agent_input: web::Json<AgentInput>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Creating a Private Key and Signer //
    let context = create_context("secp256k1")
        .expect("Error creating the right context");
    let private_key = context.new_random_private_key()
        .expect("Error generating a new Private Key");
    let public_key = context.get_public_key(private_key.as_ref())
        .expect("Error generating a new Public Key");

    // Creating the Payload //
    let org_id = &agent_input.org_id;
    let roles_as_string = &agent_input.roles;
    let metadata_as_string = &agent_input.metadata;

    let mut roles = Vec::<String>::new();
    for role in roles_as_string.chars() {
        let entry: String = role.to_string().split(",").collect();
        roles.push(entry.clone());
    }

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

    // Building the Transaction //
    // Building the Batch //
    let batch_list = BatchBuilder::new(
        PIKE_FAMILY_NAME, 
        PIKE_FAMILY_VERSION, 
        &private_key.as_hex()
    )
    .add_transaction(
        &payload.into_proto()?,
        &[PIKE_NAMESPACE.to_string()],
        &[PIKE_NAMESPACE.to_string()],
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
        .send()
        .await?
        .text()
        .await?;

    println!("============ create_agent ============");
    println!("!dgc-network! private_key = {:?}", private_key.as_hex());
    println!("!dgc-network! public_key = {:?}", public_key.as_hex());
    println!("!dgc-network! res = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

pub async fn update_agent(
    req: HttpRequest,
    agent_input: web::Json<AgentInput>,
) -> Result<HttpResponse, RestApiResponseError> {
/*
    let response_url = req.url_for_static("agent")?;

    let private_key_as_hex = &agent_input.private_key;
    let org_id = &agent_input.org_id;
    let roles_as_string = &agent_input.roles;
    let metadata_as_string = &agent_input.metadata;

    let context = Secp256k1Context::new();
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
        .expect("Error generating a new Private Key");
    let public_key = context.get_public_key(&private_key)
        .expect("Error generating a new Public Key");

    println!("============ update_agent ============");
    println!("!dgc-network! private_key = {:?}", private_key.as_hex());
    println!("!dgc-network! public_key = {:?}", public_key.as_hex());
    println!("!dgc-network! org_id = {:?}", org_id);
    println!("!dgc-network! roles = {:?}", roles_as_string);
    println!("!dgc-network! metadata = {:?}", metadata_as_string);

    let mut roles = Vec::<String>::new();
    for role in roles_as_string.chars() {
        let entry: String = role.to_string().split(",").collect();
        roles.push(entry.clone());
    }

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

    let batch_list = BatchBuilder::new(PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION, &private_key.as_hex())
        .add_transaction(
            &payload.into_proto()?,
            &[PIKE_NAMESPACE.to_string()],
            &[PIKE_NAMESPACE.to_string()],
        )?
        .create_batch_list();

    println!("!dgc-network! batch_list = {:?}", batch_list);
    println!("!dgc-network! response_url = {:?}", response_url);

    //let mock_sender = MockMessageSender::new(ResponseType::ClientBatchSubmitResponseOK);
    //let mock_batch_submitter = Box::new(MockBatchSubmitter {
    //    sender: mock_sender,
    //});

    //let batch_submitter = Box::new(SplinterBatchSubmitter::new(config.endpoint().url()));
    let batch_submitter = Box::new(SplinterBatchSubmitter::new(response_url.to_string()));

    //mock_batch_submitter
    batch_submitter
        .submit_batches(SubmitBatches {
            batch_list,
            response_url,
            //service_id: query_service_id.into_inner().service_id,
        })
        .await
        .map(|link| HttpResponse::Ok().json(link))
*/

    Ok(HttpResponse::Ok().body("Hello world! create_agent"))
}
