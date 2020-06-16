// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use actix_web::{web, HttpRequest, HttpResponse};
use sawtooth_sdk::signing::CryptoFactory;
use sawtooth_sdk::signing::create_context;

use crate::Endpoint;
use crate::transaction::BatchBuilder;
use crate::connection::SawtoothConnection;
use crate::submitter::{BatchStatusResponse, BatchStatuses, SubmitBatches, DEFAULT_TIME_OUT};
use crate::submitter::{BatchSubmitter, SawtoothBatchSubmitter};
use crate::error::RestApiResponseError;

use grid_sdk::protocol::pike::{
    PIKE_NAMESPACE, PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION,
    state::{
        KeyValueEntry, KeyValueEntryBuilder, Agent,
    },
    payload::{
        Action, PikePayloadBuilder, CreateAgentActionBuilder, 
        //CreateAgentAction, UpdateAgentAction, UpdateAgentActionBuilder, 
    },
};
use grid_sdk::protos::IntoProto;
use grid_sdk::protos::IntoBytes;

//use serde::{Deserialize, Serialize};

//#[derive(Debug, Serialize, Deserialize)]
use serde::Deserialize;

#[derive(Deserialize)]
pub struct AgentInput {
    private_key: String,
    org_id: String,
    roles: String,
    metadata: String,
}

pub async fn list_agents(
    req: HttpRequest,
    //agent_input: web::Json<AgentInput>,
) -> Result<HttpResponse, RestApiResponseError> {

    //let private_key = &agent_input.private_key;
    //let org_id = &agent_input.org_id;
    //let roles_as_string = &agent_input.roles;
    //let metadata_as_string = &agent_input.metadata;

    // Get the URL
    let response_url = match req.url_for_static("agent") {
        Ok(url) => format!("{}?{}", url, req.query_string()),
        Err(err) => {
            return Err(err.into());
        }
    };

    Ok(HttpResponse::Ok().body("Hello world! list_agents"))

}

use super::state::{MockTransactionContext, State};

pub async fn fetch_agent(
    public_key: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    let mut transaction_context = MockTransactionContext::default();
    let state = State::new(&mut transaction_context);
    let result = state.get_agent(&public_key).unwrap();
    let agent = result.unwrap();
    let org_id = Agent::org_id;
    match org_id {
        org_id => agent.org_id(),
        _ => "Hello world! fetch_agent",
        //Some(org_id) => agent.org_id().to_string(),
        //None => "Hello world! fetch_agent".to_string()
    };
    Ok(HttpResponse::Ok().body(org_id))
    //let org_id = agent.org_id();
    //Ok(HttpResponse::Ok().body("Hello world! fetch_agent"))
/*

    Ok(HttpResponse::Ok().json(agent.org_id()))
*/
    //Ok(HttpResponse::Ok().body("Hello world! fetch_agent"))
}

pub async fn create_agent(
    req: HttpRequest,
    //query: web::Query<HashMap<String, String>>,
    agent_input: web::Json<AgentInput>,
    //info: web::Json<Info>,
) -> Result<HttpResponse, RestApiResponseError> {

    let context = create_context("secp256k1")?;
    let private_key = context.new_random_private_key()?.as_hex();

    //let private_key = &agent_input.private_key;
    let org_id = &agent_input.org_id;
    let roles_as_string = &agent_input.roles;
    let metadata_as_string = &agent_input.metadata;
    //Ok(HttpResponse::Ok().body(org_id))

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
        .with_public_key("public_key".to_string())
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
/*
    let private_key = match query.get("private_key") {
        Some(private_key) => Some(private_key.as_str().to_string()),
        None => Some("".to_string()),
    };
*/

    //let batch_list = BatchBuilder::new(PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION, Some(private_key.to_string()))
    let batch_list = BatchBuilder::new(PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION, &private_key)
        .add_transaction(
            &payload.into_proto()?,
            &[PIKE_NAMESPACE.to_string()],
            &[PIKE_NAMESPACE.to_string()],
        )?
        .create_batch_list();

    let response_url = req.url_for_static("agent")?;
    
    let sawtooth_connection = SawtoothConnection::new(&response_url.to_string());

    let batch_submitter = Box::new(SawtoothBatchSubmitter::new(
        sawtooth_connection.get_sender(),
    ));

    //Ok(HttpResponse::Ok().body("Hello world! I am here to create_agent"))


    batch_submitter
        .submit_batches(SubmitBatches {
            batch_list,
            response_url,
            //service_id: query_service_id.into_inner().service_id,
        })
        .await
        .map(|link| HttpResponse::Ok().json(link))


    //Ok(HttpResponse::Ok().body("Hello world! create_agent"))
}

pub async fn update_agent(
    //url: &str,
    //key: Option<String>,
    //wait: u64,
    //update_agent: web::Json<UpdateAgentAction>,
    //service_id: Option<String>,
//) -> Result<(), CliError> {
) -> Result<HttpResponse, RestApiResponseError> {
    Ok(HttpResponse::Ok().body("Hello world! update_agent"))
/*
    let payload = PikePayloadBuilder::new()
        .with_action(Action::UpdateAgent)
        .with_update_agent(update_agent)
        .build()
        .map_err(|err| CliError::UserError(format!("{}", err)))?;

    let batch_list = pike_batch_builder(key)
        .add_transaction(
            &payload.into_proto()?,
            &[PIKE_NAMESPACE.to_string()],
            &[PIKE_NAMESPACE.to_string()],
        )?
        .create_batch_list();

    submit_batches(url, wait, &batch_list, service_id.as_deref())
*/    
}
