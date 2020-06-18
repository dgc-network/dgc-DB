// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::{web, HttpRequest, HttpResponse};
//use sawtooth_sdk::signing::CryptoFactory;
use sawtooth_sdk::signing::create_context;
use sawtooth_sdk::signing::secp256k1::Secp256k1Context;
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use serde::Deserialize;

use crate::transaction::BatchBuilder;
use crate::submitter::{BatchSubmitter, SubmitBatches};
use crate::submitter::{MockBatchSubmitter, MockMessageSender, ResponseType};
use super::state::{MockTransactionContext, MockState};
use crate::error::RestApiResponseError;

use grid_sdk::protocol::pike::{
    PIKE_NAMESPACE, PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION,
    state::{
        KeyValueEntry, KeyValueEntryBuilder,
    },
    payload::{
        Action, PikePayloadBuilder, 
        CreateAgentActionBuilder, UpdateAgentActionBuilder, 
    },
};
use grid_sdk::protos::IntoProto;

#[derive(Deserialize)]
pub struct AgentInput {
    private_key: String,
    org_id: String,
    roles: String,
    metadata: String,
}

pub async fn list_agents(
    req: HttpRequest,
) -> Result<HttpResponse, RestApiResponseError> {
    // Get the URL
    let response_url = match req.url_for_static("agent") {
        Ok(url) => format!("{}?{}", url, req.query_string()),
        Err(err) => {
            return Err(err.into());
        }
    };

    Ok(HttpResponse::Ok().body("Hello world! list_agents"))

}

pub async fn fetch_agent(
    public_key: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    let mut transaction_context = MockTransactionContext::default();
    let state = MockState::new(&mut transaction_context);
    //let result = state.get_agent(&public_key).unwrap();
    let result = match state.get_agent(&public_key){
        Ok(x)  => {
            if x != None {
                x.unwrap();
            } else {
                return Err(RestApiResponseError::BadRequest(format!(
                    "Cannot find the data for public_key : {:?}",
                    public_key.to_string()
                )));
            }
        }
        Err(e) => return Err(e),
    };
    //let org_id = result.org_id();
    //let agent = result.unwrap();
    //let org_id = agent.org_id();
    println!("I am here! result : {:?}", result);

    Ok(HttpResponse::Ok().body("Hello world! fetch_agent"))

}

pub async fn create_agent(
    req: HttpRequest,
    agent_input: web::Json<AgentInput>,
) -> Result<HttpResponse, RestApiResponseError> {

    //let context = create_context("secp256k1")?;
    let context = Secp256k1Context.new()?;
    let private_key = context.new_random_private_key()?;
    let public_key_hex = context.get_public_key(&private_key)?.as_hex();

    //let private_key = &agent_input.private_key;
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
        .with_public_key(public_key_hex.to_string())
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

    let batch_list = BatchBuilder::new(PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION, &private_key.as_hex())
        .add_transaction(
            &payload.into_proto()?,
            &[PIKE_NAMESPACE.to_string()],
            &[PIKE_NAMESPACE.to_string()],
        )?
        .create_batch_list();

    let response_url = req.url_for_static("agent")?;

    let mock_sender = MockMessageSender::new(ResponseType::ClientBatchSubmitResponseOK);
    let mock_batch_submitter = Box::new(MockBatchSubmitter {
        sender: mock_sender,
    });

    mock_batch_submitter
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
    req: HttpRequest,
    agent_input: web::Json<AgentInput>,
) -> Result<HttpResponse, RestApiResponseError> {

    let private_key_hex = &agent_input.private_key;
    let org_id = &agent_input.org_id;
    let roles_as_string = &agent_input.roles;
    let metadata_as_string = &agent_input.metadata;

    let context = create_context("secp256k1")?;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_hex)?;
    let public_key_hex = context.get_public_key(&private_key)?.as_hex();


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
        .with_public_key(public_key_hex.to_string())
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

    let batch_list = BatchBuilder::new(PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION, &private_key_hex)
        .add_transaction(
            &payload.into_proto()?,
            &[PIKE_NAMESPACE.to_string()],
            &[PIKE_NAMESPACE.to_string()],
        )?
        .create_batch_list();

    let response_url = req.url_for_static("agent")?;

    let mock_sender = MockMessageSender::new(ResponseType::ClientBatchSubmitResponseOK);
    let mock_batch_submitter = Box::new(MockBatchSubmitter {
        sender: mock_sender,
    });

    mock_batch_submitter
        .submit_batches(SubmitBatches {
            batch_list,
            response_url,
            //service_id: query_service_id.into_inner().service_id,
        })
        .await
        .map(|link| HttpResponse::Ok().json(link))


    //Ok(HttpResponse::Ok().body("Hello world! create_agent"))
}
/*
pub async fn update_agent(
    //url: &str,
    //key: Option<String>,
    //wait: u64,
    //update_agent: web::Json<UpdateAgentAction>,
    //service_id: Option<String>,
//) -> Result<(), CliError> {
) -> Result<HttpResponse, RestApiResponseError> {
    Ok(HttpResponse::Ok().body("Hello world! update_agent"))

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
    
}
*/