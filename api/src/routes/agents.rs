// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use actix_web::{web, HttpRequest, HttpResponse};

use crate::Endpoint;
use crate::transaction::BatchBuilder;
use crate::connection::SawtoothConnection;
use crate::submitter::{BatchStatusResponse, BatchStatuses, SubmitBatches, DEFAULT_TIME_OUT};
use crate::submitter::{BatchSubmitter, SawtoothBatchSubmitter};
use crate::error::RestApiResponseError;

use grid_sdk::protocol::pike::{
    PIKE_NAMESPACE, PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION,
    state::{
        KeyValueEntry, KeyValueEntryBuilder,
    },
    payload::{
        Action, PikePayloadBuilder, CreateAgentActionBuilder, 
        //CreateAgentAction, UpdateAgentAction, UpdateAgentActionBuilder, 
    },
};
use grid_sdk::protos::IntoProto;

pub async fn list_agents(
    req: HttpRequest,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Max wait time allowed is 95% of network's configured timeout
    let max_wait_time = (DEFAULT_TIME_OUT * 95) / 100;

    let wait = match query.get("wait") {
        Some(wait_time) => {
            if wait_time == "false" {
                None
            } else {
                match wait_time.parse::<u32>() {
                    Ok(wait_time) => {
                        if wait_time > max_wait_time {
                            Some(max_wait_time)
                        } else {
                            Some(wait_time)
                        }
                    }
                    Err(_) => {
                        return Err(RestApiResponseError::BadRequest(format!(
                            "Query wait has invalid value {}. \
                             It should set to false or a time in seconds to wait for the commit",
                            wait_time
                        )));
                    }
                }
            }
        }

        None => Some(max_wait_time),
    };

    Ok(HttpResponse::Ok().body(wait.unwrap().to_string()))
/*
    // Get the Batch ID
    let batch_ids = match query.get("id") {
        Some(ids) => ids.split(',').map(ToString::to_string).collect(),
        None => {
            return Err(RestApiResponseError::BadRequest(
                "Request for statuses missing id query.".to_string(),
            ));
        }
    };

    // Get the URL
    let response_url = match req.url_for_static("agent") {
        Ok(url) => format!("{}?{}", url, req.query_string()),
        Err(err) => {
            //return Err(err.into());
            return Err(RestApiResponseError::BadRequest("I am here.".to_string(),));
            //return Err(RestApiResponseError::BadRequest(req.query_string().to_string(),));
        }
    };

    let sawtooth_connection = SawtoothConnection::new(&response_url);

    let batch_submitter = Box::new(SawtoothBatchSubmitter::new(
        sawtooth_connection.get_sender(),
    ));

    batch_submitter
        .batch_status(BatchStatuses {
            batch_ids,
            wait,
            //service_id: query_service_id.into_inner().service_id,
        })
        .await
        .map(|batch_statuses| {
            HttpResponse::Ok().json(BatchStatusResponse {
                data: batch_statuses,
                link: response_url,
            })
        })
*/
    //Ok(HttpResponse::Ok().body("Hello world! list_agents"))

}

pub async fn fetch_agent(
    public_key: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {
    Ok(HttpResponse::Ok().body("Hello world! fetch_agent"))
}

pub async fn create_agent(
    req: HttpRequest,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, RestApiResponseError> {

    let org_id = match query.get("org_id") {
        Some(org_id) => org_id.to_string(),
        None => "".to_string(),
    };

    let roles_as_string = match query.get("roles_as_string") {
        Some(roles_as_string) => roles_as_string.to_string(),
        None => "".to_string(),
    };

    let metadata_as_string = match query.get("metadata_as_string") {
        Some(metadata_as_string) => metadata_as_string.to_string(),
        None => "".to_string(),
    };

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
        .with_org_id(org_id)
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

    let private_key = match query.get("private_key") {
        Some(private_key) => Some(private_key.as_str().to_string()),
        None => Some("".to_string()),
    };
    
    let batch_list = BatchBuilder::new(PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION, private_key)
        .add_transaction(
            &payload.into_proto()?,
            &[PIKE_NAMESPACE.to_string()],
            &[PIKE_NAMESPACE.to_string()],
        )?
        .create_batch_list();
/*
    let response_url = match req.url_for_static("agent") {
        Ok(url) => format!("{}?{}", url, req.query_string()),
        Err(err) => {
            return Err(err.into());
        }
    };
*/
    let response_url = req.url_for_static("agent")?;
    
    let sawtooth_connection = SawtoothConnection::new(&response_url.to_string());

    let batch_submitter = Box::new(SawtoothBatchSubmitter::new(
        sawtooth_connection.get_sender(),
    ));

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
