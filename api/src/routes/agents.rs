// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use actix_web::{web, HttpRequest, HttpResponse};
//use actix::{Handler, Message, SyncContext};
//use actix_web::{web, HttpResponse};
//use serde::{Deserialize, Serialize};
//use serde::Deserialize;
//use serde_json::Value as JsonValue;

//use crate::AppState;
use crate::submitter::{BatchStatusResponse, BatchStatuses, SubmitBatches, DEFAULT_TIME_OUT};
//use crate::submitter::{SubmitBatches, DEFAULT_TIME_OUT};
//use crate::submitter::{SubmitBatches, BatchSubmitter, DEFAULT_TIME_OUT};
use crate::submitter::{BatchSubmitter, SawtoothBatchSubmitter};
//use crate::{batch_submitter::SawtoothBatchSubmitter, connection::SawtoothConnection};
use crate::connection::SawtoothConnection;
//use crate::config::Endpoint;
use crate::Endpoint;
use crate::transaction::BatchBuilder;
//use crate::transaction::{pike_batch_builder, PIKE_NAMESPACE};
//use grid_sdk::protocol::pike::state::{
//    KeyValueEntry, KeyValueEntryBuilder,
//};
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

use crate::error::RestApiResponseError;
//use validator::Validate;

//const GRID_DAEMON_KEY: &str = "GRID_DAEMON_KEY";
//const GRID_DAEMON_ENDPOINT: &str = "GRID_DAEMON_ENDPOINT";
//const GRID_SERVICE_ID: &str = "GRID_SERVICE_ID";
//const DEFAULT_TIME_OUT: u32 = 300; // Max timeout 300 seconds == 5 minutes
/*
#[derive(Deserialize)]
pub struct NewAgent {
    agent: NewAgentData,
}

//#[derive(Deserialize, Validate)]
#[derive(Deserialize)]
struct NewAgentData {
    //private_key: Option<String>,
    org_id: Option<String>, 
    roles: Option<String>, 
    metadata: Option<String>

    #[validate(length(min = 1))]
    username: Option<String>,
    #[validate(email)]
    email: Option<String>,
    #[validate(length(min = 8))]
    password: Option<String>,

}
*/
/*
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentSlice {
    pub public_key: String,
    pub org_id: String,
    pub active: bool,
    pub roles: Vec<String>,
    pub metadata: JsonValue,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
}

impl AgentSlice {
    pub fn from_agent(agent: &Agent) -> Self {
        Self {
            public_key: agent.public_key.clone(),
            org_id: agent.org_id.clone(),
            active: agent.active,
            roles: agent.roles.clone(),
            metadata: agent.metadata.clone(),
            service_id: agent.service_id.clone(),
        }
    }
}

struct ListAgents {
    service_id: Option<String>,
}

impl Message for ListAgents {
    type Result = Result<Vec<AgentSlice>, RestApiResponseError>;
}
*/
/*
impl Handler<ListAgents> for DbExecutor {
    type Result = Result<Vec<AgentSlice>, RestApiResponseError>;

    fn handle(&mut self, msg: ListAgents, _: &mut SyncContext<Self>) -> Self::Result {
        let fetched_agents =
            db::get_agents(&*self.connection_pool.get()?, msg.service_id.as_deref())?
                .iter()
                .map(|agent| AgentSlice::from_agent(agent))
                .collect::<Vec<AgentSlice>>();

        Ok(fetched_agents)
    }
}
*/
pub async fn list_agents(
    req: HttpRequest,
    //state: web::Data<AppState>,
    query: web::Query<HashMap<String, String>>,
    //query_service_id: web::Query<QueryServiceId>,
    //_: AcceptServiceIdParam,
    //state: web::Data<AppState>,
    //query: web::Query<QueryServiceId>,
    //_: AcceptServiceIdParam,
) -> Result<HttpResponse, RestApiResponseError> {
/*
    state
        .database_connection
        .send(ListAgents {
            service_id: query.into_inner().service_id,
        })
        .await?
        .map(|agents| HttpResponse::Ok().json(agents))
*/
    
    /// Max wait time allowed is 95% of network's configured timeout
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

    ///
    let response_url = match req.url_for_static("agent") {
        Ok(url) => format!("{}?{}", url, req.query_string()),
        Err(err) => {
            //return Err(err.into());
            return Err(RestApiResponseError::BadRequest("I am here.".to_string(),));
        }
    };

    let sawtooth_connection = SawtoothConnection::new(&response_url);

    let batch_submitter = Box::new(SawtoothBatchSubmitter::new(
        sawtooth_connection.get_sender(),
    ));

    /// 
    let batch_ids = match query.get("id") {
        Some(ids) => ids.split(',').map(ToString::to_string).collect(),
        None => {
            return Err(RestApiResponseError::BadRequest(
                "Request for statuses missing id query.".to_string(),
            ));
        }
    };

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

    //Ok(HttpResponse::Ok().body("Hello world! list_agents"))

}
/*
struct FetchAgent {
    public_key: String,
    service_id: Option<String>,
}

impl Message for FetchAgent {
    type Result = Result<AgentSlice, RestApiResponseError>;
}
*/
/*
impl Handler<FetchAgent> for DbExecutor {
    type Result = Result<AgentSlice, RestApiResponseError>;

    fn handle(&mut self, msg: FetchAgent, _: &mut SyncContext<Self>) -> Self::Result {
        let fetched_agent = match db::get_agent(
            &*self.connection_pool.get()?,
            &msg.public_key,
            msg.service_id.as_deref(),
        )? {
            Some(agent) => AgentSlice::from_agent(&agent),
            None => {
                return Err(RestApiResponseError::NotFoundError(format!(
                    "Could not find agent with public key: {}",
                    msg.public_key
                )));
            }
        };

        Ok(fetched_agent)
    }
}
*/
pub async fn fetch_agent(
    //state: web::Data<AppState>,
    public_key: web::Path<String>,
//    query: web::Query<QueryServiceId>,
//    _: AcceptServiceIdParam,
) -> Result<HttpResponse, RestApiResponseError> {
/*    
    state
        .database_connection
        .send(FetchAgent {
            public_key: public_key.into_inner(),
            service_id: query.into_inner().service_id,
        })
        .await?
        .map(|agent| HttpResponse::Ok().json(agent))
*/        
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
