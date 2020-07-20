// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::{web, HttpRequest, HttpResponse};
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use sawtooth_sdk::signing::PrivateKey;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::messaging::stream::MessageConnection;
use sawtooth_sdk::messaging::zmq_stream::ZmqMessageConnection;
use sawtooth_sdk::messaging::zmq_stream::ZmqMessageSender;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::ContextError;
use serde::Deserialize;
use protobuf::Message;
use reqwest;
//use serde_json::json;
//use serde_json::{Result, Value};
//use serde_json::Value;
use std::str;

use crate::transaction::BatchBuilder;
use crate::state::{
    PIKE_NAMESPACE, PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION,
    PIKE_ORG_NAMESPACE, 
    //ApiTransactionContext, ApiState
};
use crate::error::RestApiResponseError;

use grid_sdk::protocol::pike::{
    state::{
        KeyValueEntry, KeyValueEntryBuilder,
        Organization, OrganizationList,
    },
    payload::{
        Action, PikePayloadBuilder, 
        CreateOrganizationActionBuilder, UpdateOrganizationActionBuilder, 
    },
};
use grid_sdk::protos::IntoProto;
use grid_sdk::protos::FromBytes;

use crypto::digest::Digest;
use crypto::sha2::Sha512;
use std::cell::RefCell;
use std::collections::HashMap;

use crate::zmq_context::ZmqTransactionContext;
/*
//#[derive(Default)]
#[derive(Clone)]
/// An OrgTransactionContext that can be used to test OrgState
pub struct OrgTransactionContext {
    //state: RefCell<HashMap<String, Vec<u8>>>,
    context_id: String,
    sender: ZmqMessageSender,
}

impl OrgTransactionContext {
    /// Context provides an interface for getting, setting, and deleting
    /// validator state. All validator interactions by a handler should be
    /// through a Context instance.
    ///
    /// # Arguments
    ///
    /// * `sender` - for client grpc communication
    /// * `context_id` - the context_id passed in from the validator
    fn new(context_id: &str, sender: ZmqMessageSender) -> Self {
        OrgTransactionContext {
            context_id: String::from(context_id),
            sender,
        }
    }
}

impl TransactionContext for OrgTransactionContext {
    
/*
    fn get_state_entries(
        &self,
        addresses: &[String],
    ) -> Result<Vec<(String, Vec<u8>)>, ContextError> {
        let mut results = Vec::new();
        for addr in addresses {
            let data = match self.state.borrow().get(addr) {
                Some(data) => data.clone(),
                None => Vec::new(),
            };
            results.push((addr.to_string(), data));
        }
        Ok(results)
    }

    fn set_state_entries(&self, entries: Vec<(String, Vec<u8>)>) -> Result<(), ContextError> {
        for (addr, data) in entries {
            self.state.borrow_mut().insert(addr, data);
        }
        Ok(())
    }

    /// this is not needed for these tests
    fn delete_state_entries(&self, _addresses: &[String]) -> Result<Vec<String>, ContextError> {
        unimplemented!()
    }

    /// this is not needed for these tests
    fn add_receipt_data(&self, _data: &[u8]) -> Result<(), ContextError> {
        unimplemented!()
    }

    /// this is not needed for these tests
    fn add_event(
        &self,
        _event_type: String,
        _attributes: Vec<(String, String)>,
        _data: &[u8],
    ) -> Result<(), ContextError> {
        unimplemented!()
    }
*/    
}

/// Computes the address a Pike Organization is stored at based on its identifier
pub fn compute_org_address(identifier: &str) -> String {
    let mut sha = Sha512::new();
    sha.input(identifier.as_bytes());

    String::from(PIKE_NAMESPACE) + PIKE_ORG_NAMESPACE + &sha.result_str()[..62]
}

pub struct OrgState<'a> {
    context: &'a dyn TransactionContext,
    //context: &'a mut dyn TransactionContext,
    //address_map: HashMap<String, Option<String>>,
}

impl<'a> OrgState<'a> {    
    pub fn new(context: &'a dyn TransactionContext) -> OrgState {
        OrgState { context }
    }
/*
    pub fn new(context: &'a mut dyn TransactionContext) -> OrgState {
        OrgState {
            context,
            address_map: HashMap::new(),
        }
    }
*/
    pub fn get_organization(&self, id: &str) -> Result<Option<Organization>, ApplyError> {
        let address = compute_org_address(id);
        let d = self.context.get_state_entry(&address)?;
        match d {
            Some(packed) => {
                let orgs: OrganizationList = match OrganizationList::from_bytes(packed.as_slice()) {
                    Ok(orgs) => orgs,
                    Err(err) => {
                        return Err(ApplyError::InternalError(format!(
                            "Cannot deserialize organization list: {:?}",
                            err,
                        )))
                    }
                };

                for org in orgs.organizations() {
                    if org.org_id() == id {
                        return Ok(Some(org.clone()));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }
}
*/
#[derive(Deserialize)]
pub struct OrgInput {
    private_key: String,
    org_id: String,
    name: String,
    address: String,
    metadata: String,
}

#[derive(Deserialize)]
struct List {
    data: Vec<Sub>,
    head: String,
    link: String,
}

#[derive(Deserialize)]
struct Sub {
    address: String,
    data: String,
}

#[derive(Deserialize)]
struct Res {
    data: String,
    head: String,
    link: String,
}

pub async fn list_orgs(
) -> Result<HttpResponse, RestApiResponseError> {

    let res = reqwest::get("http://rest-api:8008/state?address=cad11d01").await?;
    let list = res.json::<List>().await?;
    for sub in list.data.iter() {
        let bytes = sub.data.as_bytes();
        let org = Organization::from_bytes(bytes).unwrap();

        println!("============ list_org ============");
        //println!("address: {}", sub.address);
        //println!("data: {}", sub.data);
        println!("!dgc-network! data = {:?}", sub.data);
        println!("!dgc-network! bytes = {:?}", bytes);
        println!("!dgc-network! org = {:?}", org);
    }

    println!("============ list_org ============");
    println!("!dgc-network! link = {:?}", list.link);
    Ok(HttpResponse::Ok().body(list.link))

    //Ok(HttpResponse::Ok().body("Hello world! list_org"))

}

pub async fn fetch_org(
    org_id: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    println!("!dgc-network! org_id = {:?}", org_id);

    println!("============ fetch_org_1 ============");

    let request: TpProcessRequest = TpProcessRequest::new();
    //let conn = ZmqMessageConnection::new(&endpoint);
    let conn = ZmqMessageConnection::new("tcp://localhost:4004");
    let (sender, receiver) = conn.create();
    let transaction_context = ZmqTransactionContext::new(
        request.get_context_id(),
        sender.clone(),
    );

    //let transaction_context = OrgTransactionContext::default();
    println!("============ fetch_org_2 ============");
    let state = OrgState::new(&transaction_context);
    println!("============ fetch_org_3 ============");
    let org = state.get_organization(&org_id).unwrap();
    println!("============ fetch_org_4 ============");
    println!("!dgc-network! org = {:?}", org);
    //let agent = result.unwrap();
    println!("============ fetch_org_5 ============");

    Ok(HttpResponse::Ok().body("Hello world! fetch_org"))

}

pub async fn create_org(
    org_input: web::Json<OrgInput>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Creating a Private Key and Signer //
    let private_key_as_hex = &org_input.private_key;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
        .expect("Error generating a new Private Key");

    // Creating the Payload //
    let org_id = &org_input.org_id;
    let name = &org_input.name;
    let address = &org_input.address;
    let metadata_as_string = &org_input.metadata;

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

    println!("============ create_organization ============");
    println!("!dgc-network! res = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

pub async fn update_org(
    org_input: web::Json<OrgInput>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Creating a Private Key and Signer //
    let private_key_as_hex = &org_input.private_key;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
        .expect("Error generating a new Private Key");

    // Creating the Payload //
    let org_id = &org_input.org_id;
    let name = &org_input.name;
    let address = &org_input.address;
    let metadata_as_string = &org_input.metadata;

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

    println!("============ update_organization ============");
    println!("!dgc-network! res = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}
