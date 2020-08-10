// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::*;
//use sawtooth_sdk::signing::create_context;
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use sawtooth_sdk::signing::PrivateKey;
use sawtooth_sdk::processor::handler::ApplyError;
use serde::Deserialize;
use protobuf::Message;
use reqwest;
use chrono;
use std::convert::TryInto;

use crate::transaction::BatchBuilder;
use crate::error::RestApiResponseError;
use crate::{List, Fetch};

use dgc_config::protos::*;
use dgc_config::addressing::*;
//use dgc_config::protocol::track_and_trace::state::*;
use dgc_config::protocol::track_and_trace::payload::*;
//use dgc_config::protocol::schema::payload::*;
use dgc_config::protocol::schema::state::*;

#[derive(Deserialize)]
pub struct RecordData {
    private_key: String,
    record_id: String,
    schema: String,
    properties: String,
}

pub async fn list_records(
) -> Result<HttpResponse, RestApiResponseError> {

    let url = format!("http://rest-api:8008/state?address={}", get_record_prefix());
    let list = reqwest::get(&url).await?.json::<List>().await?;
    println!("============ list_record_data ============");
    for sub in list.data {
        let msg = base64::decode(&sub.data).unwrap();
        let record: track_and_trace_state::Record = match protobuf::parse_from_bytes(&msg){
            Ok(record) => record,
            Err(err) => {
                return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                    "Cannot deserialize organization: {:?}",
                    err,
                ))))
            }
        };
        println!("!dgc-network! serialized: {:?}", record);
    }

    println!("============ list_record_link ============");
    println!("!dgc-network! link = {:?}", list.link);
    Ok(HttpResponse::Ok().body(list.link))
}

pub async fn fetch_record(
    record_id: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    let address = make_record_address(&record_id);
    let url = format!("http://rest-api:8008/state/{}", address);
    let res = reqwest::get(&url).await?.json::<Fetch>().await?;
    println!("============ fetch_record_data ============");
    let msg = base64::decode(&res.data).unwrap();
    let record: track_and_trace_state::Record = match protobuf::parse_from_bytes(&msg){
        Ok(record) => record,
        Err(err) => {
            return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                "Cannot deserialize organization: {:?}",
                err,
            ))))
        }
    };
    println!("!dgc-network! serialized: {:?}", record);

    println!("============ fetch_record_link ============");
    println!("!dgc-network! link = {:?}", res.link);
    Ok(HttpResponse::Ok().body(res.link))
}

pub async fn create_record(
    input_data: web::Json<RecordData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Create batch_list_bytes //
    let batch_list_bytes = match do_batches(input_data, "CREATE"){
        Ok(record) => record,
        Err(err) => {
            return Err(RestApiResponseError::UserError(format!(
                "Cannot deserialize record: {:?}",
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

    println!("============ create_record_link ============");
    println!("!dgc-network! submit_status = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

pub async fn update_record(
    input_data: web::Json<RecordData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // create batch_list //
    let batch_list_bytes = match do_batches(input_data, "FINALIZE"){
        Ok(record) => record,
        Err(err) => {
            return Err(RestApiResponseError::UserError(format!(
                "Cannot deserialize record: {:?}",
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

    println!("============ update_record_link ============");
    println!("!dgc-network! submit_status = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

fn do_batches(
    input_data: web::Json<RecordData>,
    action_plan: &str,
) -> Result<Vec<u8>, RestApiResponseError> {

    // Retrieving a Private Key from the input_data //
    let private_key_as_hex = &input_data.private_key;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
    .expect("Error generating a Private Key");
    //let context = create_context("secp256k1")
    //.expect("Error creating the right context");
    //let public_key = context.get_public_key(&private_key)
    //.expect("Error retrieving a Public Key");


    // Creating the Payload //
    let record_id = &input_data.record_id;
    let schema = &input_data.schema;

    if action_plan == "CREATE" {

        // Building the Action and Payload//
        let property_value = PropertyValueBuilder::new()
        .with_name("egg".into())
        .with_data_type(DataType::Number)
        .with_number_value(42)
        .build()
        .unwrap();

        let action = CreateRecordActionBuilder::new()
        .with_record_id(record_id.into())
        .with_schema(schema.into())
        .with_properties(vec![property_value.clone()])
        .build()
        .unwrap();

        let payload = TrackAndTracePayloadBuilder::new()
        .with_action(Action::CreateRecord(action.clone()))
        .with_timestamp(chrono::offset::Utc::now().timestamp().try_into().unwrap())
        .build()
        .unwrap();

        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            TNT_FAMILY_NAME, 
            TNT_FAMILY_VERSION, 
            &private_key.as_hex(),
        )
        .add_transaction(
            &payload.into_proto()?,
            &[get_record_prefix(), get_pike_prefix()],
            &[get_record_prefix(), get_pike_prefix()],
        )?
        .create_batch_list();

        let batch_list_bytes = batch_list
            .write_to_bytes()
            .expect("Error converting batch list to bytes");

        return Ok(batch_list_bytes);

    //} else if (action_plan == "FinalizeRecord") {
    } else {

        // Building the Action and Payload//
        let action = FinalizeRecordActionBuilder::new()
            .with_record_id(record_id.into())
            .build()
            .unwrap();

        let payload = TrackAndTracePayloadBuilder::new()
        .with_action(Action::FinalizeRecord(action.clone()))
        .with_timestamp(chrono::offset::Utc::now().timestamp().try_into().unwrap())
        .build()
        .unwrap();

        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            TNT_FAMILY_NAME, 
            TNT_FAMILY_VERSION, 
            &private_key.as_hex(),
        )
        .add_transaction(
            &payload.into_proto()?,
            &[get_record_prefix(), get_pike_prefix()],
            &[get_record_prefix(), get_pike_prefix()],
        )?
        .create_batch_list();

        let batch_list_bytes = batch_list
            .write_to_bytes()
            .expect("Error converting batch list to bytes");

        return Ok(batch_list_bytes);
        
    }
}

