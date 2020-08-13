// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::*;
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
    let mut response_data = "[".to_owned();
    for sub in list.data {
        let msg = base64::decode(&sub.data).unwrap();
        let records: pike_state::RecordList = match protobuf::parse_from_bytes(&msg){
            Ok(records) => records,
            Err(err) => {
                return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                    "Cannot deserialize data: {:?}",
                    err,
                ))))
            }
        };

        record_id: String,
        schema: String,
        owners: Vec<AssociatedAgent>,
        custodians: Vec<AssociatedAgent>,
        field_final: bool,
    
        for record in records.get_records() {
            println!("!dgc-network! response_data: ");
            println!("    record_id: {:?},", record.record_id);
            println!("    schema: {:?},", record.schema);
            println!("    owners: {:?},", record.owners);
            println!("    custodians: {:?}", record.custodians);
            println!("    field_final: {:?}", record.field_final);
            
            response_data = response_data + &format!("\n  {{\n    record_id: {:?}, \n    schema: {:?}, \n    owner: {:?}, \n    custodians: {:?}, \n    field_final: {:?}\n  }},\n", record.record_id, record.schema, record.owners, record.custodians, record.field_final);
        }
    }
    response_data = response_data + &format!("]");
    Ok(HttpResponse::Ok().body(response_data))
}

pub async fn fetch_record(
    record_id: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    let address = make_record_address(&record_id);
    let url = format!("http://rest-api:8008/state/{}", address);
    let res = reqwest::get(&url).await?.json::<Fetch>().await?;

    let records: pike_state::RecordList = match protobuf::parse_from_bytes(&msg){
        Ok(records) => records,
        Err(err) => {
            return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                "Cannot deserialize data: {:?}",
                err,
            ))))
        }
    };
    let mut response_data = "".to_owned();
    for record in records.get_records() {
        println!("!dgc-network! response_data: ");
        println!("    record_id: {:?},", record.record_id);
        println!("    schema: {:?},", record.schema);
        println!("    owners: {:?},", record.owners);
        println!("    custodians: {:?}", record.custodians);
        println!("    field_final: {:?}", record.field_final);
        
        response_data = response_data + &format!("{{\n  record_id: {:?}, \n  schema: {:?}, \n  owners: {:?}, \n  custodians: {:?}, \n  field_final: {:?} \n}}", record.record_id, record.schema, record.owners, record.custodians, record.field_final);
    }
    Ok(HttpResponse::Ok().body(response_data))
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

    // Creating the Payload //
    let record_id = &input_data.record_id;
    let schema = &input_data.schema;
    let properties_as_string = &input_data.properties;
    
    let mut properties = Vec::<PropertyDefinition>::new();
    for meta in properties_as_string.chars() {
        let meta_as_string = meta.to_string();
        let key_val: Vec<&str> = meta_as_string.split(",").collect();
        if key_val.len() != 7 {
            "Metadata is formated incorrectly".to_string();            
        }
        let name = match key_val.get(0) {
            Some(value) => value.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };
        let data_type = match key_val.get(1) {
            Some(value) => value.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };
        let required = match key_val.get(2) {
            Some(value) => value.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };
        let description = match key_val.get(3) {
            Some(value) => value.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };
        let number_exponent = match key_val.get(4) {
            Some(value) => value.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };
        let enum_options = match key_val.get(5) {
            Some(value) => value.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };
        let struct_properties = match key_val.get(6) {
            Some(value) => value.to_string(),
            None => "Metadata is formated incorrectly".to_string()
        };

        let property_value = PropertyValueBuilder::new()
        .with_name("egg".into())
        .with_data_type(DataType::Number)
        .with_number_value(42)
        .build()
        .unwrap();
/*    
        let builder = PropertyDefinitionBuilder::new();
        let property_definition = builder
        .with_name(name.to_string())
        .with_data_type(DataType::String)
        .with_description(description.to_string())
        .build()
        .unwrap();
*/
        properties.push(property_value.clone());
    }


    if action_plan == "CREATE" {

        // Building the Action and Payload//
        let action = CreateRecordActionBuilder::new()
        .with_record_id(record_id.into())
        .with_schema(schema.into())
        //.with_properties(vec![property_value.clone()])
        .with_properties(properties)
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

