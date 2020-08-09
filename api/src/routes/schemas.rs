// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::*;
use sawtooth_sdk::signing::create_context;
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use sawtooth_sdk::signing::PrivateKey;
use sawtooth_sdk::processor::handler::ApplyError;
use serde::Deserialize;
use protobuf::Message;
use reqwest;

use crate::transaction::BatchBuilder;
use crate::error::RestApiResponseError;
use crate::{List, Fetch};

use dgc_config::protos::*;
use dgc_config::addressing::*;
use dgc_config::protocol::schema::payload::*;
use dgc_config::protocol::schema::state::*;

#[derive(Deserialize)]
pub struct SchemaData {
    private_key: String,
    schema_name: String,
    description: String,
    //properties: Vec<PropertyValue>,
    properties: String,
}

pub async fn list_schemas(
) -> Result<HttpResponse, RestApiResponseError> {

    let url = format!("http://rest-api:8008/state?address={}", &get_schema_prefix());
    let list = reqwest::get(&url).await?.json::<List>().await?;
    println!("============ list_schema_data ============");
    for sub in list.data {
        let msg = base64::decode(&sub.data).unwrap();
        let schema: schema_state::Schema = match protobuf::parse_from_bytes(&msg){
            Ok(schema) => schema,
            Err(err) => {
                return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                    "Cannot deserialize organization: {:?}",
                    err,
                ))))
            }
        };
        println!("!dgc-network! serialized: {:?}", schema);
    }

    println!("============ list_schema_link ============");
    println!("!dgc-network! link = {:?}", list.link);
    Ok(HttpResponse::Ok().body(list.link))
}

pub async fn fetch_schema(
    product_id: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    let address = make_schema_address(&product_id);
    let url = format!("http://rest-api:8008/state/{}", address);
    let res = reqwest::get(&url).await?.json::<Fetch>().await?;
    println!("============ fetch_schema_data ============");
    let msg = base64::decode(&res.data).unwrap();
    let schema: schema_state::Schema = match protobuf::parse_from_bytes(&msg){
        Ok(schema) => schema,
        Err(err) => {
            return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                "Cannot deserialize organization: {:?}",
                err,
            ))))
        }
    };
    println!("!dgc-network! serialized: {:?}", schema);

    println!("============ fetch_schema_link ============");
    println!("!dgc-network! link = {:?}", res.link);
    Ok(HttpResponse::Ok().body(res.link))
}

pub async fn create_schema(
    input_data: web::Json<SchemaData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Create batch_list_bytes //
    let batch_list_bytes = match do_batches(input_data, "CREATE"){
        Ok(schema) => schema,
        Err(err) => {
            return Err(RestApiResponseError::UserError(format!(
                "Cannot deserialize organization: {:?}",
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

    println!("============ create_schema_link ============");
    println!("!dgc-network! submit_status = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

pub async fn update_schema(
    input_data: web::Json<SchemaData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // create batch_list //
    let batch_list_bytes = match do_batches(input_data, "UPDATE"){
        Ok(schema) => schema,
        Err(err) => {
            return Err(RestApiResponseError::UserError(format!(
                "Cannot deserialize organization: {:?}",
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

    println!("============ update_schema_link ============");
    println!("!dgc-network! submit_status = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

fn do_batches(
    input_data: web::Json<SchemaData>,
    action_plan: &str,
) -> Result<Vec<u8>, RestApiResponseError> {

    // Retrieving a Private Key from the input_data //
    let private_key_as_hex = &input_data.private_key;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
    .expect("Error generating a Private Key");

    // Creating the Payload //
    let schema_name = &input_data.schema_name;
    let description = &input_data.description;
    //let properties_as_string = &input_data.properties;

    let builder = PropertyDefinitionBuilder::new();
    let property_definition = builder
        .with_name("TEST".to_string())
        .with_data_type(DataType::String)
        .with_description("Optional".to_string())
        .build()
        .unwrap();

/*
    let mut roles = Vec::<String>::new();
    for role in roles_as_string.chars() {
        let entry: String = role.to_string().split(",").collect();
        roles.push(entry.clone());
    }
*/
/*
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
*/

    if action_plan == "CREATE" {

        // Building the Action and Payload//
        let action = SchemaCreateBuilder::new()
        .with_schema_name(schema_name.to_string())
        .with_description(description.to_string())
        .with_properties(vec![property_definition.clone()])
        .build()
        .unwrap();

        let payload = SchemaPayloadBuilder::new()
        .with_action(Action::SchemaCreate(action.clone()))
        .build()
        .unwrap();

        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            SCHEMA_FAMILY_NAME, 
            SCHEMA_FAMILY_VERSION, 
            &private_key.as_hex(),
        )
        .add_transaction(
            &payload.into_proto()?,
            &[get_schema_prefix()],
            &[get_schema_prefix()],
        )?
        .create_batch_list();

        let batch_list_bytes = batch_list
            .write_to_bytes()
            .expect("Error converting batch list to bytes");

        return Ok(batch_list_bytes);

    //} else if (action_plan == "UPDATE") {
    } else {

        // Building the Action and Payload//
        let action = SchemaUpdateBuilder::new()
        .with_schema_name(schema_name.to_string())
        //.with_description(description.to_string())
        .with_properties(vec![property_definition.clone()])
        .build()
        .unwrap();

        let payload = SchemaPayloadBuilder::new()
        .with_action(Action::SchemaUpdate(action.clone()))
        .build()
        .unwrap();

        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            SCHEMA_FAMILY_NAME, 
            SCHEMA_FAMILY_VERSION, 
            &private_key.as_hex(),
        )
        .add_transaction(
            &payload.into_proto()?,
            &[get_schema_prefix()],
            &[get_schema_prefix()],
        )?
        .create_batch_list();

        let batch_list_bytes = batch_list
            .write_to_bytes()
            .expect("Error converting batch list to bytes");

        return Ok(batch_list_bytes);
        
    }
}

