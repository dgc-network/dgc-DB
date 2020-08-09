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
//use chrono;
//use std::convert::TryInto;

use crate::transaction::BatchBuilder;
use crate::error::RestApiResponseError;
use crate::{List, Fetch};

use dgc_config::protos::*;
use dgc_config::addressing::*;
//use dgc_config::protocol::product::state::*;
//use dgc_config::protocol::product::payload::*;
use dgc_config::protocol::schema::payload::*;
use dgc_config::protocol::schema::state::*;

#[derive(Deserialize)]
pub struct SchematData {
    private_key: String,
    schema_name: String,
    description: String,
    //properties: Vec<PropertyValue>,
    properties: String,
}

pub async fn list_schemas(
    //req: HttpRequest,
) -> Result<HttpResponse, RestApiResponseError> {

    let url = format!("http://rest-api:8008/state?address={}{}", &hash(&PRODUCT_FAMILY_NAME, 6), PRODUCT_GS1_NAMESPACE);
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
        //println!("!dgc-network! public_key: {:?}", agent.public_key);
    }

    println!("============ list_schema_link ============");
    println!("!dgc-network! link = {:?}", list.link);
    Ok(HttpResponse::Ok().body(list.link))
    
    //Ok(HttpResponse::Ok().json(pike_state::Agent {
    //    org_id: agent.org_id.to_string(),
    //}))
    
    //Ok(HttpResponse::Ok().body("Hello world! list_agent"))

}

pub async fn fetch_schema(
    product_id: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    //println!("!dgc-network! public_key = {:?}", public_key);
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
    //Ok(HttpResponse::Ok().body(res))

    //Ok(HttpResponse::Ok().body("Hello world! fetch_agent"))

}

pub async fn create_product(
    input_data: web::Json<ProductData>,
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

    //Ok(HttpResponse::Ok().body("Hello world! create_agent"))
}

pub async fn update_schema(
    input_data: web::Json<ProductData>,
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
    
    //Ok(HttpResponse::Ok().body("Hello world! update_agent"))
}

fn do_batches(
    input_data: web::Json<ProductData>,
    action_plan: &str,
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
    let schema_name = &input_data.schema_name;
    let description = &input_data.description;
    //let roles_as_string = &input_data.roles;
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
/*        
        let builder = PropertyDefinitionBuilder::new();
        let property_definition = builder
            .with_name("TEST".to_string())
            .with_data_type(DataType::String)
            .with_description("Optional".to_string())
            .build()
            .unwrap();
*/
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
/*
        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            SCHEMA_FAMILY_NAME, 
            SCHEMA_FAMILY_VERSION, 
            &private_key.as_hex(),
        )
        .add_transaction(
            &payload.into_proto()?,
            &[hash(&SCHEMA_FAMILY_NAME, 6)],
            &[hash(&SCHEMA_FAMILY_NAME, 6)],
        )?
        .create_batch_list();

        let batch_list_bytes = batch_list
            .write_to_bytes()
            .expect("Error converting batch list to bytes");

        return Ok(batch_list_bytes);
*/
    //} else if (action_plan == "UPDATE") {
    } else {

        // Building the Action and Payload//
/*        
        let builder = PropertyDefinitionBuilder::new();
        let property_definition = builder
            .with_name("TEST".to_string())
            .with_data_type(DataType::String)
            .with_description("Optional".to_string())
            .build()
            .unwrap();
*/
        let action = SchemaUpdateBuilder::new()
        .with_schema_name(schema_name.to_string())
        .with_description(description.to_string())
        .with_properties(vec![property_definition.clone()])
        .build()
        .unwrap();

        let payload = SchemaPayloadBuilder::new()
        .with_action(Action::SchemaUpdate(action.clone()))
        .build()
        .unwrap();
/*
        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            SCHEMA_FAMILY_NAME, 
            SCHEMA_FAMILY_VERSION, 
            &private_key.as_hex(),
        )
        .add_transaction(
            &payload.into_proto()?,
            &[hash(&SCHEMA_FAMILY_NAME, 6)],
            &[hash(&SCHEMA_FAMILY_NAME, 6)],
        )?
        .create_batch_list();

        let batch_list_bytes = batch_list
            .write_to_bytes()
            .expect("Error converting batch list to bytes");

        return Ok(batch_list_bytes);
*/        
    }

            // Building the Transaction and Batch//
            let batch_list = BatchBuilder::new(
                SCHEMA_FAMILY_NAME, 
                SCHEMA_FAMILY_VERSION, 
                &private_key.as_hex(),
            )
            .add_transaction(
                &payload.into_proto()?,
                &[hash(&SCHEMA_FAMILY_NAME, 6)],
                &[hash(&SCHEMA_FAMILY_NAME, 6)],
            )?
            .create_batch_list();
    
            let batch_list_bytes = batch_list
                .write_to_bytes()
                .expect("Error converting batch list to bytes");
    
            return Ok(batch_list_bytes);
    
}

