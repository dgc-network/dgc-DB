// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::*;
use sawtooth_sdk::processor::handler::ApplyError;
use serde::Deserialize;
use protobuf::Message;
use reqwest;

use crate::transaction::BatchBuilder;
use crate::error::RestApiResponseError;
use crate::{List, Fetch, split_vec};

use dgc_config::protos::*;
use dgc_config::addressing::*;
use dgc_config::protocol::schema::payload::*;
use dgc_config::protocol::schema::state::*;

#[derive(Deserialize)]
pub struct SchemaData {
    private_key: String,
    schema_name: String,
    description: String,
    properties: String,
}

pub async fn list_schemas(
) -> Result<HttpResponse, RestApiResponseError> {

    let url = format!("http://rest-api:8008/state?address={}", &get_schema_prefix());
    let list = reqwest::get(&url).await?.json::<List>().await?;
    let mut response_data = "[".to_owned();
    for sub in list.data {
        let msg = base64::decode(&sub.data).unwrap();
        let schemas: schema_state::SchemaList = match protobuf::parse_from_bytes(&msg){
            Ok(schemas) => schemas,
            Err(err) => {
                return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                    "Cannot deserialize data: {:?}",
                    err,
                ))))
            }
        };

        for schema in schemas.get_schemas() {
            println!("!dgc-network! response_data: ");
            println!("    schema_name: {:?},", schema.name);
            println!("    description: {:?},", schema.description);
            println!("    owner: {:?},", schema.owner);
            println!("    properties: {:?}", schema.properties);

            response_data = response_data + &format!("\n  {{\n    schema_name: {:?}, \n    description: {:?}, \n    owner: {:?}, \n    properties: {:?}, \n  }},\n", schema.name, schema.description, schema.owner, schema.properties);
        }
    }
    response_data = response_data + &format!("]");
    Ok(HttpResponse::Ok().body(response_data))
}

pub async fn fetch_schema(
    product_id: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    let address = make_schema_address(&product_id);
    let url = format!("http://rest-api:8008/state/{}", address);
    let res = reqwest::get(&url).await?.json::<Fetch>().await?;
    println!("============ fetch_schema_data ============");
    let msg = base64::decode(&res.data).unwrap();
    let schemas: schema_state::SchemaList = match protobuf::parse_from_bytes(&msg){
        Ok(schemas) => schemas,
        Err(err) => {
            return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                "Cannot deserialize organization: {:?}",
                err,
            ))))
        }
    };
    let mut response_data = "".to_owned();
    for schema in schemas.get_schemas() {
        println!("!dgc-network! response_data: ");
        println!("    schema_name: {:?},", schema.name);
        println!("    description: {:?},", schema.description);
        println!("    owner: {:?},", schema.owner);
        println!("    properties: {:?}", schema.properties);
        
        response_data = response_data + &format!("{{\n  schema_name: {:?}, \n  description: {:?}, \n  owner: {:?}, \n  properties: {:?}, \n}}", schema.name, schema.description, schema.owner, schema.properties);
    }
    Ok(HttpResponse::Ok().body(response_data))
}

pub async fn create_schema(
    input_data: web::Json<SchemaData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Creating the Payload //
    let private_key = &input_data.private_key;
    let schema_name = &input_data.schema_name;
    let description = &input_data.description;
    let properties = retrieve_property_definitions(&input_data);

    // Building the Action and Payload//
    let action = SchemaCreateBuilder::new()
        .with_schema_name(schema_name.to_string())
        .with_description(description.to_string())
        .with_properties(properties)
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
        private_key,
    ).add_transaction(
        &payload.into_proto()?,
        &[get_schema_prefix(), get_pike_prefix()],
        &[get_schema_prefix(), get_pike_prefix()],
    )?.create_batch_list();

    let batch_list_bytes = batch_list
        .write_to_bytes()
        .expect("Error converting batch list to bytes");

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

    // Creating the Payload //
    let private_key = &input_data.private_key;
    let schema_name = &input_data.schema_name;
    let description = &input_data.description;
    let properties = retrieve_property_definitions(&input_data);

    // Building the Action and Payload//
    let action = SchemaUpdateBuilder::new()
        .with_schema_name(schema_name.to_string())
        .with_properties(properties)
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
        private_key,
    ).add_transaction(
        &payload.into_proto()?,
        &[get_schema_prefix(), get_pike_prefix()],
        &[get_schema_prefix(), get_pike_prefix()],
    )?.create_batch_list();

    let batch_list_bytes = batch_list
        .write_to_bytes()
        .expect("Error converting batch list to bytes");

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

fn retrieve_property_definitions(
    input_data: &web::Json<SchemaData>,
) -> Vec::<PropertyDefinition> {
/*
    name: String,
    data_type: DataType,
    required: bool,
    description: String,
    number_exponent: i32,
    enum_options: Vec<String>,
    struct_properties: Vec<PropertyDefinition>,
*/
    let mut properties = Vec::<PropertyDefinition>::new();
    let properties_as_string = &input_data.properties;
    let vec: Vec<&str> = properties_as_string.split(",").collect();
    let key_val_vec = split_vec(vec, 7);
    for key_val in key_val_vec {

        let name: String = match key_val.get(0) {
            Some(value) => value.to_string(),
            None => "name is formated incorrectly".to_string()
        };
        println!("!dgc-network! name = {:?}", name);
        
        let data_type: DataType = match key_val.get(1) {
            Some(value) => 
                if (value == &"Bytes") | (value == &"bytes") | (value == &"BYTES") {DataType::Bytes}
                else if (value == &"Boolean") | (value == &"boolean") | (value == &"BOOLEAN") {DataType::Boolean}
                else if (value == &"Number") | (value == &"number") | (value == &"NUMBER") {DataType::Number}
                else if (value == &"String") | (value == &"string") | (value == &"STRING") {DataType::String}
                else if (value == &"Enum") | (value == &"enum") | (value == &"ENUM") {DataType::Enum}
                else if (value == &"Struct") | (value == &"struct") | (value == &"STRUCT") {DataType::Struct}
                else if (value == &"LatLong") | (value == &"LatLong") | (value == &"LATLONG") {DataType::LatLong}
                else {DataType::String},
            None => DataType::String
        };
        println!("!dgc-network! data_type = {:?}", data_type);

        let required_string = match key_val.get(2) {
            Some(value) => value.to_string(),
            None => "false".to_string()
        };    
        let required = required_string.parse::<bool>();

        let description = match key_val.get(3) {
            Some(value) => value.to_string(),
            None => "description is formated incorrectly".to_string()
        };

        if data_type == DataType::Number {
            let number_exponent_string = match key_val.get(4) {
                Some(value) => value.to_string(),
                None => "0".to_string()
            };
            let number_exponent = number_exponent_string.parse::<i32>();
    
            let property_definition = PropertyDefinitionBuilder::new()
            .with_name(name.clone().into())
            .with_data_type(DataType::Number)
            .with_required(required.clone())
            .with_description(description.clone().to_string())
            .with_number_exponent(number_exponent.unwrap())
            .build()
            .unwrap();    
            properties.push(property_definition.clone());

        } else {
            
            let property_definition = PropertyDefinitionBuilder::new()
            .with_name(name.clone().into())
            .with_data_type(data_type.clone())
            .with_required(required.clone())
            .with_description(description.clone().to_string())
            .build()
            .unwrap();    
            properties.push(property_definition.clone());
        }
    }
    return properties
}
