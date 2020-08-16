// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::*;
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use sawtooth_sdk::signing::PrivateKey;
use sawtooth_sdk::processor::handler::ApplyError;
use serde::Deserialize;
use protobuf::Message;
use reqwest;

use crate::transaction::BatchBuilder;
use crate::error::RestApiResponseError;
//use crate::{List, Fetch};
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

    // Create batch_list_bytes //
    let batch_list_bytes = match do_batches(input_data, "CREATE"){
        Ok(schema) => schema,
        Err(err) => {
            return Err(RestApiResponseError::UserError(format!(
                "Cannot deserialize data: {:?}",
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
                "Cannot deserialize data: {:?}",
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
    let properties_as_string = &input_data.properties;

    let mut properties = Vec::<PropertyDefinition>::new();
    let vec: Vec<&str> = properties_as_string.split(",").collect();
    let key_val_vec = split_vec(vec, 7);
    for key_val in key_val_vec {
        if key_val.len() != 7 {
            "Properties are formated incorrectly".to_string();            
        }
        let name = match key_val.get(0) {
            Some(value) => value.to_string(),
            None => "name is formated incorrectly".to_string()
        };
        //let data_type = match key_val.get(1) {
        //    Some(value) => value.to_string(),
        //    None => "data_type is formated incorrectly".to_string()
        //};
        let data_type = match key_val.get(1) {
            Some(value) => {
                if (value == &"Byte") | (value == &"byte") | (value == &"BYTE") {return DataType::Bytes};
                if (value == &"Boolean") | (value == &"boolean") | (value == &"BOOLEAN") {return DataType::Boolean};
                if (value == &"Number") | (value == &"number") | (value == &"NUMBER") {return DataType::Number};
                if (value == &"String") | (value == &"string") | (value == &"STRING") {return DataType::String};
                if (value == &"Enum") | (value == &"enum") | (value == &"ENUM") {return DataType::Enum};
                if (value == &"Struct") | (value == &"struct") | (value == &"STRUCT") {return DataType::Struct};
                if (value == &"LatLong") | (value == &"LatLong") | (value == &"LATLONG") {return DataType::LatLong};
            },
            None => DataType::Bytes
        };

        //let required = match key_val.get(2) {
        //    Some(value) => value.to_string(),
        //    None => "required is formated incorrectly".to_string()
        //};
        let required = match key_val.get(2) {
            Some(value) => {
                if (value == &"True") | (value == &"true") | (value == &"TRUE") {return true}
                else {return false};
            },
            None => false
        };

        let description = match key_val.get(3) {
            Some(value) => value.to_string(),
            None => "description is formated incorrectly".to_string()
        };
        let number_exponent = match key_val.get(4) {
            Some(value) => value.to_string(),
            None => "number is formated incorrectly".to_string()
        };
        let enum_options = match key_val.get(5) {
            Some(value) => value.to_string(),
            None => "enum_options are formated incorrectly".to_string()
        };
        let struct_properties = match key_val.get(6) {
            Some(value) => value.to_string(),
            None => "struct_properties are formated incorrectly".to_string()
        };

        let builder = PropertyDefinitionBuilder::new();
        let property_definition = builder
        .with_name(name.to_string())
        //.with_data_type(DataType::String)
        .with_data_type(data_type)
        .with_required(required)
        .with_description(description.to_string())
        .build()
        .unwrap();

        properties.push(property_definition.clone());
    }

    if action_plan == "CREATE" {

        // Building the Action and Payload//
        let action = SchemaCreateBuilder::new()
        .with_schema_name(schema_name.to_string())
        .with_description(description.to_string())
        //.with_properties(vec![property_definition.clone()])
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
            &private_key.as_hex(),
        )
        .add_transaction(
            &payload.into_proto()?,
            &[get_schema_prefix(), get_pike_prefix()],
            &[get_schema_prefix(), get_pike_prefix()],
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
        //.with_properties(vec![property_definition.clone()])
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
            &private_key.as_hex(),
        )
        .add_transaction(
            &payload.into_proto()?,
            &[get_schema_prefix(), get_pike_prefix()],
            &[get_schema_prefix(), get_pike_prefix()],
        )?
        .create_batch_list();

        let batch_list_bytes = batch_list
            .write_to_bytes()
            .expect("Error converting batch list to bytes");

        return Ok(batch_list_bytes);
        
    }
}

