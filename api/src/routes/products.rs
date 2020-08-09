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
use chrono;
use std::convert::TryInto;

use crate::transaction::BatchBuilder;
use crate::error::RestApiResponseError;
use crate::{List, Fetch};

use dgc_config::protos::*;
use dgc_config::addressing::*;
use dgc_config::protocol::product::state::*;
use dgc_config::protocol::product::payload::*;
use dgc_config::protocol::schema::state::*;

#[derive(Deserialize)]
pub struct ProductData {
    private_key: String,
    product_id: String,
    product_type: String,
    owner: String,
    //properties: Vec<PropertyValue>,
    properties: String,
}

pub async fn list_products(
) -> Result<HttpResponse, RestApiResponseError> {

    let url = format!("http://rest-api:8008/state?address={}", &get_product_prefix());
    let list = reqwest::get(&url).await?.json::<List>().await?;
    println!("============ list_product_data ============");
    for sub in list.data {
        let msg = base64::decode(&sub.data).unwrap();
        let product: product_state::Product = match protobuf::parse_from_bytes(&msg){
            Ok(product) => product,
            Err(err) => {
                return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                    "Cannot deserialize organization: {:?}",
                    err,
                ))))
            }
        };
        println!("!dgc-network! serialized: {:?}", product);
    }

    println!("============ list_product_link ============");
    println!("!dgc-network! link = {:?}", list.link);
    Ok(HttpResponse::Ok().body(list.link))
}

pub async fn fetch_product(
    product_id: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    let address = make_product_address(&product_id);
    let url = format!("http://rest-api:8008/state/{}", address);
    let res = reqwest::get(&url).await?.json::<Fetch>().await?;
    println!("============ fetch_product_data ============");
    let msg = base64::decode(&res.data).unwrap();
    let product: product_state::Product = match protobuf::parse_from_bytes(&msg){
        Ok(product) => product,
        Err(err) => {
            return Err(RestApiResponseError::ApplyError(ApplyError::InternalError(format!(
                "Cannot deserialize organization: {:?}",
                err,
            ))))
        }
    };
    println!("!dgc-network! serialized: {:?}", product);

    println!("============ fetch_product_link ============");
    println!("!dgc-network! link = {:?}", res.link);
    Ok(HttpResponse::Ok().body(res.link))
}

pub async fn create_product(
    input_data: web::Json<ProductData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // Create batch_list_bytes //
    let batch_list_bytes = match do_batches(input_data, "CREATE"){
        Ok(product) => product,
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

    println!("============ create_product_link ============");
    println!("!dgc-network! submit_status = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

pub async fn update_product(
    input_data: web::Json<ProductData>,
) -> Result<HttpResponse, RestApiResponseError> {

    // create batch_list //
    let batch_list_bytes = match do_batches(input_data, "UPDATE"){
        Ok(product) => product,
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

    println!("============ update_product_link ============");
    println!("!dgc-network! submit_status = {:?}", res);

    Ok(HttpResponse::Ok().body(res))
}

fn do_batches(
    input_data: web::Json<ProductData>,
    action_plan: &str,
) -> Result<Vec<u8>, RestApiResponseError> {

    // Retrieving a Private Key from the input_data //
    let private_key_as_hex = &input_data.private_key;
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
    .expect("Error generating a Private Key");

    // Creating the Payload //
    let product_id = &input_data.product_id;
    let owner = &input_data.owner;
    let properties_as_string = &input_data.properties;
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
        let action = ProductCreateActionBuilder::new()
        .with_product_id(product_id.to_string())
        .with_product_type(ProductType::GS1)
        .with_owner(owner.to_string())
        .with_properties(make_properties())
        .build()
        .unwrap();

        let payload = ProductPayloadBuilder::new()
        .with_action(Action::ProductCreate(action.clone()))
        .with_timestamp(chrono::offset::Utc::now().timestamp().try_into().unwrap())
        .build()
        .unwrap();

        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            PRODUCT_FAMILY_NAME, 
            PRODUCT_FAMILY_VERSION, 
            &private_key.as_hex(),
        )
        .add_transaction(
            &payload.into_proto()?,
            &[get_product_prefix()],
            &[get_product_prefix()],
        )?
        .create_batch_list();

        let batch_list_bytes = batch_list
            .write_to_bytes()
            .expect("Error converting batch list to bytes");

        return Ok(batch_list_bytes);

    //} else if (action_plan == "UPDATE") {
    } else {

        // Building the Action and Payload//
        let action = ProductUpdateActionBuilder::new()
        .with_product_id(product_id.to_string())
        .with_product_type(ProductType::GS1)
        .with_properties(make_properties())
        .build()
        .unwrap();

        let payload = ProductPayloadBuilder::new()
        .with_action(Action::ProductUpdate(action.clone()))
        .with_timestamp(chrono::offset::Utc::now().timestamp().try_into().unwrap())
        .build()
        .unwrap();

        // Building the Transaction and Batch//
        let batch_list = BatchBuilder::new(
            PRODUCT_FAMILY_NAME, 
            PRODUCT_FAMILY_VERSION, 
            &private_key.as_hex(),
        )
        .add_transaction(
            &payload.into_proto()?,
            &[get_product_prefix()],
            &[get_product_prefix()],
        )?
        .create_batch_list();

        let batch_list_bytes = batch_list
            .write_to_bytes()
            .expect("Error converting batch list to bytes");

        return Ok(batch_list_bytes);
    }
}

fn make_properties() -> Vec<PropertyValue> {
    let property_value_description = PropertyValueBuilder::new()
        .with_name("description".into())
        .with_data_type(DataType::String)
        .with_string_value("This is a product description".into())
        .build()
        .unwrap();
    let property_value_price = PropertyValueBuilder::new()
        .with_name("price".into())
        .with_data_type(DataType::Number)
        .with_number_value(3)
        .build()
        .unwrap();

    vec![
        property_value_description.clone(),
        property_value_price.clone(),
    ]
}
