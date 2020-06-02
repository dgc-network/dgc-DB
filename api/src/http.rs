// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

//use crate::CliError;
use crate::error::RestApiResponseError as CliError;
use protobuf::Message;
use reqwest::Client;
use sawtooth_sdk::messages::batch::BatchList;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Instant;

pub fn submit_batches(
    url: &str,
    mut wait: u64,
    batch_list: &BatchList,
    service_id: Option<&str>,
) -> Result<(), CliError> {
    let bytes = batch_list.write_to_bytes()?;

    let client = Client::new();

    let mut final_url = format!("{}/submit_batches", url);
    if let Some(service_id) = service_id {
        final_url = format!("{}?service_id={}", final_url, service_id);
    }
    debug!("url {}", final_url);
    let batch_link = client
        .post(&final_url)
        .body(bytes)
        .send()?
        .json::<BatchStatusLink>()?;

    debug!("Response: {:#?}", batch_link);

    while wait > 0 {
        let time = Instant::now();

        let batch_status = client
            .get(&format!("{}&wait={}", batch_link.link, wait))
            .send()?
            .json::<BatchStatusResponse>()?;

        debug!("Batch Status: {:#?}", batch_status);

        if batch_status.data.iter().all(|x| x.status != "PENDING") {
            break;
        }

        wait -= time.elapsed().as_secs()
    }

    Ok(())
}

// Server Responses

#[derive(Deserialize, Debug)]
pub struct BatchStatusLink {
    pub link: String,
}

#[derive(Deserialize, Debug)]
struct BatchStatusResponse {
    pub data: Vec<BatchStatus>,
    pub link: String,
}

#[derive(Deserialize, Debug)]
struct BatchStatus {
    pub id: String,
    pub invalid_transactions: Vec<HashMap<String, String>>,
    pub status: String,
}
