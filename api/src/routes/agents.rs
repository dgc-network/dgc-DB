// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::{web, HttpRequest, HttpResponse};
//use sawtooth_sdk::signing::CryptoFactory;
//use sawtooth_sdk::signing::create_context;
use sawtooth_sdk::signing::Context;
use sawtooth_sdk::signing::secp256k1::Secp256k1Context;
use sawtooth_sdk::signing::PrivateKey;
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use serde::Deserialize;

use crate::transaction::BatchBuilder;
use crate::submitter::{BatchSubmitter, SubmitBatches, SplinterBatchSubmitter};
use crate::submitter::{MockBatchSubmitter, MockMessageSender, ResponseType};
use crate::routes::batches::{submit_batches, get_batch_statuses};
use crate::state::{MockTransactionContext, MockState};
use crate::error::RestApiResponseError;

use grid_sdk::protocol::pike::{
    PIKE_NAMESPACE, PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION,
    state::{
        KeyValueEntry, KeyValueEntryBuilder,
    },
    payload::{
        Action, PikePayloadBuilder, 
        CreateAgentActionBuilder, UpdateAgentActionBuilder, 
    },
};
use grid_sdk::protos::IntoProto;

#[derive(Deserialize)]
pub struct AgentInput {
    private_key: String,
    org_id: String,
    roles: String,
    metadata: String,
}

pub async fn list_agents(
    req: HttpRequest,
) -> Result<HttpResponse, RestApiResponseError> {
    // Get the URL
    let response_url = match req.url_for_static("agent") {
        Ok(url) => format!("{}?{}", url, req.query_string()),
        Err(err) => {
            return Err(err.into());
        }
    };

    Ok(HttpResponse::Ok().body("Hello world! list_agents"))

}

pub async fn fetch_agent(
    public_key: web::Path<String>,
) -> Result<HttpResponse, RestApiResponseError> {

    println!("!dgc-network! public_key = {:?}", public_key);
    let mut transaction_context = MockTransactionContext::default();
    let state = MockState::new(&mut transaction_context);
    //let result = state.get_agent(&public_key).unwrap();
    let result = match state.get_agent(&public_key){
        Ok(x)  => {
            if x != None {
                x.unwrap();
            } else {
                return Err(RestApiResponseError::BadRequest(format!(
                    "Cannot find the data for public_key : {:?}",
                    public_key.to_string()
                )));
            }
        }
        Err(e) => return Err(e),
    };
    //let org_id = result.org_id();
    //let agent = result.unwrap();
    //let org_id = agent.org_id();
    println!("!dgc-network! result = {:?}", result);

    Ok(HttpResponse::Ok().body("Hello world! fetch_agent"))

}

//use std::alloc::{dealloc, Layout};
//use std::ptr;

pub async fn create_agent(
    req: HttpRequest,
    agent_input: web::Json<AgentInput>,
) -> Result<HttpResponse, RestApiResponseError> {

    /// Client: Building and Submitting Transactions

    /// Creating a Private Key and Signer
    //use sawtooth_sdk::signing::CryptoFactory;
    //use sawtooth_sdk::signing::create_context;
    
    let context = create_context("secp256k1")
        .expect("Error creating the right context");
    let private_key = context
        .new_random_private_key()
        .expect("Error generating a new Private Key");
    let crypto_factory = CryptoFactory::new(context.as_ref());
    let signer = crypto_factory.new_signer(private_key.as_ref());

    /// Encoding Your Payload
    //extern crate serde;
    extern crate serde_cbor;

    use serde::{Serialize, Deserialize};

    // Using serde to create a serializable struct
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Payload {
        verb: String,
        name: String,
        value: u32,
    }

    // --snip--
    let payload = Payload{  verb : String::from("set"),
                            name : String::from("foo"),
                            value : 42 };

    let payload_bytes = serde_cbor::to_vec(&payload).expect("upsi");

    /// Building the Transaction
    /// 1. Create the Transaction Header
    extern crate protobuf;
    extern crate openssl;
    extern crate rand;
    
    use rand::{thread_rng, Rng};
    
    use protobuf::Message
    use protobuf::RepeatedField;
    
    use openssl::sha::sha512;
    use sawtooth_sdk::messages::transaction::TransactionHeader;
    
    let mut txn_header = TransactionHeader::new();
    txn_header.set_family_name(String::from("intkey"));
    txn_header.set_family_version(String::from("1.0"));
    
    // Generate a random 128 bit number to use as a nonce
    let mut nonce = [0u8; 16];
    thread_rng()
        .try_fill(&mut nonce[..])
        .expect("Error generating random nonce");
    txn_header.set_nonce(to_hex_string(&nonce.to_vec()));
    
    let input_vec: Vec<String> = vec![String::from(
        "1cf1266e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7",
    )];
    let output_vec: Vec<String> = vec![String::from(
        "1cf1266e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7",
    )];
    
    txn_header.set_inputs(RepeatedField::from_vec(input_vec));
    txn_header.set_outputs(RepeatedField::from_vec(output_vec));
    txn_header.set_signer_public_key(
        signer
            .get_public_key()
            .expect("Error retrieving Public Key")
            .as_hex(),
    );
    txn_header.set_batcher_public_key(
        signer
            .get_public_key()
            .expect("Error retrieving Public Key")
            .as_hex(),
    );
    
    txn_header.set_payload_sha512(to_hex_string(&sha512(&payload_bytes).to_vec()));
    
    let txn_header_bytes = txn_header
        .write_to_bytes()
        .expect("Error converting transaction header to bytes");
    
    // --snip--
    
    // To properly format the Sha512 String
    pub fn to_hex_string(bytes: &Vec<u8>) -> String {
        let strs: Vec<String> = bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        strs.join("")
    }

    /// 2. Create the Transaction
    use sawtooth_sdk::messages::transaction::Transaction;

    let signature = signer
        .sign(&txn_header_bytes)
        .expect("Error signing the transaction header");
    
    let mut txn = Transaction::new();
    txn.set_header(txn_header_bytes.to_vec());
    txn.set_header_signature(signature);
    txn.set_payload(payload_bytes);
    

    /// 3. (optional) Encode the Transaction(s)
    let txn_list_vec = vec![txn1, txn2];
    let txn_list = TransactionList::new();
    txn_list.set_transactions(RepeatedField::from_vec(txn_list_vec));
    
    let txn_list_bytes = txn_list
        .write_to_bytes()
        .expect("Error converting Transaction List to bytes");

    /// Building the Batch

    /// 1. Create the BatchHeader
    use sawtooth_sdk::messages::batch::BatchHeader;

    let mut batch_header = BatchHeader::new();

    batch_header.set_signer_public_key(
        signer
            .get_public_key()
            .expect("Error retrieving Public Key")
            .as_hex(),
    );

    let transaction_ids = vec![txn.clone()]
        .iter()
        .map(|trans| String::from(trans.get_header_signature()))
        .collect();

    batch_header.set_transaction_ids(RepeatedField::from_vec(transaction_ids));

    let batch_header_bytes = batch_header
        .write_to_bytes()
        .expect("Error converting batch header to bytes");

    /// 2. Create the Batch
    use sawtooth_sdk::messages::batch::Batch;

    let signature = signer
        .sign(&batch_header_bytes)
        .expect("Error signing the batch header");
    
    let mut batch = Batch::new();
    
    batch.set_header(batch_header_bytes);
    batch.set_header_signature(signature);
    batch.set_transactions(RepeatedField::from_vec(vec![txn]));

    /// 3. Encode the Batch(es) in a BatchList
    use sawtooth_sdk::messages::batch::BatchList;

    let mut batch_list = BatchList::new();
    batch_list.set_batches(RepeatedField::from_vec(vec![batch]));
    let batch_list_bytes = batch_list
        .write_to_bytes()
        .expect("Error converting batch list to bytes");

    /// Submitting Batches to the Validator
    // When using an external crate don't forget to add it to your dependencies
    // in the Cargo.toml file, just like with the sdk itself
    extern crate reqwest;

    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:8008/batches")
        .header("Content-Type", "application/octet-stream")
        .body(
            batch_list_bytes,
        )
        .send()

    /// 

    let response_url = req.url_for_static("agent")?;

    let org_id = &agent_input.org_id;
    let roles_as_string = &agent_input.roles;
    let metadata_as_string = &agent_input.metadata;

    let context = Secp256k1Context::new();
    let private_key = context.new_random_private_key()
        .expect("Error generating a new Private Key");
    let public_key = context.get_public_key(private_key.as_ref())
        .expect("Error generating a new Public Key");

    println!("============ create_agent ============");
    println!("!dgc-network! private_key = {:?}", private_key.as_hex());
    println!("!dgc-network! public_key = {:?}", public_key.as_hex());
    println!("!dgc-network! org_id = {:?}", org_id);
    println!("!dgc-network! roles = {:?}", roles_as_string);
    println!("!dgc-network! metadata = {:?}", metadata_as_string);
    println!("============ create_agent ============");

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
        .with_org_id(org_id.to_string())
        .with_public_key(public_key.as_hex())
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

    let batch_list = BatchBuilder::new(PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION, &private_key.as_hex())
        .add_transaction(
            &payload.into_proto()?,
            &[PIKE_NAMESPACE.to_string()],
            &[PIKE_NAMESPACE.to_string()],
        )?
        .create_batch_list();

    //println!("!dgc-network! batch_list = {:?}", batch_list);
    //println!("!dgc-network! response_url = {:?}", response_url);

    //let mock_sender = MockMessageSender::new(ResponseType::ClientBatchSubmitResponseOK);
    //let mock_batch_submitter = Box::new(MockBatchSubmitter {
    //    sender: mock_sender,
    //});

    //let batch_submitter = Box::new(SplinterBatchSubmitter::new(config.endpoint().url()));
    let batch_submitter = Box::new(SplinterBatchSubmitter::new(response_url.to_string()));

    //mock_batch_submitter
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
    req: HttpRequest,
    agent_input: web::Json<AgentInput>,
) -> Result<HttpResponse, RestApiResponseError> {

    let response_url = req.url_for_static("agent")?;

    let private_key_as_hex = &agent_input.private_key;
    let org_id = &agent_input.org_id;
    let roles_as_string = &agent_input.roles;
    let metadata_as_string = &agent_input.metadata;

    let context = Secp256k1Context::new();
    let private_key = Secp256k1PrivateKey::from_hex(&private_key_as_hex)
        .expect("Error generating a new Private Key");
    let public_key = context.get_public_key(&private_key)
        .expect("Error generating a new Public Key");

    println!("============ update_agent ============");
    println!("!dgc-network! private_key = {:?}", private_key.as_hex());
    println!("!dgc-network! public_key = {:?}", public_key.as_hex());
    println!("!dgc-network! org_id = {:?}", org_id);
    println!("!dgc-network! roles = {:?}", roles_as_string);
    println!("!dgc-network! metadata = {:?}", metadata_as_string);

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

    let action = UpdateAgentActionBuilder::new()
        .with_org_id(org_id.to_string())
        .with_public_key(public_key.as_hex())
        .with_active(true)
        .with_roles(roles)
        .with_metadata(metadata)
        .build()
        .unwrap();

    let payload = PikePayloadBuilder::new()
        .with_action(Action::UpdateAgent)
        .with_update_agent(action)
        .build()
        .map_err(|err| RestApiResponseError::UserError(format!("{}", err)))?;

    let batch_list = BatchBuilder::new(PIKE_FAMILY_NAME, PIKE_FAMILY_VERSION, &private_key.as_hex())
        .add_transaction(
            &payload.into_proto()?,
            &[PIKE_NAMESPACE.to_string()],
            &[PIKE_NAMESPACE.to_string()],
        )?
        .create_batch_list();

    println!("!dgc-network! batch_list = {:?}", batch_list);
    println!("!dgc-network! response_url = {:?}", response_url);

    //let mock_sender = MockMessageSender::new(ResponseType::ClientBatchSubmitResponseOK);
    //let mock_batch_submitter = Box::new(MockBatchSubmitter {
    //    sender: mock_sender,
    //});

    //let batch_submitter = Box::new(SplinterBatchSubmitter::new(config.endpoint().url()));
    let batch_submitter = Box::new(SplinterBatchSubmitter::new(response_url.to_string()));

    //mock_batch_submitter
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
