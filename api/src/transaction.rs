// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

//! Contains functions which assist with the creation of Batches and Transactions
//! Contains functions which assist with signing key management

use std::time::Instant;
use crypto::digest::Digest;
use crypto::sha2::Sha512;
use protobuf::Message;

use sabre_sdk::protocol::payload::ExecuteContractActionBuilder;
use sabre_sdk::protos::IntoBytes;

use sawtooth_sdk::messages::batch::Batch;
use sawtooth_sdk::messages::batch::BatchHeader;
use sawtooth_sdk::messages::batch::BatchList;
use sawtooth_sdk::messages::transaction::Transaction;
use sawtooth_sdk::messages::transaction::TransactionHeader;
use sawtooth_sdk::signing;
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;

use crate::error::RestApiResponseError as CliError;
use dgc_config::addressing::*;

#[derive(Clone)]
pub struct BatchBuilder {
    family_name: String,
    family_version: String,
    key_str: String,
    //key_name: Option<String>,
    batches: Vec<Batch>,
}

impl BatchBuilder {
    pub fn new(
        family_name: &str, 
        family_version: &str, 
        key_str: &str, 
        //key_name: Option<String>
    ) -> BatchBuilder {
        BatchBuilder {
            family_name: family_name.to_string(),
            family_version: family_version.to_string(),
            //key_name,
            key_str: key_str.to_string(),
            batches: Vec::new(),
        }
    }

    pub fn add_transaction<T: protobuf::Message>(
        &mut self,
        payload: &T,
        inputs: &[String],
        outputs: &[String],
    ) -> Result<Self, CliError> {
        // create execute contract action for sabre payload
        let sabre_payload = ExecuteContractActionBuilder::new()
            .with_name(self.family_name.to_string())
            .with_version(self.family_version.to_string())
            .with_inputs(inputs.to_vec())
            .with_outputs(outputs.to_vec())
            .with_payload(payload.write_to_bytes()?)
            .into_payload_builder()
            .map_err(|err| CliError::UserError(format!("{}", err)))?
            .build()
            .map_err(|err| CliError::UserError(format!("{}", err)))?;

        let mut input_addresses = vec![
            compute_contract_registry_address(&self.family_name),
            compute_contract_address(&self.family_name, &self.family_version),
        ];

        for input in inputs {
            let namespace = match input.get(..6) {
                Some(namespace) => namespace,
                None => {
                    return Err(CliError::UserError(format!(
                        "Input must be at least 6 characters long: {}",
                        input
                    )));
                }
            };

            input_addresses.push(compute_namespace_registry_address(namespace)?);
        }
        input_addresses.append(&mut inputs.to_vec());

        let mut output_addresses = vec![
            compute_contract_registry_address(&self.family_name),
            compute_contract_address(&self.family_name, &self.family_version),
        ];

        for output in outputs {
            let namespace = match output.get(..6) {
                Some(namespace) => namespace,
                None => {
                    return Err(CliError::UserError(format!(
                        "Output must be at least 6 characters long: {}",
                        output
                    )));
                }
            };

            output_addresses.push(compute_namespace_registry_address(namespace)?);
        }
        output_addresses.append(&mut outputs.to_vec());

        let private_key = Secp256k1PrivateKey::from_hex(&self.key_str)?;
        let context = signing::create_context("secp256k1")?;
        let public_key = context.get_public_key(&private_key)?.as_hex();
        let factory = signing::CryptoFactory::new(&*context);
        let signer = factory.new_signer(&private_key);

        let mut txn = Transaction::new();
        let mut txn_header = TransactionHeader::new();

        txn_header.set_family_name(SABRE_FAMILY_NAME.into());
        txn_header.set_family_version(SABRE_FAMILY_VERSION.into());
        txn_header.set_nonce(create_nonce());
        txn_header.set_signer_public_key(public_key.clone());
        txn_header.set_batcher_public_key(public_key.clone());

        txn_header.set_inputs(protobuf::RepeatedField::from_vec(input_addresses));
        txn_header.set_outputs(protobuf::RepeatedField::from_vec(output_addresses));

        let payload_bytes = sabre_payload.into_bytes()?;
        let mut sha = Sha512::new();
        sha.input(&payload_bytes);
        let hash: &mut [u8] = &mut [0; 64];
        sha.result(hash);
        txn_header.set_payload_sha512(bytes_to_hex_str(hash));
        txn.set_payload(payload_bytes.to_vec());

        let txn_header_bytes = txn_header.write_to_bytes()?;
        txn.set_header(txn_header_bytes.clone());

        let b: &[u8] = &txn_header_bytes;
        txn.set_header_signature(signer.sign(b)?);

        let mut batch = Batch::new();
        let mut batch_header = BatchHeader::new();

        batch_header.set_transaction_ids(protobuf::RepeatedField::from_vec(vec![txn
            .header_signature
            .clone()]));
        batch_header.set_signer_public_key(public_key);
        batch.set_transactions(protobuf::RepeatedField::from_vec(vec![txn]));

        let batch_header_bytes = batch_header.write_to_bytes()?;
        batch.set_header(batch_header_bytes.clone());

        batch.set_header_signature(signer.sign(&batch_header_bytes)?);

        self.batches.push(batch);

        Ok(self.clone())
      
    }

    pub fn create_batch_list(&mut self) -> BatchList {
        let mut batch_list = BatchList::new();
        batch_list.set_batches(protobuf::RepeatedField::from_vec(self.batches.clone()));

        batch_list
    }
}

/// Creates a nonce appropriate for a TransactionHeader
fn create_nonce() -> String {
    let elapsed = Instant::now().elapsed();
    format!("{}{}", elapsed.as_secs(), elapsed.subsec_nanos())
}

/// Returns a hex string representation of the supplied bytes
///
/// # Arguments
///
/// * `b` - input bytes
fn bytes_to_hex_str(b: &[u8]) -> String {
    b.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Returns a state address for a given sabre contract registry
///
/// # Arguments
///
/// * `name` - the name of the contract registry
fn compute_contract_registry_address(name: &str) -> String {
    let hash: &mut [u8] = &mut [0; 64];

    let mut sha = Sha512::new();
    sha.input(name.as_bytes());
    sha.result(hash);

    String::from(SABRE_CONTRACT_REGISTRY_PREFIX) + &bytes_to_hex_str(hash)[..64]
}

/// Returns a state address for a given sabre contract
///
/// # Arguments
///
/// * `name` - the name of the contract
/// * `version` - the version of the contract
fn compute_contract_address(name: &str, version: &str) -> String {
    let hash: &mut [u8] = &mut [0; 64];

    let s = String::from(name) + "," + version;

    let mut sha = Sha512::new();
    sha.input(s.as_bytes());
    sha.result(hash);

    String::from(SABRE_CONTRACT_PREFIX) + &bytes_to_hex_str(hash)[..64]
}

/// Returns a state address for a given namespace registry
///
/// # Arguments
///
/// * `namespace` - the address prefix for this namespace
fn compute_namespace_registry_address(namespace: &str) -> Result<String, CliError> {
    let prefix = match namespace.get(..6) {
        Some(x) => x,
        None => {
            return Err(CliError::UserError(format!(
                "Namespace must be at least 6 characters long: {}",
                namespace
            )));
        }
    };

    let hash: &mut [u8] = &mut [0; 64];

    let mut sha = Sha512::new();
    sha.input(prefix.as_bytes());
    sha.result(hash);

    Ok(String::from(SABRE_NAMESPACE_REGISTRY_PREFIX) + &bytes_to_hex_str(hash)[..64])
}
