// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

use futures::prelude::*;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use sawtooth_sdk::messages::batch::{Batch, BatchList};
use sawtooth_sdk::messages::client_batch_submit::{
    ClientBatchStatus,
    ClientBatchStatusRequest, ClientBatchStatusResponse, ClientBatchStatusResponse_Status,
    ClientBatchSubmitRequest, ClientBatchSubmitResponse, ClientBatchSubmitResponse_Status,
};
//use sawtooth_sdk::messages::validator::Message_MessageType;
use sawtooth_sdk::messages::validator::{Message, Message_MessageType};
//use sawtooth_sdk::messaging::stream::MessageSender;
use sawtooth_sdk::messaging::stream::{MessageFuture, MessageSender, SendError};
use sawtooth_sdk::messaging::zmq_stream::ZmqMessageSender;
use std::sync::mpsc::channel;

use crate::error::RestApiResponseError;

pub const DEFAULT_TIME_OUT: u32 = 300; // Max timeout 300 seconds == 5 minutes

pub struct SubmitBatches {
    pub batch_list: BatchList,
    pub response_url: Url,
    //pub service_id: Option<String>,
}

pub struct BatchStatuses {
    pub batch_ids: Vec<String>,
    pub wait: Option<u32>,
    //pub service_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BatchStatus {
    pub id: String,
    pub invalid_transactions: Vec<HashMap<String, String>>,
    pub status: String,
}

impl BatchStatus {
    pub fn from_proto(proto: &ClientBatchStatus) -> BatchStatus {
        BatchStatus {
            id: proto.get_batch_id().to_string(),
            invalid_transactions: proto
                .get_invalid_transactions()
                .iter()
                .map(|txn| {
                    let mut invalid_transaction_info = HashMap::new();
                    invalid_transaction_info
                        .insert("id".to_string(), txn.get_transaction_id().to_string());
                    invalid_transaction_info
                        .insert("message".to_string(), txn.get_message().to_string());
                    invalid_transaction_info.insert(
                        "extended_data".to_string(),
                        base64::encode(txn.get_extended_data()),
                    );
                    invalid_transaction_info
                })
                .collect(),
            status: format!("{:?}", proto.get_status()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BatchStatusResponse {
    pub data: Vec<BatchStatus>,
    pub link: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BatchStatusLink {
    pub link: String,
}

pub trait BatchSubmitter: Send + 'static {
    fn submit_batches(
        &self,
        submit_batches: SubmitBatches,
    ) -> Pin<Box<dyn Future<Output = Result<BatchStatusLink, RestApiResponseError>> + Send>>;

    fn batch_status(
        &self,
        batch_statuses: BatchStatuses,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<BatchStatus>, RestApiResponseError>> + Send>>;

    fn clone_box(&self) -> Box<dyn BatchSubmitter>;
}

impl Clone for Box<dyn BatchSubmitter> {
    fn clone(&self) -> Box<dyn BatchSubmitter> {
        self.clone_box()
    }
}
/*
#[derive(Clone)]
pub struct SawtoothBatchSubmitter {
    sender: ZmqMessageSender,
}

impl SawtoothBatchSubmitter {
    pub fn new(sender: ZmqMessageSender) -> Self {
        Self { sender }
    }
}

macro_rules! try_fut {
    ($try_expr:expr) => {
        match $try_expr {
            Ok(res) => res,
            Err(err) => return futures::future::err(err).boxed(),
        }
    };
}

impl BatchSubmitter for SawtoothBatchSubmitter {
    fn submit_batches(
        &self,
        msg: SubmitBatches,
    ) -> Pin<Box<dyn Future<Output = Result<BatchStatusLink, RestApiResponseError>> + Send>> {
        
        let mut client_submit_request = ClientBatchSubmitRequest::new();
        client_submit_request.set_batches(protobuf::RepeatedField::from_vec(
            msg.batch_list.get_batches().to_vec(),
        ));

        let response_status: ClientBatchSubmitResponse = try_fut!(query_validator(
            &self.sender,
            Message_MessageType::CLIENT_BATCH_SUBMIT_REQUEST,
            &client_submit_request,
        ));

        future::ready(
            process_validator_response(response_status.get_status()).map(|_| {
                let batch_query = msg
                    .batch_list
                    .get_batches()
                    .iter()
                    .map(Batch::get_header_signature)
                    .collect::<Vec<_>>()
                    .join(",");

                let mut response_url = msg.response_url;
                response_url.set_query(Some(&format!("id={}", batch_query)));

                BatchStatusLink {
                    link: response_url.to_string(),
                }
            }),
        ).boxed()
    }

    fn batch_status(
        &self,
        msg: BatchStatuses,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<BatchStatus>, RestApiResponseError>> + Send>> {
        let mut batch_status_request = ClientBatchStatusRequest::new();
        batch_status_request.set_batch_ids(protobuf::RepeatedField::from_vec(msg.batch_ids));
        match msg.wait {
            Some(wait_time) => {
                batch_status_request.set_wait(true);
                batch_status_request.set_timeout(wait_time);
            }
            None => {
                batch_status_request.set_wait(false);
            }
        }

        println!("I am here! msg.wait = {:?}", msg.wait);

        let response_status: ClientBatchStatusResponse = try_fut!(query_validator(
            &self.sender,
            Message_MessageType::CLIENT_BATCH_STATUS_REQUEST,
            &batch_status_request,
        ));

        println!("I am here! response_status = {:?}", response_status);

        future::ready(process_batch_status_response(response_status)).boxed()
    }

    fn clone_box(&self) -> Box<dyn BatchSubmitter> {
        Box::new(self.clone())
    }
}
*/
pub struct MockMessageSender {
    response_type: ResponseType,
}

#[derive(Clone, Copy, Debug)]
pub enum ResponseType {
    ClientBatchStatusResponseOK,
    ClientBatchStatusResponseInvalidId,
    ClientBatchStatusResponseInternalError,
    ClientBatchSubmitResponseOK,
    ClientBatchSubmitResponseInvalidBatch,
    ClientBatchSubmitResponseInternalError,
}

impl MockMessageSender {
    pub fn new(response_type: ResponseType) -> Self {
        MockMessageSender { response_type }
    }
}

macro_rules! try_fut {
    ($try_expr:expr) => {
        match $try_expr {
            Ok(res) => res,
            Err(err) => return futures::future::err(err).boxed(),
        }
    };
}

pub struct MockBatchSubmitter {
    sender: MockMessageSender,
}

impl BatchSubmitter for MockBatchSubmitter {
    fn submit_batches(
        &self,
        msg: SubmitBatches,
    ) -> Pin<Box<dyn Future<Output = Result<BatchStatusLink, RestApiResponseError>> + Send>>
    {
        let mut client_submit_request = ClientBatchSubmitRequest::new();
        client_submit_request.set_batches(protobuf::RepeatedField::from_vec(
            msg.batch_list.get_batches().to_vec(),
        ));

        let response_status: ClientBatchSubmitResponse = try_fut!(query_validator(
            &self.sender,
            Message_MessageType::CLIENT_BATCH_SUBMIT_REQUEST,
            &client_submit_request,
        ));

        future::ready(
            match process_validator_response(response_status.get_status()) {
                Ok(_) => {
                    let batch_query = msg
                        .batch_list
                        .get_batches()
                        .iter()
                        .map(Batch::get_header_signature)
                        .collect::<Vec<_>>()
                        .join(",");

                    let mut response_url = msg.response_url.clone();
                    response_url.set_query(Some(&format!("id={}", batch_query)));

                    Ok(BatchStatusLink {
                        link: response_url.to_string(),
                    })
                }
                Err(err) => Err(err),
            },
        )
        .boxed()
    }

    fn batch_status(
        &self,
        msg: BatchStatuses,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<BatchStatus>, RestApiResponseError>> + Send>>
    {
        let mut batch_status_request = ClientBatchStatusRequest::new();
        batch_status_request.set_batch_ids(protobuf::RepeatedField::from_vec(msg.batch_ids));
        match msg.wait {
            Some(wait_time) => {
                batch_status_request.set_wait(true);
                batch_status_request.set_timeout(wait_time);
            }
            None => {
                batch_status_request.set_wait(false);
            }
        }

        let response_status: ClientBatchStatusResponse = try_fut!(query_validator(
            &self.sender,
            Message_MessageType::CLIENT_BATCH_STATUS_REQUEST,
            &batch_status_request,
        ));

        future::ready(process_batch_status_response(response_status)).boxed()
    }

    fn clone_box(&self) -> Box<dyn BatchSubmitter> {
        unimplemented!()
    }
}

impl MessageSender for MockMessageSender {
/*    
    fn send(
        &self,
        destination: Message_MessageType,
        correlation_id: &str,
        contents: &[u8],
    ) -> Result<MessageFuture, SendError> {
        let mut mock_validator_response = Message::new();
        mock_validator_response.set_message_type(destination);
        mock_validator_response.set_correlation_id(correlation_id.to_string());
        match &self.response_type {
            ResponseType::ClientBatchStatusResponseOK => {
                let request: ClientBatchStatusRequest =
                    protobuf::parse_from_bytes(contents).unwrap();
                if request.get_batch_ids().len() <= 1 {
                    mock_validator_response.set_content(get_batch_statuses_response_one_id())
                } else {
                    mock_validator_response
                        .set_content(get_batch_statuses_response_multiple_ids())
                }
            }
            ResponseType::ClientBatchStatusResponseInvalidId => {
                mock_validator_response.set_content(get_batch_statuses_response_invalid_id())
            }
            ResponseType::ClientBatchStatusResponseInternalError => mock_validator_response
                .set_content(get_batch_statuses_response_validator_internal_error()),
            ResponseType::ClientBatchSubmitResponseOK => mock_validator_response.set_content(
                get_submit_batches_response(ClientBatchSubmitResponse_Status::OK),
            ),
            ResponseType::ClientBatchSubmitResponseInvalidBatch => mock_validator_response
                .set_content(get_submit_batches_response(
                    ClientBatchSubmitResponse_Status::INVALID_BATCH,
                )),
            ResponseType::ClientBatchSubmitResponseInternalError => mock_validator_response
                .set_content(get_submit_batches_response(
                    ClientBatchSubmitResponse_Status::INTERNAL_ERROR,
                )),
        }

        let mock_resut = Ok(mock_validator_response);
        let (send, recv) = channel();
        send.send(mock_resut).unwrap();
        Ok(MessageFuture::new(recv))
    }
*/
    fn reply(
        &self,
        _destination: Message_MessageType,
        _correlation_id: &str,
        _contents: &[u8],
    ) -> Result<(), SendError> {
        unimplemented!()
    }

    fn close(&mut self) {
        unimplemented!()
    }
}

pub fn query_validator<T: protobuf::Message, C: protobuf::Message, MS: MessageSender>(
    sender: &MS,
    message_type: Message_MessageType,
    message: &C,
) -> Result<T, RestApiResponseError> {

    println!("I am here! message = {:?}", message);

    let content = protobuf::Message::write_to_bytes(message).map_err(|err| {
        RestApiResponseError::RequestHandlerError(format!(
            "Failed to serialize batch submit request. {}",
            err.to_string()
        ))
    })?;

    println!("I am here! content = {:?}", content);

    let correlation_id = Uuid::new_v4().to_string();

    println!("I am here! correlation_id = {:?}", correlation_id);

    let mut response_future = sender
        .send(message_type, &correlation_id, &content)
        .map_err(|err| {
            RestApiResponseError::SawtoothConnectionError(format!(
                "Failed to send message to validator. {}",
                err.to_string()
            ))
        })?;

    println!("I am here! response_future = {:?}", response_future);

    protobuf::parse_from_bytes(
        response_future
            .get_timeout(Duration::new(DEFAULT_TIME_OUT.into(), 0))
            .map_err(|err| RestApiResponseError::RequestHandlerError(err.to_string()))?
            .get_content(),
    )
    .map_err(|err| {
        RestApiResponseError::RequestHandlerError(format!(
            "Failed to parse validator response from bytes. {}",
            err.to_string()
        ))
    })

}

pub fn process_validator_response(
    status: ClientBatchSubmitResponse_Status,
) -> Result<(), RestApiResponseError> {

    Ok(())
/*
    match status {
        ClientBatchSubmitResponse_Status::OK => Ok(()),
        ClientBatchSubmitResponse_Status::INVALID_BATCH => Err(RestApiResponseError::BadRequest(
            "The submitted BatchList was rejected by the validator. It was '
            'poorly formed, or has an invalid signature."
                .to_string(),
        )),
        _ => Err(RestApiResponseError::SawtoothValidatorResponseError(
            format!("Validator responded with error {:?}", status),
        )),
    }
*/
}

pub fn process_batch_status_response(
    response: ClientBatchStatusResponse,
) -> Result<Vec<BatchStatus>, RestApiResponseError> {
    let status = response.get_status();
    match status {
        ClientBatchStatusResponse_Status::OK => Ok(response
            .get_batch_statuses()
            .iter()
            .map(BatchStatus::from_proto)
            .collect()),
        ClientBatchStatusResponse_Status::INVALID_ID => Err(RestApiResponseError::BadRequest(
            "Blockchain items are identified by 128 character hex-strings. A submitted \
             batch id was invalid"
                .to_string(),
        )),
        _ => Err(RestApiResponseError::SawtoothValidatorResponseError(
            format!("Validator responded with error {:?}", status),
        )),
    }
}
