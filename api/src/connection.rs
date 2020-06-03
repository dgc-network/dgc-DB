// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use sawtooth_sdk::messaging::{
    stream::{MessageConnection, MessageReceiver},
    zmq_stream::{ZmqMessageConnection, ZmqMessageSender},
};

pub struct SawtoothConnection {
    sender: ZmqMessageSender,
    receiver: MessageReceiver,
}

impl SawtoothConnection {
    pub fn new(validator_address: &str) -> SawtoothConnection {
        let zmq_connection = ZmqMessageConnection::new(&validator_address);
        let (sender, receiver) = zmq_connection.create();
        SawtoothConnection { sender, receiver }
    }

    pub fn get_sender(&self) -> ZmqMessageSender {
        self.sender.clone()
    }

    pub fn get_receiver(&self) -> &MessageReceiver {
        &self.receiver
    }
}
