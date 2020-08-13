// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate cfg_if;
extern crate crypto;
extern crate dgc_config;
extern crate protobuf;

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        #[macro_use]
        extern crate sabre_sdk;
    } else {
        #[macro_use]
        extern crate clap;
        #[macro_use]
        extern crate log;
        extern crate sawtooth_sdk;
        extern crate flexi_logger;

        mod error;

        use flexi_logger::{LogSpecBuilder, Logger};
        use sawtooth_sdk::processor::TransactionProcessor;
        use handler::PikeTransactionHandler;
        use error::CliError;
    }
}

pub mod handler;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<(), CliError> {
    let matches = clap_app!(wasm_store_tp =>
        (version: crate_version!())
        (about: "Implements the Pike transaction family")
        (@arg connect: -C --connect +takes_value
         "connection endpoint for validator")
        (@arg verbose: -v --verbose +multiple
         "increase output verbosity"))
    .get_matches();

    let log_level = match matches.occurrences_of("verbose") {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    let mut log_spec_builder = LogSpecBuilder::new();
    log_spec_builder.default(log_level);
    Logger::with(log_spec_builder.build()).start()?;

    let connect = matches
        .value_of("connect")
        .unwrap_or("tcp://localhost:4004");

    let handler = PikeTransactionHandler::new();
    let mut processor = TransactionProcessor::new(connect);

    processor.add_handler(&handler);
    processor.start();

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {}
