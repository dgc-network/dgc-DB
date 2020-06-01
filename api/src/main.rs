// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

#[macro_use] extern crate log;

mod routes;
mod error;
mod submitter;
mod transaction;
mod key;
mod http;

use actix_web::{web, App, HttpResponse, HttpServer, Responder, };
//use actix_web::{web, App, HttpResponse, HttpServer, Responder, Result,};
//use crate::routes::{
//    fetch_agent, fetch_grid_schema, fetch_organization, fetch_product, fetch_record,
//    fetch_record_property, list_agents, list_grid_schemas, list_organizations,
//    list_products, list_records, submit_batches, get_batch_statuses, 
//};
use crate::routes::batches::{submit_batches, get_batch_statuses};
use crate::routes::agents::{create_agent, update_agent, list_agents, fetch_agent};
use crate::submitter::BatchSubmitter;
pub use crate::error::RestApiServerError;

#[derive(Clone)]
pub struct AppState {
    batch_submitter: Box<dyn BatchSubmitter + 'static>,
    //database_connection: Addr<DbExecutor>,
}
/*
impl AppState {
    pub fn new(
        //batch_submitter: Box<dyn BatchSubmitter + 'static>,
        //connection_pool: ConnectionPool,
    ) -> Self {
        //let database_connection = SyncArbiter::start(SYNC_ARBITER_THREAD_COUNT, move || {
        //    DbExecutor::new(connection_pool.clone())
        //});

        AppState {
            batch_submitter: Box<dyn BatchSubmitter + 'static>,
            //batch_submitter,
            //database_connection,
        }
    }
}
*/
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[actix_rt::main]
async fn main(
    //bind_url: &str,
    //batch_submitter: Box<dyn BatchSubmitter + 'static>,
) -> std::io::Result<()> {
//) -> Result<(RestApiShutdownHandle,
//    thread::JoinHandle<Result<(), RestApiServerError>>,),
//    RestApiServerError,> {
//) -> Result {

    //let batch_submitter = web::Data::new(AppState {
    //    batch_submitter: Box<dyn BatchSubmitter + 'static>,
    //});

    //let state = AppState::new(batch_submitter);
    //HttpServer::new(move || {
    HttpServer::new(|| {
        App::new()
            //.data(state.clone())
            .data(AppState {
                //batch_submitter: Box<dyn BatchSubmitter + 'static>::from("Actix-web"),
                batch_submitter,
            })
            //.data(batch_submitter.clone())
            .route("/", web::get().to(index))
            .service(web::resource("/batches").route(web::post().to(submit_batches)))
            .service(
                web::resource("/batch_statuses")
                    .name("batch_statuses")
                    .route(web::get().to(get_batch_statuses)),
            )
            
            .service(
                web::scope("/agent")
                    .service(web::resource("")
                        .route(web::post().to(create_agent))
                        .route(web::put().to(update_agent))
                        .route(web::get().to(list_agents)))
                    .service(
                        web::resource("/{public_key}").route(web::get().to(fetch_agent)),
                    ),
            )
/*            
            .service(
                web::scope("/organization")
                    .service(web::resource("").route(web::get().to(list_organizations)))
                    .service(
                        web::resource("/{id}").route(web::get().to(fetch_organization)),
                    ),
            )
            .service(
                web::scope("/product")
                    .service(web::resource("").route(web::get().to(list_products)))
                    .service(web::resource("/{id}").route(web::get().to(fetch_product))),
            )
            .service(
                web::scope("/schema")
                    .service(web::resource("").route(web::get().to(list_grid_schemas)))
                    .service(
                        web::resource("/{name}").route(web::get().to(fetch_grid_schema)),
                    ),
            )
            .service(
                web::scope("/record")
                    .service(web::resource("").route(web::get().to(list_records)))
                    .service(
                        web::scope("/{record_id}")
                            .service(web::resource("").route(web::get().to(fetch_record)))
                            .service(
                                web::resource("/property/{property_name}")
                                    .route(web::get().to(fetch_record_property)),
                            ),
                    ),
            )
*/            
})
//    .bind("127.0.0.1:8088")?
//    .bind(bind_url)?
    .bind("0.0.0.0:8088")?
    .run()
    .await
}