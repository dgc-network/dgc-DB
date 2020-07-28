// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

mod routes;
mod error;
//mod submitter;
//mod state;
mod transaction;
//mod zmq_context;

use actix_web::{web, App, HttpResponse, HttpServer, Responder, };

//use crate::routes::batches::{submit_batches, get_batch_statuses};
use crate::routes::agents::{create_agent, update_agent, list_agents, fetch_agent};
use crate::routes::organizations::{create_org, update_org, list_orgs, fetch_org};
/*
#[derive(Clone)]
pub struct AppState {
    batch_submitter: Box<dyn BatchSubmitter + 'static>,
    //database_connection: Addr<DbExecutor>,
}

impl AppState {
    pub fn new(
        batch_submitter: Box<dyn BatchSubmitter + 'static>,
        //connection_pool: ConnectionPool,
    ) -> Self {
        //let database_connection = SyncArbiter::start(SYNC_ARBITER_THREAD_COUNT, move || {
        //    DbExecutor::new(connection_pool.clone())
        //});

        AppState {
            batch_submitter,
            //database_connection,
        }
    }
}
*/
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let endpoint = "0.0.0.0:8088";
    //HttpServer::new(move || {
    HttpServer::new(|| {
        App::new()
            //.data(state.clone())
            .route("/", web::get().to(index))
/*
            .service(web::resource("/submit_batches")
                .route(web::post().to(submit_batches)))

            .service(web::resource("/batch_statuses")
                .name("batch_statuses")
                .route(web::get().to(get_batch_statuses)))            
*/            
            .service(web::resource("/agent")
                .name("agent")
                .route(web::post().to(create_agent))
                .route(web::put().to(update_agent))
                .route(web::get().to(list_agents)))

            .service(web::resource("/agent/{public_key}")
                .route(web::get().to(fetch_agent)))
        
            .service(web::resource("/organization")
                .name("organization")
                .route(web::post().to(create_org))
                .route(web::put().to(update_org))
                .route(web::get().to(list_orgs)))

            .service(web::resource("/organization/{org_id}")
                .route(web::get().to(fetch_org)))
        
/*
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
    .bind(endpoint)?
    .run()
    .await
}