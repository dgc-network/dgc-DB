// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

mod routes;
mod error;
mod transaction;

use actix_web::{web, App, HttpResponse, HttpServer, Responder, };
use serde::Deserialize;

use crate::routes::agents::{create_agent, update_agent, list_agents, fetch_agent};
use crate::routes::organizations::{create_org, update_org, list_orgs, fetch_org};

#[derive(Deserialize)]
pub struct List {
    data: Vec<Sub>,
    head: String,
    link: String,
}

#[derive(Deserialize)]
pub struct Sub {
    address: String,
    data: String,
}

#[derive(Deserialize)]
pub struct Res {
    data: String,
    head: String,
    link: String,
}

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