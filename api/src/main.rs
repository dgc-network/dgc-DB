// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

mod routes;
mod error;
mod transaction;

use actix_web::*;
use serde::Deserialize;

use crate::routes::agents::*;
use crate::routes::organizations::*;
use crate::routes::products::*;
use crate::routes::schemas::*;
use crate::routes::records::*;

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
pub struct Fetch {
    data: String,
    head: String,
    link: String,
}

async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello world! Welcome to dgc.network")
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let endpoint = "0.0.0.0:8088";
    //HttpServer::new(move || {
    HttpServer::new(|| {
        App::new()
            //.data(state.clone())
            .route("/", web::get().to(index))
            .route("/keygen", web::post().to(keygen))
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
                .route(web::put().to(update_agent)))

            .service(web::resource("/agents")
                .name("agents")
                .route(web::get().to(list_agents)))

            .service(web::resource("/agent/{public_key}")
                .route(web::get().to(fetch_agent)))
        
            .service(web::resource("/organization")
                .name("organization")
                .route(web::post().to(create_org))
                .route(web::put().to(update_org)))

            .service(web::resource("/organizations")
                .name("organizations")
                .route(web::get().to(list_orgs)))

            .service(web::resource("/organization/{org_id}")
                .route(web::get().to(fetch_org)))

            .service(web::resource("/product")
                .name("product")
                .route(web::post().to(create_product))
                .route(web::put().to(update_product)))

            .service(web::resource("/products")
                .name("products")
                .route(web::get().to(list_products)))

            .service(web::resource("/product/{product_id}")
                .route(web::get().to(fetch_product)))

            .service(web::resource("/schema")
                .name("schema")
                .route(web::post().to(create_schema))
                .route(web::put().to(update_schema)))

            .service(web::resource("/schemas")
                .name("schemas")
                .route(web::get().to(list_schemas)))

            .service(web::resource("/schema/{schema_name}")
                .route(web::get().to(fetch_schema)))

            .service(web::resource("/record")
                .name("record")
                .route(web::post().to(create_record))
                .route(web::put().to(update_record)))

            .service(web::resource("/records")
                .name("records")
                .route(web::get().to(list_records)))

            .service(web::resource("/record/{record_id}")
                .route(web::get().to(fetch_record)))

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