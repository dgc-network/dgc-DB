// Copyright (c) The dgc.network
// SPDX-License-Identifier: Apache-2.0

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use crate::api::routes::{
//    fetch_agent, fetch_grid_schema, fetch_organization, fetch_product, fetch_record,
//    fetch_record_property, list_agents, list_grid_schemas, list_organizations,
//    list_products, list_records, submit_batches,
    get_batch_statuses, 
};

async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

async fn index2() -> impl Responder {
    HttpResponse::Ok().body("Hello world again!")
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(index))
            .route("/again", web::get().to(index2))
            .service(web::resource("/batches").route(web::post().to(submit_batches)))
            .service(
                web::resource("/batch_statuses")
                    .name("batch_statuses")
                    .route(web::get().to(get_batch_statuses)),
            )
/*            
            .service(
                web::scope("/agent")
                    .service(web::resource("").route(web::get().to(list_agents)))
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
//    .bind("127.0.0.1:8088")?
//    .bind(bind_url)?
    .bind("0.0.0.0:8088")?
    .run()
    .await
}