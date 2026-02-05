use actix_web::{middleware, web, App, HttpServer};
use dotenv::dotenv;
use env_logger::Env;

mod db;
mod handlers;
mod models;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger and environment
    dotenv().ok();
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    log::info!("Connecting to database...");
    let pool = db::get_db_pool().await;

    // Run migrations
    log::info!("Running migrations...");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    log::info!("Starting server at http://localhost:8080");

    let pool_data = web::Data::new(pool);

    HttpServer::new(move || {
        App::new()
            .app_data(pool_data.clone())
            .wrap(middleware::Logger::default())
            .service(
                web::scope("/hotels")
                    .route("", web::get().to(handlers::hotels::get_hotels))
                    .route("/{id}", web::get().to(handlers::hotels::get_hotel_by_id)),
            )
            .service(
                web::scope("/bookings")
                    .route("", web::post().to(handlers::bookings::create_booking))
                    .route("/{id}", web::get().to(handlers::bookings::get_booking))
                    .route(
                        "/{id}",
                        web::delete().to(handlers::bookings::cancel_booking),
                    ),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
