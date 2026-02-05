use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::env;

pub async fn get_db_pool() -> SqlitePool {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool")
}
