use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Hotel {
    pub id: i64,
    pub name: String,
    pub city: String,
    pub price_per_night: f64,
    pub available_rooms: i64,
    pub total_rooms: i64,
    pub rating: f32,
}
