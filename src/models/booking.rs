use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Booking {
    pub id: i64,
    pub hotel_id: i64,
    pub guest_name: String,
    pub email: String,
    pub check_in: chrono::NaiveDate,
    pub check_out: chrono::NaiveDate,
    pub rooms: i64,
    pub guests_count: i64,
    pub total_price: f64,
    pub status: String,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateBooking {
    pub hotel_id: i64,
    pub guest_name: String,
    #[validate(email)]
    pub email: String,
    pub check_in: chrono::NaiveDate,
    pub check_out: chrono::NaiveDate,
    #[validate(range(min = 1))]
    pub rooms: i64,
    #[validate(range(min = 1))]
    pub guests_count: i64,
}
