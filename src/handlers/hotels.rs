use crate::models::hotel::Hotel;
use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use sqlx::SqlitePool;

#[derive(Deserialize)]
pub struct HotelSearch {
    pub city: Option<String>,
    pub min_price: Option<f64>,
    pub max_price: Option<f64>,
}

pub async fn get_hotels(
    pool: web::Data<SqlitePool>,
    params: web::Query<HotelSearch>,
) -> impl Responder {
    let mut query = String::from("SELECT * FROM hotels WHERE 1=1");

    if let Some(city) = &params.city {
        query.push_str(&format!(" AND city LIKE '%{}%'", city));
    }

    if let Some(min) = params.min_price {
        query.push_str(&format!(" AND price_per_night >= {}", min));
    }

    if let Some(max) = params.max_price {
        query.push_str(&format!(" AND price_per_night <= {}", max));
    }

    let hotels = sqlx::query_as::<_, Hotel>(&query)
        .fetch_all(pool.get_ref())
        .await;

    match hotels {
        Ok(hotels) => HttpResponse::Ok().json(hotels),
        Err(_) => HttpResponse::InternalServerError().json("Error fetching hotels"),
    }
}

pub async fn get_hotel_by_id(pool: web::Data<SqlitePool>, path: web::Path<i64>) -> impl Responder {
    let id = path.into_inner();

    let hotel = sqlx::query_as::<_, Hotel>("SELECT * FROM hotels WHERE id = ?")
        .bind(id)
        .fetch_optional(pool.get_ref())
        .await;

    match hotel {
        Ok(Some(hotel)) => HttpResponse::Ok().json(hotel),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Hotel not found"})),
        Err(_) => HttpResponse::InternalServerError().json("Error fetching hotel"),
    }
}
