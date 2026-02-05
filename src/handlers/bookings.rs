use crate::models::booking::{Booking, CreateBooking};
use crate::models::hotel::Hotel;
use actix_web::{web, HttpResponse, Responder};

use sqlx::{Row, SqlitePool};
use validator::Validate;

// Helper error struct
#[derive(serde::Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn create_booking(
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateBooking>,
) -> impl Responder {
    // 1. Validar inputs básicos
    if let Err(e) = body.validate() {
        return HttpResponse::BadRequest().json(e);
    }

    if body.check_in >= body.check_out {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Check-out must be after check-in".to_string(),
        });
    }

    // 2. Transacción de base de datos (CRÍTICO: Inicia transacción)
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return HttpResponse::InternalServerError().json("Failed to start transaction"),
    };

    // 3. Verificar existencia del hotel y precio
    let hotel = match sqlx::query_as::<_, Hotel>("SELECT * FROM hotels WHERE id = ?")
        .bind(body.hotel_id)
        .fetch_optional(&mut *tx)
        .await
    {
        Ok(Some(h)) => h,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "Hotel not found".to_string(),
            })
        }
        Err(_) => return HttpResponse::InternalServerError().json("Database error"),
    };

    // 4. Lógica de "Overbooking Prevention"
    // Sumar todas las habitaciones reservadas que se solapen con estas fechas
    let rooms_taken: i64 = match sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(rooms), 0) FROM bookings 
        WHERE hotel_id = ? 
        AND status = 'confirmed'
        AND check_in < ? 
        AND check_out > ?
        "#,
    )
    .bind(body.hotel_id)
    .bind(body.check_out)
    .bind(body.check_in)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(count) => count,
        Err(_) => return HttpResponse::InternalServerError().json("Availability check failed"),
    };

    if rooms_taken + body.rooms > hotel.total_rooms as i64 {
        return HttpResponse::Conflict().json(ErrorResponse {
            error: format!(
                "Not enough rooms available. {} taken, {} requested, {} total.",
                rooms_taken, body.rooms, hotel.total_rooms
            ),
        });
    }

    // 5. Calcular precio total
    let nights = (body.check_out - body.check_in).num_days();
    let total_price = hotel.price_per_night * (nights as f64) * (body.rooms as f64);

    // 6. Insertar Reserva
    let booking_id = match sqlx::query(
        r#"
        INSERT INTO bookings (hotel_id, guest_name, email, check_in, check_out, rooms, guests_count, total_price, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'confirmed')
        RETURNING id
        "#
    )
    .bind(body.hotel_id)
    .bind(&body.guest_name)
    .bind(&body.email)
    .bind(body.check_in)
    .bind(body.check_out)
    .bind(body.rooms)
    .bind(body.guests_count)
    .bind(total_price)
    .fetch_one(&mut *tx)
    .await {
        Ok(row) => row.get::<i64, _>("id"),
        Err(_) => return HttpResponse::InternalServerError().json("Failed to insert booking"),
    };

    // 7. Commit Transacción
    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError().json("Failed to commit transaction");
    }

    // 8. Retornar éxito
    HttpResponse::Created().json(serde_json::json!({
        "id": booking_id,
        "status": "confirmed",
        "total_price": total_price,
        "message": "Booking successful"
    }))
}

pub async fn get_booking(pool: web::Data<SqlitePool>, path: web::Path<i64>) -> impl Responder {
    let id = path.into_inner();

    match sqlx::query_as::<_, Booking>("SELECT * FROM bookings WHERE id = ?")
        .bind(id)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(booking)) => HttpResponse::Ok().json(booking),
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "Booking not found".to_string(),
        }),
        Err(_) => HttpResponse::InternalServerError().json("Database error"),
    }
}

pub async fn cancel_booking(pool: web::Data<SqlitePool>, path: web::Path<i64>) -> impl Responder {
    let id = path.into_inner();

    // Start transaction
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return HttpResponse::InternalServerError().json("Failed to start transaction"),
    };

    // Check if booking exists and check-in hasn't passed
    let booking = match sqlx::query_as::<_, Booking>("SELECT * FROM bookings WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                error: "Booking not found".to_string(),
            })
        }
        Err(_) => return HttpResponse::InternalServerError().json("Database error"),
    };

    let today = chrono::Utc::now().naive_utc().date();
    if booking.check_in <= today {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Cannot cancel booking after or on check-in date".to_string(),
        });
    }

    if sqlx::query("UPDATE bookings SET status = 'cancelled' WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json("Failed to cancel booking");
    }

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError().json("Failed to commit transaction");
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Booking cancelled successfully",
        "id": id,
        "refund_amount": booking.total_price
    }))
}
