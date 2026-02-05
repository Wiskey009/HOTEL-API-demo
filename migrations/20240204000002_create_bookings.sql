-- Create bookings table
CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hotel_id INTEGER NOT NULL REFERENCES hotels(id),
    guest_name TEXT NOT NULL,
    email TEXT NOT NULL,
    check_in DATE NOT NULL,
    check_out DATE NOT NULL,
    rooms INTEGER NOT NULL,
    guests_count INTEGER NOT NULL,
    total_price REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'confirmed',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index for faster availability checks
CREATE INDEX idx_bookings_hotel_dates ON bookings(hotel_id, check_in, check_out);
