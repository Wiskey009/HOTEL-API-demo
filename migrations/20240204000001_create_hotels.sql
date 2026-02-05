-- Create hotels table
CREATE TABLE IF NOT EXISTS hotels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    city TEXT NOT NULL,
    price_per_night REAL NOT NULL,
    available_rooms INTEGER NOT NULL,
    total_rooms INTEGER NOT NULL,
    rating REAL NOT NULL
);

-- Seed some initial data
INSERT INTO hotels (name, city, price_per_night, available_rooms, total_rooms, rating)
VALUES 
('Hotel Paradise', 'Asunción', 150.0, 50, 100, 4.5),
('Hotel Deluxe', 'Ciudad del Este', 200.0, 30, 80, 4.8),
('Asunción Palace', 'Asunción', 80.0, 10, 40, 4.1);
