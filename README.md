# Hotel Booking API 🏨

Esta es una demostración técnica de una API RESTful construida con **Rust**, diseñada para gestionar reservas de hoteles de forma eficiente, segura y concurrente.

El objetivo principal de este proyecto no es solo ofrecer funcionalidad, sino demostrar cómo **Rust** garantiza la integridad de los datos y el rendimiento del sistema desde la base, incluso en un desarrollo ágil.

## 🛠️ Tecnologías Principales

*   **Lenguaje:** Rust (Edición 2021)
*   **Framework Web:** Actix-web (Rendimiento líder en benchmarks)
*   **Base de Datos:** SQLite (vía `sqlx`).
    *   *Nota:* Se eligió SQLite por portabilidad para facilitar la revisión del código sin dependencias externas, pero la arquitectura con `sqlx` permite migrar a PostgreSQL cambiando solo una línea de configuración.
*   **Seguridad:** Validaciones fuertes de tipos y prevención de *Race Conditions* mediante transacciones ACID.

## ✨ Funcionalidades Implementadas

### Core API
1.  **Gestión de Hoteles:** Búsqueda y filtrado eficiente (por ciudad, precio).
2.  **Sistema de Reservas:**
    *   Creación de reservas con validación de fechas cruzadas.
    *   **Prevención de Overbooking:** Uso de transacciones de base de datos atómicas para garantizar que no se asignen más habitaciones de las disponibles, incluso bajo alta concurrencia.
    *   Cancelación de reservas y gestión de estados.

### 🛡️ Experimental: Anti-DDoS Kernel
En la carpeta `/kernel` he incluido un módulo experimental (`BlitzKernel`).
Es un **prototipo técnico** que explora cómo implementar un WAF (Web Application Firewall) de alto rendimiento utilizando:
*   Instrucciones **SIMD** para inspección profunda de paquetes a velocidad de hardware.
*   Detección de patrones de ataque (SQLi, Shellcode) en flujos binarios.
*   Gestión de memoria *Zero-Copy* para minimizar latencia.

*Este módulo representa mi interés personal por la ingeniería de sistemas, la seguridad y el código de bajo nivel.*

## 🚀 Cómo Ejecutar

El proyecto está diseñado para ser "Plug & Play".

1.  Asegúrate de tener Rust instalado.
2.  Desde la terminal:

```bash
cargo run
```

El servidor iniciará en `http://localhost:8080`.
La base de datos se inicializará y migrará automáticamente al arrancar.

## 🧪 Pruebas Rápidas

**Listar Hoteles:**
```bash
curl http://localhost:8080/hotels
```

**Crear una Reserva de Prueba:**
```bash
curl -X POST http://localhost:8080/bookings \
  -H "Content-Type: application/json" \
  -d '{
    "hotel_id": 1,
    "guest_name": "Demo User",
    "email": "demo@test.com",
    "check_in": "2026-05-01",
    "check_out": "2026-05-05",
    "rooms": 1,
    "guests_count": 2
  }'
```

---

*Desarrollado con pasión y café de madrugada por Alfred.*
