# 🛡️ BlitzKernel Anti-DDoS Module

> **Status:** Experimental Prototype
> **Performance:** Designed for >500k RPS inspection rate

Este módulo contiene el código fuente de un **Kernel de Seguridad (WAF)** diseñado para proteger la API del Hotel de ataques de alto volumen y explotación de vulnerabilidades.

## 🚀 Capacidades

Este kernel no es un simple middleware, es un motor de inspección profunda de paquetes (DPI) implementado en Rust de alto rendimiento.

1.  **Detección de Ataques en Tiempo Real:**
    *   **SQL Injection & XSS:** Escaneo de payloads en busca de patrones maliciosos.
    *   **SlowLoris:** Detección de conexiones lentas o cabeceras anómalas.
    *   **Shellcode (SIMD):** Uso de instrucciones vectoriales (`u8x16`) para detectar firmas binarias de exploits a velocidad de memoria.

2.  **Rate Limiting Inteligente:**
    *   Detección de ráfagas (Bursts) por IP.
    *   Scoring de reputación de IP dinámico.
    *   Blacklisting automático temporal.

3.  **Arquitectura Resiliente:**
    *   **Circuit Breaker:** Protege el backend (Hotel API) cortando el tráfico si detecta degradación de servicio.
    *   **Zero-Overhead:** Diseñado para añadir <1ms de latencia.

## 🛠️ Integración Propuesta

Aunque actualmente el código se encuentra aislado en `kernel/`, la arquitectura está diseñada para integrarse como un **Reverse Proxy** delante de la API:

```rust
// Ejemplo conceptual de integración en main.rs
use kernel::adaptedkernel::GatewayIntegration;

#[actix_web::main]
async fn main() {
    // 1. Iniciar el Escudo Anti-DDoS
    let shield = GatewayIntegration::new(
        "http://localhost:8080".to_string(), // Upstream (Hotel API)
        "http://backup-server".to_string() 
    );
    
    // 2. Activar mitigación automática
    shield.enable_auto_mitigation(90); // Bloquear si amenaza > 90%

    // 3. Iniciar Proxy Servidor
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(shield.clone()))
            .service(web::resource("/{tail:.*}").to(proxy_handler))
    })
    .bind(("0.0.0.0", 80))
    .run()
    .await
}
```

## 📂 Archivos del Módulo

*   `kernelSafe.rs`: Versión original optimizada para entornos WASM/Edge Computing.
*   `adaptedkernel.rs`: Versión adaptada con estructuras para servidor (Tokio/Gateway) y lógica de inspección profunda.

---
*Este módulo demuestra la capacidad de escalar la seguridad del proyecto desde una simple API REST hasta una infraestructura de misión crítica.*
