# 🎙️ GUÍA TÁCTICA PARA LA ENTREVISTA

Esta guía es tu "chuleta" para tener abierta durante la llamada. No la leas literal, úsala como puntos de apoyo.

---

## 1. INTRODUCCIÓN (Tu Historia)
> **Pregunta:** *"Cuéntanos sobre ti."*

*   "Soy Alfred. Durante el día trabajo en el campo, lo que me ha enseñado disciplina y esfuerzo duro. Pero mi verdadera pasión está en el código, especialmente en el **Backend y Rust**."
*   "Llevo tiempo formándome en sistemas de alto rendimiento y bajo nivel. Busco mi primera oportunidad profesional para aplicar esta obsesión por la calidad y la eficiencia."

---

## 2. DEMO DEL PROYECTO (Hotel API)
> **Acción:** Comparte pantalla y muestra el código o la terminal.

### Puntos Clave a Mencionar:
1.  **Arquitectura Limpia:**
    *   "He separado el código en `models`, `handlers` y `db`. Está todo modularizado para que el equipo pueda crecer sin pisarse el código."

2.  **Seguridad Anti-Overbooking (La Joya):**
    *   *Abre `src/handlers/bookings.rs` (línea ~40)*.
    *   "Lo más importante en un hotel es no vender la misma habitación dos veces. Para eso implementé **Transacciones Atómicas ACID** (`pool.begin()`)."
    *   "La base de datos bloquea la operación hasta confirmar que hay sitio. Si 100 personas clican 'Reservar' a la vez, el sistema garantiza que no habrá errores."

3.  **Portabilidad:**
    *   "Uso **SQLite** para esta demo porque así podéis probarlo sin instalar nada. Pero el código usa `sqlx`, así que cambiar a **PostgreSQL** para producción es cambiar literalmente UNA lÍNEA en el `.env`."

---

## 3. EL "FACTOR WOW" (El Kernel Anti-DDoS)
> **Estrategia:** Sacar esto cuando te pregunten por tus intereses o si sabes algo más avanzado.

*   "Además de la API, en mis ratos libres investigo sobre ciberseguridad y rendimiento extremo."
*   "He incluido en la carpeta `/kernel` un prototipo de **WAF (Firewall)** que estoy diseñando."
*   **¿Qué hace especial a este Kernel?**
    *   **SIMD:** "Usa instrucciones vectoriales (como las de los videojuegos) para escanear paquetes de red a la velocidad de la luz."
    *   **Seguridad:** "Detecta ataques de SQL Injection y patrones binarios de hackers antes de que lleguen a la API."
    *   "Es un prototipo, pero demuestra que puedo manejar Rust a nivel de sistema, no solo hacer APIs web."

---

## 4. PREGUNTAS TÉCNICAS (Respuestas Preparadas)

### *"¿Por qué Rust y no Node.js o Python?"*
> "Por **seguridad** y **ahorro de costes**. Rust previene errores de memoria en tiempo de compilación (no tendremos caídas sorpresa en producción). Además, consume mucha menos RAM que Node.js, lo que nos ahorrará dinero en servidores AWS/Azure."

### *"¿Cómo escalarías esto si tenemos 1 millón de usuarios?"*
> 1. Cambiaría SQLite por **PostgreSQL**.
> 2. Pondría un **Load Balancer** (Nginx) delante de varias instancias de esta API.
> 3. Añadiría **Redis** para cachear las búsquedas de hoteles (lectura rápida).
> 4. E integraría mi Kernel para filtrar el tráfico malicioso.

### *"¿Tienes experiencia profesional?"*
> "Esta sería mi primera experiencia oficial, pero como veis, no programo como un junior. Tengo una capacidad de trabajo brutal (gracias al campo) y aprendo tecnologías complejas como Rust por mi cuenta. Si me dais la oportunidad, voy a rendir desde el día uno."

---

## 5. CIERRE
*   "Me da igual que el equipo sea pequeño o el sueldo inicial. Yo quiero aportar valor, aprender de vosotros y demostrar que puedo construir software de calidad internacional."
*   "Gracias por vuestro tiempo."
