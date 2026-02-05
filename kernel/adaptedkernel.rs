// src/kernel/antiddos_kernel.rs
// =================================================================
// BLITZKERNEL ANTI-DDoS - 100% Safe + MÁXIMA PERFORMANCE
// Filtrado de tráfico, rate limiting y análisis en tiempo real
// =================================================================

#![forbid(unsafe_code)]
#![feature(portable_simd)]

use bytes::Bytes;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::simd::{u8x16, Simd, SimdPartialEq};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;

use js_sys::{Array, Date, Function, Object, Reflect, SharedArrayBuffer, Uint32Array, Uint8Array};
use wasm_bindgen::prelude::*;

// ==================== CONSTANTES ANTI-DDoS ====================
const CACHE_LINE: usize = 64;
const SIMD_WIDTH: usize = 16;
const REQUEST_BUFFER_SIZE: usize = 1024 * 1024 * 128; // 128MB para logs
const MAX_REQUESTS_PER_SEC: u32 = 10000;
const BURST_WINDOW: usize = 10;
const IP_BLACKLIST_CAPACITY: usize = 100_000;
const PATTERN_DB_SIZE: usize = 50_000;

// ==================== ESTRUCTURAS DE DETECCIÓN ====================

#[derive(Clone, Debug)]
struct IPProfile {
    ip: IpAddr,
    request_count: u32,
    last_request: Instant,
    request_timestamps: VecDeque<Instant>,
    suspicious_score: u8,
    is_whitelisted: bool,
    is_blacklisted: bool,
    request_pattern: Vec<u8>, // Hash del patrón de requests
}

impl IPProfile {
    fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            request_count: 0,
            last_request: Instant::now(),
            request_timestamps: VecDeque::with_capacity(BURST_WINDOW),
            suspicious_score: 0,
            is_whitelisted: false,
            is_blacklisted: false,
            request_pattern: Vec::new(),
        }
    }

    fn update_request(&mut self) -> bool {
        let now = Instant::now();
        self.request_count += 1;
        self.last_request = now;

        // Mantener ventana de tiempo
        self.request_timestamps.push_back(now);
        if self.request_timestamps.len() > BURST_WINDOW {
            self.request_timestamps.pop_front();
        }

        // Calcular si es burst (más de 100 reqs en 1 segundo)
        if self.request_timestamps.len() >= BURST_WINDOW {
            let first = self.request_timestamps.front().unwrap();
            let duration = now.duration_since(*first);
            if duration.as_secs() < 1 && self.request_timestamps.len() >= BURST_WINDOW {
                self.suspicious_score = self.suspicious_score.saturating_add(10);
                return true; // Posible ataque
            }
        }

        false
    }
}

#[derive(Clone, Copy, Debug)]
struct AttackPattern {
    signature: u64,
    severity: u8,
    pattern_type: AttackType,
    detection_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum AttackType {
    SlowLoris,
    HTTPFlood,
    SYNFlood,
    POSTFlood,
    XSS,
    SQLi,
    DirectoryTraversal,
    Custom,
}

// ==================== KERNEL ANTI-DDoS PRINCIPAL ====================

#[wasm_bindgen]
pub struct DDoSShield {
    ip_profiles: Arc<Mutex<HashMap<IpAddr, IPProfile>>>,
    blacklist: Arc<Mutex<lru::LruCache<IpAddr, Instant>>>,
    whitelist: Arc<Mutex<Vec<IpAddr>>>,
    attack_patterns: Arc<Mutex<Vec<AttackPattern>>>,
    request_buffer: SharedBuffer,
    stats: Rc<ShieldStats>,
    simd: SimdProcessor,
    rules: Arc<Mutex<FilterRules>>,
    geoip_enabled: Cell<bool>,
    learning_mode: Cell<bool>,
}

#[wasm_bindgen]
impl DDoSShield {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console::log_1(&"🛡️ DDoSShield Kernel Iniciado".into());

        let ip_profiles = Arc::new(Mutex::new(HashMap::new()));
        let blacklist = Arc::new(Mutex::new(lru::LruCache::new(
            IP_BLACKLIST_CAPACITY.try_into().unwrap(),
        )));
        let whitelist = Arc::new(Mutex::new(Vec::new()));
        let attack_patterns = Arc::new(Mutex::new(Vec::with_capacity(PATTERN_DB_SIZE)));
        let request_buffer = SharedBuffer::new(REQUEST_BUFFER_SIZE);
        let stats = Rc::new(ShieldStats::new());
        let simd = SimdProcessor::new();
        let rules = Arc::new(Mutex::new(FilterRules::default()));

        Self {
            ip_profiles,
            blacklist,
            whitelist,
            attack_patterns,
            request_buffer,
            stats,
            simd,
            rules,
            geoip_enabled: Cell::new(false),
            learning_mode: Cell::new(false),
        }
    }

    // ==================== API PRINCIPAL ====================

    #[wasm_bindgen(js_name = "analyzeRequest")]
    pub async fn analyze_request(
        &self,
        ip: String,
        method: String,
        path: String,
        headers: JsValue,
        body: Option<Uint8Array>,
    ) -> JsValue {
        let start_time = Instant::now();

        // Parsear IP
        let ip_addr: IpAddr = ip.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap());

        // Verificar blacklist
        if self.check_blacklist(&ip_addr).await {
            self.stats
                .blocked_requests
                .set(self.stats.blocked_requests.get() + 1);
            return self.create_response(true, "BLACKLISTED", 0, start_time);
        }

        // Verificar whitelist
        if self.check_whitelist(&ip_addr).await {
            return self.create_response(false, "WHITELISTED", 100, start_time);
        }

        // Analizar IP
        let mut profile = self.get_or_create_profile(&ip_addr).await;

        // Actualizar contador de requests
        let is_burst = profile.update_request();

        // Analizar patrones de ataque
        let mut threat_score = 0u8;
        let mut attack_detected = None;

        // Detectar Slow Loris
        if self.detect_slowloris(&headers, &profile).await {
            threat_score = threat_score.saturating_add(30);
            attack_detected = Some(AttackType::SlowLoris);
        }

        // Detectar HTTP Flood
        if is_burst {
            threat_score = threat_score.saturating_add(25);
            if attack_detected.is_none() {
                attack_detected = Some(AttackType::HTTPFlood);
            }
        }

        // Analizar cuerpo del request
        if let Some(body_data) = body {
            let mut buffer = vec![0u8; body_data.length() as usize];
            body_data.copy_to(&mut buffer);

            let body_threat = self.analyze_body(&buffer, &path, &method).await;
            threat_score = threat_score.saturating_add(body_threat.score);

            if body_threat.attack_type.is_some() && attack_detected.is_none() {
                attack_detected = body_threat.attack_type;
            }
        }

        // Verificar rate limiting
        let rate_limit_result = self.check_rate_limit(&profile).await;
        if rate_limit_result.blocked {
            threat_score = 100;
        }

        // Actualizar perfil
        profile.suspicious_score = profile.suspicious_score.saturating_add(threat_score);

        if threat_score > 70 {
            profile.is_blacklisted = true;
            self.add_to_blacklist(ip_addr).await;
            attack_detected = attack_detected.or(Some(AttackType::Custom));
        }

        // Guardar perfil actualizado
        self.ip_profiles.lock().await.insert(ip_addr, profile);

        // Actualizar estadísticas
        self.stats
            .total_requests
            .set(self.stats.total_requests.get() + 1);
        if threat_score > 0 {
            self.stats
                .threats_detected
                .set(self.stats.threats_detected.get() + 1);
        }

        // Crear respuesta
        self.create_response(
            threat_score > 70 || rate_limit_result.blocked,
            if attack_detected.is_some() {
                "THREAT_DETECTED"
            } else {
                "CLEAN"
            },
            threat_score,
            start_time,
        )
    }

    #[wasm_bindgen(js_name = "analyzeBatch")]
    pub async fn analyze_batch(&self, requests: Array) -> Array {
        let results = Array::new();

        for i in 0..requests.length() {
            if let Ok(request_obj) = requests.get(i).dyn_into::<Object>() {
                let ip = Reflect::get(&request_obj, &"ip".into())
                    .unwrap_or(JsValue::from_str("0.0.0.0"))
                    .as_string()
                    .unwrap_or_default();

                let method = Reflect::get(&request_obj, &"method".into())
                    .unwrap_or(JsValue::from_str("GET"))
                    .as_string()
                    .unwrap_or_default();

                let path = Reflect::get(&request_obj, &"path".into())
                    .unwrap_or(JsValue::from_str("/"))
                    .as_string()
                    .unwrap_or_default();

                let headers =
                    Reflect::get(&request_obj, &"headers".into()).unwrap_or(JsValue::NULL);

                let body = Reflect::get(&request_obj, &"body".into())
                    .ok()
                    .and_then(|v| v.dyn_into::<Uint8Array>().ok());

                let result = self.analyze_request(ip, method, path, headers, body).await;
                results.push(&result);
            }
        }

        results
    }

    // ==================== GESTIÓN DE LISTAS ====================

    #[wasm_bindgen(js_name = "addToBlacklist")]
    pub async fn add_to_blacklist(&self, ip: String) -> bool {
        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
            let mut blacklist = self.blacklist.lock().await;
            blacklist.put(ip_addr, Instant::now());

            // También marcar en el perfil
            if let Some(mut profile) = self.ip_profiles.lock().await.get_mut(&ip_addr) {
                profile.is_blacklisted = true;
            }

            true
        } else {
            false
        }
    }

    #[wasm_bindgen(js_name = "addToWhitelist")]
    pub async fn add_to_whitelist(&self, ip: String) -> bool {
        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
            let mut whitelist = self.whitelist.lock().await;
            whitelist.push(ip_addr);

            // Actualizar perfil
            if let Some(mut profile) = self.ip_profiles.lock().await.get_mut(&ip_addr) {
                profile.is_whitelisted = true;
                profile.is_blacklisted = false;
            }

            true
        } else {
            false
        }
    }

    #[wasm_bindgen(js_name = "clearBlacklist")]
    pub async fn clear_blacklist(&self) {
        let mut blacklist = self.blacklist.lock().await;
        blacklist.clear();
    }

    // ==================== CONFIGURACIÓN ====================

    #[wasm_bindgen(js_name = "setRateLimit")]
    pub async fn set_rate_limit(&self, requests_per_second: u32, burst_size: u32) {
        let mut rules = self.rules.lock().await;
        rules.rate_limit_rps = requests_per_second;
        rules.burst_size = burst_size;
    }

    #[wasm_bindgen(js_name = "enableGeoIP")]
    pub fn enable_geoip(&self, enable: bool) {
        self.geoip_enabled.set(enable);
    }

    #[wasm_bindgen(js_name = "enableLearning")]
    pub fn enable_learning(&self, enable: bool) {
        self.learning_mode.set(enable);
    }

    #[wasm_bindgen(js_name = "addCustomRule")]
    pub async fn add_custom_rule(&self, pattern: String, attack_type: String, severity: u8) {
        let mut rules = self.rules.lock().await;

        let pattern_bytes = pattern.as_bytes();
        let signature = self.simd.fast_hash(pattern_bytes) as u64;

        let attack_type_enum = match attack_type.as_str() {
            "SQLi" => AttackType::SQLi,
            "XSS" => AttackType::XSS,
            "DirectoryTraversal" => AttackType::DirectoryTraversal,
            "SlowLoris" => AttackType::SlowLoris,
            "HTTPFlood" => AttackType::HTTPFlood,
            _ => AttackType::Custom,
        };

        rules.custom_patterns.push(AttackPattern {
            signature,
            severity,
            pattern_type: attack_type_enum,
            detection_count: 0,
        });
    }

    // ==================== ESTADÍSTICAS ====================

    #[wasm_bindgen(js_name = "getStats")]
    pub fn get_stats(&self) -> JsValue {
        self.stats.as_js_value()
    }

    #[wasm_bindgen(js_name = "getTopAttackers")]
    pub async fn get_top_attackers(&self, limit: usize) -> Array {
        let profiles = self.ip_profiles.lock().await;
        let mut sorted_profiles: Vec<(&IpAddr, &IPProfile)> = profiles
            .iter()
            .filter(|(_, p)| p.suspicious_score > 50)
            .collect();

        sorted_profiles.sort_by(|a, b| b.1.suspicious_score.cmp(&a.1.suspicious_score));

        let result = Array::new();
        for (ip, profile) in sorted_profiles.iter().take(limit) {
            let obj = Object::new();
            Reflect::set(&obj, &"ip".into(), &ip.to_string().into()).unwrap();
            Reflect::set(&obj, &"score".into(), &profile.suspicious_score.into()).unwrap();
            Reflect::set(&obj, &"requests".into(), &profile.request_count.into()).unwrap();
            Reflect::set(&obj, &"blacklisted".into(), &profile.is_blacklisted.into()).unwrap();
            result.push(&obj);
        }

        result
    }
}

// ==================== IMPLEMENTACIONES INTERNAS ====================

impl DDoSShield {
    async fn check_blacklist(&self, ip: &IpAddr) -> bool {
        let blacklist = self.blacklist.lock().await;
        blacklist.contains(ip)
    }

    async fn check_whitelist(&self, ip: &IpAddr) -> bool {
        let whitelist = self.whitelist.lock().await;
        whitelist.contains(ip)
    }

    async fn get_or_create_profile(&self, ip: &IpAddr) -> IPProfile {
        let mut profiles = self.ip_profiles.lock().await;
        profiles
            .entry(*ip)
            .or_insert_with(|| IPProfile::new(*ip))
            .clone()
    }

    async fn detect_slowloris(&self, headers: &JsValue, profile: &IPProfile) -> bool {
        // Detectar conexiones con muchos headers o keep-alive anormal
        let headers_str = headers.as_string().unwrap_or_default();

        // Contar headers
        let header_count = headers_str.matches("\r\n").count();

        // Detectar si hay muchos headers (posible Slow Loris)
        if header_count > 100 {
            return true;
        }

        // Verificar User-Agent anómalo o vacío
        if !headers_str.contains("User-Agent:")
            || headers_str.contains("User-Agent: \r\n")
            || headers_str.contains("User-Agent: Mozilla/4.0")
        {
            return true;
        }

        false
    }

    async fn analyze_body(&self, body: &[u8], path: &str, method: &str) -> ThreatAnalysis {
        let mut score = 0u8;
        let mut attack_type = None;

        // Convertir a lowercase para análisis
        let body_lower = String::from_utf8_lossy(body).to_lowercase();

        // Detectar SQL Injection
        let sql_patterns = [
            "select",
            "union",
            "insert",
            "delete",
            "drop",
            "or '1'='1",
            "' or ",
            "--",
            "#",
            "/*",
            "*/",
        ];
        for pattern in &sql_patterns {
            if body_lower.contains(pattern) && !self.is_learning_mode() {
                score = score.saturating_add(40);
                attack_type = Some(AttackType::SQLi);
                break;
            }
        }

        // Detectar XSS
        let xss_patterns = [
            "<script>",
            "javascript:",
            "onload=",
            "onerror=",
            "alert(",
            "document.cookie",
            "eval(",
        ];
        for pattern in &xss_patterns {
            if body_lower.contains(pattern) && !self.is_learning_mode() {
                score = score.saturating_add(35);
                attack_type = Some(AttackType::XSS);
                break;
            }
        }

        // Detectar Directory Traversal
        let traversal_patterns = [
            "../",
            "..\\",
            "/etc/passwd",
            "c:\\windows",
            "/bin/sh",
            "~/.ssh",
        ];
        for pattern in &traversal_patterns {
            if body_lower.contains(pattern) || path.contains(pattern) {
                score = score.saturating_add(30);
                attack_type = Some(AttackType::DirectoryTraversal);
                break;
            }
        }

        // POST Flood en rutas específicas
        if method == "POST" {
            let sensitive_paths = ["/login", "/api/auth", "/wp-admin", "/admin"];
            if sensitive_paths.iter().any(|p| path.contains(p)) {
                score = score.saturating_add(20);
                if attack_type.is_none() {
                    attack_type = Some(AttackType::POSTFlood);
                }
            }
        }

        // Análisis con SIMD para patrones binarios
        let simd_score = self.simd.analyze_binary_patterns(body);
        score = score.saturating_add(simd_score);

        ThreatAnalysis { score, attack_type }
    }

    async fn check_rate_limit(&self, profile: &IPProfile) -> RateLimitResult {
        let rules = self.rules.lock().await;

        // Verificar si excede rate limit global
        if profile.request_count > rules.rate_limit_rps {
            return RateLimitResult {
                blocked: true,
                remaining: 0,
                reset_in: 60, // segundos
            };
        }

        // Verificar burst
        if profile.request_timestamps.len() >= rules.burst_size as usize {
            return RateLimitResult {
                blocked: true,
                remaining: 0,
                reset_in: 10,
            };
        }

        RateLimitResult {
            blocked: false,
            remaining: rules.rate_limit_rps.saturating_sub(profile.request_count),
            reset_in: 1,
        }
    }

    fn create_response(
        &self,
        blocked: bool,
        status: &str,
        threat_score: u8,
        start_time: Instant,
    ) -> JsValue {
        let obj = Object::new();

        Reflect::set(&obj, &"blocked".into(), &blocked.into()).unwrap();
        Reflect::set(&obj, &"status".into(), &status.into()).unwrap();
        Reflect::set(&obj, &"threatScore".into(), &threat_score.into()).unwrap();
        Reflect::set(
            &obj,
            &"processingTimeMs".into(),
            &start_time.elapsed().as_micros().into(),
        )
        .unwrap();
        Reflect::set(&obj, &"timestamp".into(), &Date::now().into()).unwrap();

        obj.into()
    }

    fn is_learning_mode(&self) -> bool {
        self.learning_mode.get()
    }
}

// ==================== STRUCTURAS AUXILIARES ====================

struct ThreatAnalysis {
    score: u8,
    attack_type: Option<AttackType>,
}

struct RateLimitResult {
    blocked: bool,
    remaining: u32,
    reset_in: u64, // segundos
}

#[derive(Default)]
struct FilterRules {
    rate_limit_rps: u32,
    burst_size: u32,
    custom_patterns: Vec<AttackPattern>,
    geoip_blocklist: Vec<String>, // Códigos de país
}

struct ShieldStats {
    total_requests: Cell<u64>,
    blocked_requests: Cell<u64>,
    threats_detected: Cell<u64>,
    start_time: Instant,
    request_rate: Cell<f64>,
}

impl ShieldStats {
    fn new() -> Self {
        Self {
            total_requests: Cell::new(0),
            blocked_requests: Cell::new(0),
            threats_detected: Cell::new(0),
            start_time: Instant::now(),
            request_rate: Cell::new(0.0),
        }
    }

    fn as_js_value(&self) -> JsValue {
        let uptime = self.start_time.elapsed();
        let total = self.total_requests.get();
        let blocked = self.blocked_requests.get();
        let threats = self.threats_detected.get();

        let obj = Object::new();

        Reflect::set(&obj, &"totalRequests".into(), &total.into()).unwrap();
        Reflect::set(&obj, &"blockedRequests".into(), &blocked.into()).unwrap();
        Reflect::set(&obj, &"threatsDetected".into(), &threats.into()).unwrap();
        Reflect::set(&obj, &"uptimeSeconds".into(), &uptime.as_secs().into()).unwrap();
        Reflect::set(
            &obj,
            &"requestRate".into(),
            &(if uptime.as_secs() > 0 {
                total as f64 / uptime.as_secs() as f64
            } else {
                0.0
            })
            .into(),
        )
        .unwrap();
        Reflect::set(
            &obj,
            &"blockPercentage".into(),
            &(if total > 0 {
                (blocked as f64 / total as f64) * 100.0
            } else {
                0.0
            })
            .into(),
        )
        .unwrap();

        obj.into()
    }
}

// ==================== INTEGRACIÓN NGINX/GATEWAY ====================

#[wasm_bindgen]
pub struct GatewayIntegration {
    shield: DDoSShield,
    upstream_url: String,
    failover_url: String,
    circuit_breaker: CircuitBreaker,
}

#[wasm_bindgen]
impl GatewayIntegration {
    #[wasm_bindgen(constructor)]
    pub fn new(upstream_url: String, failover_url: String) -> Self {
        Self {
            shield: DDoSShield::new(),
            upstream_url,
            failover_url,
            circuit_breaker: CircuitBreaker::new(),
        }
    }

    #[wasm_bindgen(js_name = "processHttpRequest")]
    pub async fn process_http_request(&self, request: JsValue) -> Promise {
        // Parsear request HTTP
        let ip = Self::extract_ip(&request);
        let method = Self::extract_method(&request);
        let path = Self::extract_path(&request);
        let headers = Self::extract_headers(&request);
        let body = Self::extract_body(&request);

        // Analizar con DDoS Shield
        let analysis = self
            .shield
            .analyze_request(ip, method, path, headers, body)
            .await;

        // Verificar si está bloqueado
        let is_blocked = Reflect::get(&analysis, &"blocked".into())
            .unwrap_or(JsValue::FALSE)
            .as_bool()
            .unwrap_or(false);

        if is_blocked {
            // Devolver respuesta de bloqueo
            return Promise::resolve(&Self::create_block_response().into());
        }

        // Si pasa el filtro, reenviar al upstream
        let upstream_promise = self.forward_to_upstream(request).await;

        upstream_promise
    }

    #[wasm_bindgen(js_name = "enableAutoMitigation")]
    pub async fn enable_auto_mitigation(&self, threshold: u8) {
        console::log_1(&format!("🚨 Auto-mitigación activada con umbral {}", threshold).into());

        // Programar limpieza periódica
        let shield_clone = self.shield.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await; // Cada 5 minutos
                shield_clone.clear_stale_entries().await;
            }
        });
    }
}

// ==================== SIMD OPTIMIZATIONS ====================

impl SimdProcessor {
    fn analyze_binary_patterns(&self, data: &[u8]) -> u8 {
        let mut score = 0u8;

        // Patrones de shellcode comunes
        let shellcode_patterns = [
            b"\x90\x90\x90\x90", // NOP sled
            b"\xCC\xCC\xCC\xCC", // INT3
            b"\xE8\x00\x00\x00", // CALL rel32
            b"\x68\x00\x00\x00", // PUSH dword
        ];

        // Buscar patrones con SIMD
        for pattern in &shellcode_patterns {
            if data.len() >= pattern.len() {
                let mut i = 0;
                while i + SIMD_WIDTH <= data.len() {
                    let chunk = Simd::from_slice(&data[i..i + SIMD_WIDTH]);
                    let pattern_simd = Simd::splat(pattern[0]);

                    let mask = chunk.simd_eq(pattern_simd);
                    for j in 0..SIMD_WIDTH {
                        if mask.test(j) && i + j + pattern.len() <= data.len() {
                            if &data[i + j..i + j + pattern.len()] == *pattern {
                                score = score.saturating_add(50);
                                break;
                            }
                        }
                    }
                    i += SIMD_WIDTH;
                }
            }
        }

        score
    }
}

// ==================== CIRCUIT BREAKER ====================

struct CircuitBreaker {
    failure_count: Cell<u32>,
    last_failure: Cell<Option<Instant>>,
    state: Cell<BreakerState>,
    reset_timeout: Duration,
}

#[derive(Clone, Copy, PartialEq)]
enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failure_count: Cell::new(0),
            last_failure: Cell::new(None),
            state: Cell::new(BreakerState::Closed),
            reset_timeout: Duration::from_secs(30),
        }
    }

    fn allow_request(&self) -> bool {
        match self.state.get() {
            BreakerState::Closed => true,
            BreakerState::Open => {
                if let Some(last_fail) = self.last_failure.get() {
                    if last_fail.elapsed() > self.reset_timeout {
                        self.state.set(BreakerState::HalfOpen);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            BreakerState::HalfOpen => {
                // Permitir solo un request para probar
                self.state.set(BreakerState::Closed);
                true
            }
        }
    }

    fn record_failure(&self) {
        let failures = self.failure_count.get() + 1;
        self.failure_count.set(failures);
        self.last_failure.set(Some(Instant::now()));

        if failures >= 5 {
            self.state.set(BreakerState::Open);
        }
    }

    fn record_success(&self) {
        self.failure_count.set(0);
        self.state.set(BreakerState::Closed);
    }
}

// ==================== MIDDLEWARE PARA ACTIX/WARP ====================

/*
// Ejemplo para Actix Web:
async fn ddos_middleware(
    req: ServiceRequest,
    srv: &mut dyn Service<ServiceRequest, Response = ServiceResponse, Error = Error>,
    shield: Data<DDoSShield>,
) -> Result<ServiceResponse, Error> {

    let ip = req.connection_info().peer_addr().unwrap_or("").to_string();
    let method = req.method().to_string();
    let path = req.path().to_string();

    let analysis = shield.analyze_request(ip, method, path, JsValue::NULL, None).await;

    let blocked = analysis.blocked;

    if blocked {
        return Ok(req.into_response(
            HttpResponse::TooManyRequests()
                .body("Request bloqueado por protección DDoS")
        ));
    }

    srv.call(req).await
}
*/

// ==================== CARGO.TOML ====================
/*
[package]
name = "ddos-shield"
version = "1.0.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
wasm-bindgen = { version = "0.2", features = ["serde-serialize"] }
js-sys = "0.3"
web-sys = { version = "0.3", features = [
    "console",
    "Window",
    "RequestAnimationFrame"
] }
wasm-bindgen-futures = "0.4"
tokio = { version = "1.0", features = ["full"] }
bytes = "1.0"
lru = "0.11"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Para uso en servidor (opcional)
actix-web = { version = "4.0", optional = true }
warp = { version = "0.3", optional = true }

[features]
default = ["simd", "server"]
simd = ["portable-simd"]
server = ["actix-web", "warp"]

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = "symbols"
panic = "abort"
*/
