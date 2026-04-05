mod agent_keys;
mod backend;
mod backend_engram;
mod backend_sqlite;
mod crypto;
mod store;
mod types;
mod yubikey;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use tokio::sync::Mutex;
use tower_http::{cors::{Any, CorsLayer}, trace::TraceLayer};
use tracing::{error, info, warn};

use crate::agent_keys::{audit_log, AgentKeyStore};
use crate::store::CredStore;
use crate::types::*;

// ---------------------------------------------------------------------------
// Per-IP rate limiter
// ---------------------------------------------------------------------------

struct RateLimitEntry {
    failures: u32,
    last_failure: Option<std::time::Instant>,
}

struct AuthRateLimiter {
    entries: HashMap<IpAddr, RateLimitEntry>,
}

const MAX_FAILURES: u32 = 5;
const BASE_LOCKOUT_SECS: u64 = 30;
const MAX_LOCKOUT_SECS: u64 = 3600;
const MAX_TRACKED_IPS: usize = 10_000;

impl AuthRateLimiter {
    fn new() -> Self { Self { entries: HashMap::new() } }

    fn check_lockout(&self, ip: &IpAddr) -> Option<u64> {
        let entry = self.entries.get(ip)?;
        if entry.failures < MAX_FAILURES { return None; }
        let last = entry.last_failure?;
        let lockout = std::cmp::min(
            BASE_LOCKOUT_SECS * 2u64.saturating_pow(entry.failures - MAX_FAILURES),
            MAX_LOCKOUT_SECS,
        );
        let elapsed = last.elapsed().as_secs();
        if elapsed < lockout { Some(lockout - elapsed) } else { None }
    }

    fn record_failure(&mut self, ip: IpAddr) {
        if self.entries.len() >= MAX_TRACKED_IPS {
            // First pass: evict expired entries
            self.entries.retain(|_, e| {
                e.last_failure.map_or(false, |t| t.elapsed().as_secs() < MAX_LOCKOUT_SECS)
            });
            // If still at capacity, evict the oldest entry
            if self.entries.len() >= MAX_TRACKED_IPS {
                if let Some(oldest_ip) = self.entries.iter()
                    .min_by_key(|(_, e)| e.last_failure)
                    .map(|(ip, _)| *ip)
                {
                    self.entries.remove(&oldest_ip);
                }
            }
        }
        let entry = self.entries.entry(ip).or_insert(RateLimitEntry {
            failures: 0,
            last_failure: None,
        });
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure = Some(std::time::Instant::now());
    }

    fn record_success(&mut self, ip: IpAddr) {
        self.entries.remove(&ip);
    }
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct AppState {
    store: Arc<CredStore>,
    owner_key: String,
    agent_keys: Mutex<AgentKeyStore>,
    rate_limiter: Mutex<AuthRateLimiter>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("credd=info".parse().unwrap())
                .add_directive("tower_http=debug".parse().unwrap()),
        )
        .with_target(false)
        .init();

    let owner_key = std::env::var("CRED_OWNER_KEY")
        .expect("FATAL: CRED_OWNER_KEY must be set (do not reuse ENGRAM_API_KEY)");

    let agent_keys = AgentKeyStore::load().unwrap_or_else(|e| {
        warn!("failed to load agent keys: {}, starting fresh", e);
        AgentKeyStore::load().unwrap_or_else(|_| {
            // If load fails twice, construct a minimal empty store via load_from a nonexistent path
            AgentKeyStore::load_from(std::path::PathBuf::from("/dev/null/nonexistent"))
                .unwrap_or_else(|_| panic!("unable to initialize agent key store"))
        })
    });

    info!("deriving master key from YubiKey...");
    let master_key = yubikey::derive_master_key()
        .context("failed to derive key from YubiKey")?;
    info!("master key derived, store unlocked");

    let store = Arc::new(CredStore::new(master_key)?);

    let state = Arc::new(AppState {
        store,
        owner_key,
        agent_keys: Mutex::new(agent_keys),
        rate_limiter: Mutex::new(AuthRateLimiter::new()),
    });

    let app = Router::new()
        .route("/health", get(health))
        // Secret CRUD
        .route("/secret", post(store_secret))
        .route("/secret/{service}/{key}", get(get_secret))
        .route("/secret/{service}/{key}", delete(delete_secret))
        .route("/secrets", get(list_secrets))
        // Agent key management (owner-only)
        .route("/agent-keys", post(create_agent_key))
        .route("/agent-keys", get(list_agent_keys))
        .route("/agent-keys/{agent_id}", delete(revoke_agent_key))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any));

    let bind_addr = std::env::var("CREDD_BIND").unwrap_or_else(|_| "0.0.0.0:4400".to_string());
    let addr: SocketAddr = bind_addr.parse().expect("invalid CREDD_BIND");
    info!("credd listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await.context("server error")
}

// ---------------------------------------------------------------------------
// Auth (unchanged logic, same two-tier system)
// ---------------------------------------------------------------------------

async fn authenticate(
    headers: &HeaderMap,
    state: &AppState,
    client_ip: IpAddr,
) -> Result<AuthLevel, (StatusCode, Json<ApiError>)> {
    {
        let limiter = state.rate_limiter.lock().await;
        if let Some(remaining) = limiter.check_lockout(&client_ip) {
            return Err((StatusCode::TOO_MANY_REQUESTS, Json(ApiError {
                error: format!("rate limited, retry in {}s", remaining),
            })));
        }
    }

    let auth = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")).unwrap_or(auth);

    if token.is_empty() {
        state.rate_limiter.lock().await.record_failure(client_ip);
        return Err((StatusCode::UNAUTHORIZED, Json(ApiError { error: "missing authorization".to_string() })));
    }

    if constant_time_eq(token.as_bytes(), state.owner_key.as_bytes()) {
        state.rate_limiter.lock().await.record_success(client_ip);
        return Ok(AuthLevel::Owner);
    }

    {
        let mut agent_keys = state.agent_keys.lock().await;
        if let Some(agent_id) = agent_keys.validate(token) {
            agent_keys.touch(&agent_id);
            state.rate_limiter.lock().await.record_success(client_ip);
            return Ok(AuthLevel::Agent(agent_id));
        }
    }

    state.rate_limiter.lock().await.record_failure(client_ip);
    Err((StatusCode::UNAUTHORIZED, Json(ApiError { error: "invalid key".to_string() })))
}

fn require_owner(auth: &AuthLevel) -> Result<(), (StatusCode, Json<ApiError>)> {
    match auth {
        AuthLevel::Owner => Ok(()),
        AuthLevel::Agent(id) => {
            warn!("agent '{}' attempted owner-only operation", id);
            audit_log(id, "denied", "attempted owner-only endpoint");
            Err((StatusCode::FORBIDDEN, Json(ApiError { error: "owner access required".to_string() })))
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok", "service": "credd"}))
}

#[derive(Deserialize)]
struct TierQuery {
    tier: Option<String>,
}

#[derive(Deserialize)]
struct ServiceFilter {
    service: Option<String>,
}

async fn store_secret(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<StoreSecretRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let auth = authenticate(&headers, &state, addr.ip()).await?;
    require_owner(&auth)?;

    if let Err(msg) = crate::types::validate_name(&req.service, "service") {
        return Err((StatusCode::BAD_REQUEST, Json(ApiError { error: msg })));
    }
    if let Err(msg) = crate::types::validate_name(&req.key, "key") {
        return Err((StatusCode::BAD_REQUEST, Json(ApiError { error: msg })));
    }

    let secret = Secret::new(&req.service, &req.key, req.value);
    let id = state.store.store(&secret).await.map_err(|e| {
        error!("store error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: e.to_string() }))
    })?;

    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "stored": true, "service": req.service, "key": req.key, "engram_id": id
    }))))
}

async fn get_secret(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Path((service, key)): Path<(String, String)>,
    Query(query): Query<TierQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let auth = authenticate(&headers, &state, addr.ip()).await?;

    if let Err(msg) = crate::types::validate_name(&service, "service") {
        return Err((StatusCode::BAD_REQUEST, Json(ApiError { error: msg })));
    }
    if let Err(msg) = crate::types::validate_name(&key, "key") {
        return Err((StatusCode::BAD_REQUEST, Json(ApiError { error: msg })));
    }

    let tier = query.tier.unwrap_or_else(|| "tier1".to_string());

    match &auth {
        AuthLevel::Agent(id) => audit_log(id, "get_secret", &format!("service={} key={} tier={}", service, key, tier)),
        AuthLevel::Owner => audit_log("owner", "get_secret", &format!("service={} key={} tier={}", service, key, tier)),
    }

    let secret = state.store.get(&service, &key).await.map_err(|_| {
        (StatusCode::NOT_FOUND, Json(ApiError { error: format!("secret not found: {}/{}", service, key) }))
    })?;

    match &auth {
        AuthLevel::Owner => {
            Ok(Json(serde_json::to_value(SecretResponse {
                service: secret.service,
                key: secret.key,
                secret_type: secret.value.type_name().to_string(),
                value: secret.value,
            }).unwrap()))
        }
        AuthLevel::Agent(agent_id) => {
            let has_scope = state.agent_keys.lock().await.has_scope(agent_id, &service, &key);
            if has_scope {
                audit_log(agent_id, "get_secret_plaintext", &format!("service={} key={} (scoped)", service, key));
                Ok(Json(serde_json::to_value(AgentSecretResponse {
                    service: secret.service,
                    key: secret.key,
                    secret_type: secret.value.type_name().to_string(),
                    field_names: secret.value.field_names(),
                    value: Some(secret.value),
                    hint: None,
                }).unwrap()))
            } else {
                audit_log(agent_id, "get_secret_metadata", &format!("service={} key={} (no scope)", service, key));
                Ok(Json(serde_json::to_value(AgentSecretResponse {
                    service: secret.service,
                    key: secret.key,
                    secret_type: secret.value.type_name().to_string(),
                    field_names: secret.value.field_names(),
                    value: None,
                    hint: Some("agent does not have scope for this secret -- request owner to add scope".to_string()),
                }).unwrap()))
            }
        }
    }
}

async fn delete_secret(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Path((service, key)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let auth = authenticate(&headers, &state, addr.ip()).await?;
    require_owner(&auth)?;

    if let Err(msg) = crate::types::validate_name(&service, "service") {
        return Err((StatusCode::BAD_REQUEST, Json(ApiError { error: msg })));
    }
    if let Err(msg) = crate::types::validate_name(&key, "key") {
        return Err((StatusCode::BAD_REQUEST, Json(ApiError { error: msg })));
    }

    state.store.delete(&service, &key).await.map_err(|_| {
        (StatusCode::NOT_FOUND, Json(ApiError { error: format!("secret not found: {}/{}", service, key) }))
    })?;

    Ok(StatusCode::NO_CONTENT)
}

async fn list_secrets(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Query(filter): Query<ServiceFilter>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let auth = authenticate(&headers, &state, addr.ip()).await?;

    let all = state.store.list_all().await.map_err(|e| {
        error!("list error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: e.to_string() }))
    })?;

    let items: Vec<SecretListItem> = all.into_iter()
        .filter(|s| filter.service.as_deref().map_or(true, |f| s.service == f))
        .map(|s| {
            let preview = match &auth {
                AuthLevel::Owner => s.value.redacted_preview(),
                AuthLevel::Agent(_) => s.value.type_name().to_string(),
            };
            SecretListItem {
                service: s.service,
                key: s.key,
                secret_type: s.value.type_name().to_string(),
                field_names: s.value.field_names(),
                redacted_preview: preview,
                engram_id: s.engram_id,
            }
        })
        .collect();

    Ok(Json(items))
}

// Agent key management handlers (owner-only, identical logic to before)

async fn create_agent_key(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<AgentKeyCreateRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let auth = authenticate(&headers, &state, addr.ip()).await?;
    require_owner(&auth)?;

    let mut agent_keys = state.agent_keys.lock().await;
    let key = agent_keys.generate(&req.agent_id, &req.description, req.scopes.clone()).map_err(|e| {
        (StatusCode::CONFLICT, Json(ApiError { error: e.to_string() }))
    })?;

    audit_log("owner", "agent_key_create", &format!("agent_id={}", req.agent_id));

    Ok((StatusCode::CREATED, Json(AgentKeyCreateResponse {
        agent_id: req.agent_id, key, created_at: chrono::Utc::now().to_rfc3339(),
    })))
}

async fn list_agent_keys(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let auth = authenticate(&headers, &state, addr.ip()).await?;
    require_owner(&auth)?;

    let agent_keys = state.agent_keys.lock().await;
    let items: Vec<AgentKeyListItem> = agent_keys.list().iter().map(|k| AgentKeyListItem {
        id: k.id.clone(),
        created_at: k.created_at.to_rfc3339(),
        last_used: k.last_used.map(|t| t.to_rfc3339()),
        revoked: k.revoked,
        description: k.description.clone(),
        key_prefix: format!("{}...", &k.key[..8.min(k.key.len())]),
        scopes: k.scopes.clone(),
    }).collect();

    Ok(Json(items))
}

async fn revoke_agent_key(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let auth = authenticate(&headers, &state, addr.ip()).await?;
    require_owner(&auth)?;

    let mut agent_keys = state.agent_keys.lock().await;
    agent_keys.revoke(&agent_id).map_err(|e| {
        (StatusCode::NOT_FOUND, Json(ApiError { error: e.to_string() }))
    })?;

    audit_log("owner", "agent_key_revoke", &format!("agent_id={}", agent_id));
    Ok(Json(serde_json::json!({"revoked": true, "agent_id": agent_id})))
}
