//! sworn-api — HTTP server for the SWORN reference implementation.
//!
//! Endpoints (v0.1):
//!   POST   /attestations                              create + verify + store
//!   GET    /attestations/:id                          metadata only, no payload
//!   POST   /attestations/:id/disclosure-tokens        signer mints a redemption token
//!   POST   /attestations/:id/disclose                 redeem a token, receive payload
//!   GET    /verify/:id                                re-verify a stored attestation
//!   GET    /healthz                                   liveness
//!
//! Deliberately refused (return 400 with a message):
//!   GET    /attestations           bulk enumeration
//!   GET    /attestations?signer=X  list by signer
//!   GET    /attestations?subject=X list by subject
//!
//! Rate limits (in-memory, per-IP token bucket):
//!   default: 60 req/min
//!   POST /attestations/:id/disclose: 6 req/min (tighter cap to slow enumeration)

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use sworn_verify::{verify, AttestationFields};
use tracing::info;
use uuid::Uuid;

// ─── App state ──────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    pool: Arc<PgPool>,
    rate_limiter: Arc<RateLimiter>,
}

// ─── Wire types ─────────────────────────────────────────────────────
//
// All 32-byte and 64-byte binary fields are base64 (standard alphabet,
// with padding). String choice per SCOPE.md; documented in OpenAPI.

#[derive(Debug, Deserialize)]
struct CreateAttestationRequest {
    /// 32 bytes, base64.
    signer_pubkey: String,
    /// 32 bytes, base64. Application-defined subject identifier.
    subject: String,
    /// Absolute URI naming the activity type (SPEC §2.2).
    activity_type_uri: String,
    /// 32 bytes, base64. Optional; omit or send "" for none.
    #[serde(default)]
    witness_for: Option<String>,

    /// v0.1-final provenance (SPEC §2.5). All required.
    ///
    /// 32 bytes, base64. MUST be all-zero when source_type is Unknown (0)
    /// or SelfReported (1); otherwise SHA-256 of canonical source identifier
    /// per SPEC §9.2.
    source_hash: String,
    /// Registered value from SPEC §9.2. 0-14 currently defined.
    source_type: u16,
    /// Signer's confidence in basis points, 0-10000. Snapshot at signing time.
    confidence: u16,
    /// Registered value from SPEC §9.3. 0-5 currently defined.
    witnessing_depth: u8,
    /// Registered value from SPEC §9.4. 0-6 currently defined.
    attestor_relationship: u8,

    /// Signer-asserted timestamp (int64, unix seconds). Informational only
    /// per SPEC §2.5.1; verifiers MUST NOT use for trust decisions.
    signer_asserted_at: i64,
    /// Retention hint (int64, seconds; -1 = permanent).
    retention_hint: i64,
    /// 32 bytes, base64.
    nonce: String,
    /// 64 bytes, base64. Ed25519 over the 248-byte v0.1-final canonical bytes.
    signature: String,
    /// The full JSON payload. `SHA-256(RFC-8785(payload))` MUST equal the
    /// data_hash inside the canonical bytes that `signature` covers.
    payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct CreateAttestationResponse {
    id: Uuid,
    notarized_at: i64,
    /// Echoed back so callers can confirm what was stored.
    data_hash: String,
    activity_hash: String,
    spec_version: i16,
}

#[derive(Debug, Serialize)]
struct AttestationView {
    id: Uuid,
    spec_version: i16,
    signer_pubkey: String,
    subject: String,
    activity_type_uri: String,
    activity_hash: String,
    data_hash: String,
    /// Base64. Zero-bytes when no witness endorsement.
    witness_for: String,
    /// Base64. Zero-bytes when source_type is Unknown or SelfReported.
    source_hash: String,
    source_type: u16,
    confidence: u16,
    witnessing_depth: u8,
    attestor_relationship: u8,
    /// 'original' or 'backfilled'. See IMPLEMENTATION_NOTES.md.
    provenance_origin: String,
    signer_asserted_at: i64,
    notarized_at: i64,
    retention_hint: i64,
    nonce: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    valid: bool,
    reason: &'static str,
    attestation_id: Uuid,
}

/// Client body for POST /attestations/:id/disclosure-tokens.
///
/// The signer proves control by signing the tuple
///   b"sworn-disclosure-token-v1" || attestation_id_bytes(16)
///                                 || expires_in_secs.to_le_bytes()(8)
///                                 || issuance_nonce(32)
/// with the same private key that produced the attestation's signature.
#[derive(Debug, Deserialize)]
struct CreateTokenRequest {
    /// How long (seconds) the minted token should remain valid. Server caps at 7 days.
    expires_in_secs: i64,
    /// 32 bytes, base64. Fresh per issuance; also serves as replay guard.
    issuance_nonce: String,
    /// 64 bytes, base64. Ed25519 signature over the tuple above by the attestation's signer.
    signature: String,
}

#[derive(Debug, Serialize)]
struct CreateTokenResponse {
    token: Uuid,
    expires_at: i64,
    attestation_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct DiscloseRequest {
    token: Uuid,
}

#[derive(Debug, Serialize)]
struct DiscloseResponse {
    attestation_id: Uuid,
    payload: serde_json::Value,
    /// Server-computed on the fly so caller can re-verify without a second call.
    data_hash: String,
    /// Echoed so caller can cross-check against a previously fetched metadata view.
    signer_pubkey: String,
    signer_asserted_at: i64,
    notarized_at: i64,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    existing_id: Option<Uuid>,
}

// ─── Error type + IntoResponse ─────────────────────────────────────

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("duplicate; existing id {0}")]
    Duplicate(Uuid),
    #[error("not found")]
    NotFound,
    #[error("gone: {0}")]
    Gone(&'static str),
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    #[error("rate limited")]
    RateLimited,
    #[error("refused: {0}")]
    Refused(&'static str),
    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ApiError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorBody { error: "bad_request", message: msg.clone(), existing_id: None },
            ),
            ApiError::Duplicate(id) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "duplicate",
                    message: "This exact attestation already exists.".into(),
                    existing_id: Some(*id),
                },
            ),
            ApiError::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody { error: "not_found", message: "not found".into(), existing_id: None },
            ),
            ApiError::Gone(reason) => (
                StatusCode::GONE,
                ErrorBody { error: "gone", message: reason.to_string(), existing_id: None },
            ),
            ApiError::Unauthorized(reason) => (
                StatusCode::UNAUTHORIZED,
                ErrorBody { error: "unauthorized", message: reason.to_string(), existing_id: None },
            ),
            ApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorBody {
                    error: "rate_limited",
                    message: "Too many requests. Slow down and try again.".into(),
                    existing_id: None,
                },
            ),
            ApiError::Refused(reason) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "refused",
                    message: format!(
                        "This operation is refused by the SWORN reference implementation: {}. See the spec's shown-never-pulled discipline.",
                        reason
                    ),
                    existing_id: None,
                },
            ),
            ApiError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody { error: "internal", message: msg.clone(), existing_id: None },
            ),
        };
        (status, Json(body)).into_response()
    }
}

// ─── Rate limiter (in-memory token bucket, per IP + route class) ────
//
// Two classes: default (60 req/min) and disclose (6 req/min). The disclose
// bucket is tighter because /disclose returns payload bytes and is the one
// endpoint a hostile enumerator would hammer if they got a leaked token.
// In-memory is fine for a reference implementation; production deploys
// front this with a real limiter (nginx, envoy, cloud rate limiting).

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Bucket {
    Default,
    Disclose,
}

struct Bucketed {
    tokens: f64,
    last_refill: Instant,
}

struct RateLimiter {
    per_ip: Mutex<HashMap<(IpAddr, Bucket), Bucketed>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self { per_ip: Mutex::new(HashMap::new()) }
    }

    /// Consume 1 token; return false if the bucket is empty.
    fn allow(&self, ip: IpAddr, bucket: Bucket) -> bool {
        let (capacity, refill_per_sec) = match bucket {
            Bucket::Default => (60.0, 1.0),   // 60 tokens, +1/sec => 60/min sustained
            Bucket::Disclose => (6.0, 0.1),   // 6 tokens, +6/min sustained
        };

        let mut map = self.per_ip.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        let entry = map.entry((ip, bucket)).or_insert(Bucketed { tokens: capacity, last_refill: now });

        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * refill_per_sec).min(capacity);
        entry.last_refill = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();
    let bucket = if path.ends_with("/disclose") { Bucket::Disclose } else { Bucket::Default };

    // Client IP: use the connecting peer. Behind a proxy, the operator should
    // configure X-Forwarded-For handling at that layer; we don't parse it here
    // because misparsing can be worse than not parsing.
    let ip = addr.ip();

    if !state.rate_limiter.allow(ip, bucket) {
        return ApiError::RateLimited.into_response();
    }
    next.run(req).await
}

// ─── Handlers ──────────────────────────────────────────────────────

async fn healthz() -> &'static str {
    "ok"
}

async fn create_attestation(
    State(state): State<AppState>,
    Json(req): Json<CreateAttestationRequest>,
) -> Result<(StatusCode, Json<CreateAttestationResponse>), ApiError> {
    // Decode + width-check every binary field.
    let signer_pubkey = b64_32(&req.signer_pubkey, "signer_pubkey")?;
    let subject = b64_32(&req.subject, "subject")?;
    let nonce = b64_32(&req.nonce, "nonce")?;
    let signature = b64_64(&req.signature, "signature")?;
    let witness_for = match req.witness_for.as_deref() {
        None | Some("") => [0u8; 32],
        Some(s) => b64_32(s, "witness_for")?,
    };

    // Compute activity_hash and data_hash from provided inputs.
    // activity_hash = SHA-256(activity_type_uri as UTF-8 bytes).
    let activity_hash: [u8; 32] = Sha256::digest(req.activity_type_uri.as_bytes()).into();

    // data_hash = SHA-256(RFC-8785 canonical JSON of payload).
    let canonical_payload = serde_jcs::to_vec(&req.payload)
        .map_err(|e| ApiError::BadRequest(format!("payload canonicalization failed: {}", e)))?;
    let data_hash: [u8; 32] = Sha256::digest(&canonical_payload).into();

    // Decode + validate the v0.1-final provenance enums per SPEC §2.5, §9.2-9.4.
    let source_hash = b64_32(&req.source_hash, "source_hash")?;

    let source_type = sworn_verify::SourceType::from_u16(req.source_type)
        .ok_or_else(|| ApiError::BadRequest(format!(
            "unknown source_type value {}; see SPEC §9.2 for registered values",
            req.source_type
        )))?;
    let witnessing_depth = sworn_verify::WitnessingDepth::from_u8(req.witnessing_depth)
        .ok_or_else(|| ApiError::BadRequest(format!(
            "unknown witnessing_depth value {}; see SPEC §9.3 for registered values",
            req.witnessing_depth
        )))?;
    let attestor_relationship = sworn_verify::AttestorRelationship::from_u8(req.attestor_relationship)
        .ok_or_else(|| ApiError::BadRequest(format!(
            "unknown attestor_relationship value {}; see SPEC §9.4 for registered values",
            req.attestor_relationship
        )))?;
    if req.confidence > 10_000 {
        return Err(ApiError::BadRequest(format!(
            "confidence {} exceeds 10000 basis-points ceiling per SPEC §2.5",
            req.confidence
        )));
    }

    let fields = AttestationFields {
        signer: signer_pubkey,
        subject,
        activity_hash,
        data_hash,
        witness_for,
        source_hash,
        source_type,
        confidence: req.confidence,
        witnessing_depth,
        attestor_relationship,
        signer_asserted_at: req.signer_asserted_at,
        retention_hint: req.retention_hint,
        nonce,
    };

    // Signature check happens BEFORE we touch the database.
    verify(&fields, &signature).map_err(|e| {
        ApiError::BadRequest(format!("signature verification failed: {}", e))
    })?;

    // Persist.
    match sworn_store::insert_attestation(
        &state.pool,
        &fields,
        &signature,
        &req.activity_type_uri,
        Some(&req.payload),
    )
    .await
    {
        Ok((id, notarized_at)) => Ok((
            StatusCode::CREATED,
            Json(CreateAttestationResponse {
                id,
                notarized_at,
                data_hash: B64.encode(data_hash),
                activity_hash: B64.encode(activity_hash),
                spec_version: 2,
            }),
        )),
        Err(sworn_store::StoreError::Duplicate(existing_id)) => Err(ApiError::Duplicate(existing_id)),
        Err(e) => Err(ApiError::Internal(e.to_string())),
    }
}

async fn get_attestation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AttestationView>, ApiError> {
    let row = sworn_store::get_attestation(&state.pool, id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(AttestationView {
        id: row.id,
        spec_version: row.spec_version,
        signer_pubkey: B64.encode(row.fields.signer),
        subject: B64.encode(row.fields.subject),
        activity_type_uri: row.activity_type_uri,
        activity_hash: B64.encode(row.fields.activity_hash),
        data_hash: B64.encode(row.fields.data_hash),
        witness_for: B64.encode(row.fields.witness_for),
        source_hash: B64.encode(row.fields.source_hash),
        source_type: row.fields.source_type.to_u16(),
        confidence: row.fields.confidence,
        witnessing_depth: row.fields.witnessing_depth.to_u8(),
        attestor_relationship: row.fields.attestor_relationship.to_u8(),
        provenance_origin: row.provenance_origin,
        signer_asserted_at: row.fields.signer_asserted_at,
        notarized_at: row.notarized_at,
        retention_hint: row.fields.retention_hint,
        nonce: B64.encode(row.fields.nonce),
        signature: B64.encode(row.signature),
    }))
}

async fn verify_attestation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let row = sworn_store::get_attestation(&state.pool, id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)?;

    let (valid, reason) = match verify(&row.fields, &row.signature) {
        Ok(()) => (true, "signature_verified"),
        Err(_) => (false, "signature_invalid"),
    };

    Ok(Json(VerifyResponse { valid, reason, attestation_id: row.id }))
}

/// POST /attestations/:id/disclosure-tokens
///
/// Mint a single-use, time-limited disclosure token. Requires the caller to
/// prove control of the attestation's signing key by signing a canonical
/// issuance message (see `token_issuance_bytes`).
async fn create_disclosure_token(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<CreateTokenResponse>), ApiError> {
    let nonce = b64_32(&req.issuance_nonce, "issuance_nonce")?;
    let signature = b64_64(&req.signature, "signature")?;

    if req.expires_in_secs < 60 || req.expires_in_secs > 7 * 24 * 60 * 60 {
        return Err(ApiError::BadRequest(
            "expires_in_secs must be between 60 and 604800 (7 days)".into(),
        ));
    }

    // Fetch attestation to recover the signer pubkey.
    let att = sworn_store::get_attestation(&state.pool, id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)?;

    // Verify the issuance signature was made by the attestation's signer.
    let msg = token_issuance_bytes(id, req.expires_in_secs, &nonce);
    ed25519_verify(&att.fields.signer, &msg, &signature)
        .map_err(|_| ApiError::Unauthorized("issuance signature does not match attestation signer"))?;

    // Mint. Duplicate (same nonce) returns the existing token id rather than
    // an error — issuance is idempotent per (attestation, nonce).
    match sworn_store::create_disclosure_token(&state.pool, id, &nonce, req.expires_in_secs).await {
        Ok(tok) => Ok((
            StatusCode::CREATED,
            Json(CreateTokenResponse {
                token: tok.token,
                expires_at: tok.expires_at_unix,
                attestation_id: tok.attestation_id,
            }),
        )),
        Err(sworn_store::StoreError::Duplicate(existing_token)) => Ok((
            StatusCode::OK,
            Json(CreateTokenResponse {
                token: existing_token,
                expires_at: 0, // caller had the previous response; not re-derived here
                attestation_id: id,
            }),
        )),
        Err(e) => Err(ApiError::Internal(e.to_string())),
    }
}

/// POST /attestations/:id/disclose
///
/// Redeem a disclosure token and receive the payload. The token is marked
/// consumed atomically; a second attempt returns 410 Gone.
async fn disclose_payload(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<DiscloseRequest>,
) -> Result<Json<DiscloseResponse>, ApiError> {
    let redemption = sworn_store::redeem_disclosure_token(&state.pool, req.token)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let granted_id = match redemption {
        sworn_store::TokenRedemption::Granted { attestation_id } => attestation_id,
        sworn_store::TokenRedemption::Unknown => return Err(ApiError::NotFound),
        sworn_store::TokenRedemption::AlreadyRedeemed => {
            return Err(ApiError::Gone("Token was already redeemed."))
        }
        sworn_store::TokenRedemption::Expired => {
            return Err(ApiError::Gone("Token expired before redemption."))
        }
    };

    if granted_id != id {
        return Err(ApiError::BadRequest(
            "Token was issued for a different attestation id.".into(),
        ));
    }

    let payload = sworn_store::get_payload(&state.pool, id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::Gone("Payload has been reclaimed."))?;

    let meta = sworn_store::get_attestation(&state.pool, id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)?;

    // Recompute data_hash so the caller can independently confirm the payload
    // matches what was signed. If a reclaim job silently swapped payload bytes
    // this would surface as a mismatch when the caller re-hashes.
    let canonical = serde_jcs::to_vec(&payload)
        .map_err(|e| ApiError::Internal(format!("payload canonicalization failed: {}", e)))?;
    let data_hash: [u8; 32] = Sha256::digest(&canonical).into();

    Ok(Json(DiscloseResponse {
        attestation_id: id,
        payload,
        data_hash: B64.encode(data_hash),
        signer_pubkey: B64.encode(meta.fields.signer),
        signer_asserted_at: meta.fields.signer_asserted_at,
        notarized_at: meta.notarized_at,
    }))
}

/// Any GET on /attestations WITHOUT an id is a refused list operation.
async fn refused_list(Query(_q): Query<serde_json::Value>) -> Result<(), ApiError> {
    Err(ApiError::Refused("list-by-signer, list-by-subject, and bulk enumeration are not supported"))
}

// ─── Helpers ────────────────────────────────────────────────────────

fn b64_32(s: &str, field: &str) -> Result<[u8; 32], ApiError> {
    let bytes = B64.decode(s)
        .map_err(|e| ApiError::BadRequest(format!("{}: not valid base64: {}", field, e)))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        ApiError::BadRequest(format!("{}: expected 32 bytes, got {}", field, v.len()))
    })
}

fn b64_64(s: &str, field: &str) -> Result<[u8; 64], ApiError> {
    let bytes = B64.decode(s)
        .map_err(|e| ApiError::BadRequest(format!("{}: not valid base64: {}", field, e)))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        ApiError::BadRequest(format!("{}: expected 64 bytes, got {}", field, v.len()))
    })
}

/// Canonical byte sequence signed by the attestation signer to authorize
/// issuance of a disclosure token. Structure is deliberately different from
/// the attestation canonical bytes (§3.1) so a leaked attestation signature
/// can NEVER be replayed as a token-issuance signature.
///
/// Layout:
///   b"sworn-disclosure-token-v1"  (25 bytes, domain separator)
///   || attestation_id             (16 bytes, big-endian UUID)
///   || expires_in_secs            (8 bytes, i64 little-endian)
///   || issuance_nonce             (32 bytes)
///
/// Total: 81 bytes.
fn token_issuance_bytes(id: Uuid, expires_in_secs: i64, nonce: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(81);
    out.extend_from_slice(b"sworn-disclosure-token-v1");
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&expires_in_secs.to_le_bytes());
    out.extend_from_slice(nonce);
    out
}

fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), ()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| ())?;
    let signature = Signature::from_bytes(sig);
    vk.verify(msg, &signature).map_err(|_| ())
}

// ─── main ───────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,sqlx=warn")),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sworn:sworn@localhost:5432/sworn".to_string());
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    info!("connecting to postgres");
    let pool = sworn_store::connect(&database_url).await?;
    info!("running migrations");
    sworn_store::migrate(&pool).await?;

    let state = AppState {
        pool: Arc::new(pool),
        rate_limiter: Arc::new(RateLimiter::new()),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/attestations", post(create_attestation).get(refused_list))
        .route("/attestations/:id", get(get_attestation))
        .route("/attestations/:id/disclosure-tokens", post(create_disclosure_token))
        .route("/attestations/:id/disclose", post(disclose_payload))
        .route("/verify/:id", get(verify_attestation))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit_middleware))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    info!("sworn-api listening on {}", bind);
    let make_svc = app.into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, make_svc).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuance_bytes_are_exactly_81() {
        let id = Uuid::from_bytes([1u8; 16]);
        let nonce = [7u8; 32];
        let msg = token_issuance_bytes(id, 3600, &nonce);
        assert_eq!(msg.len(), 81);
        // Domain separator at the front, unambiguous with attestation canonical bytes.
        assert!(msg.starts_with(b"sworn-disclosure-token-v1"));
    }

    #[test]
    fn issuance_bytes_change_with_nonce() {
        let id = Uuid::from_bytes([1u8; 16]);
        let a = token_issuance_bytes(id, 3600, &[0u8; 32]);
        let b = token_issuance_bytes(id, 3600, &[1u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn issuance_bytes_change_with_expiry() {
        let id = Uuid::from_bytes([1u8; 16]);
        let a = token_issuance_bytes(id, 3600, &[0u8; 32]);
        let b = token_issuance_bytes(id, 3601, &[0u8; 32]);
        assert_ne!(a, b);
    }
}
