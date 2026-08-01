//! sworn-api — HTTP server for the SWORN reference implementation.
//!
//! Endpoints (v0.1):
//!   POST   /attestations           create + verify + store
//!   GET    /attestations/:id       metadata only, no payload
//!   GET    /verify/:id             re-verify a stored attestation
//!   GET    /healthz                liveness
//!
//! Deliberately refused:
//!   GET    /attestations           bulk enumeration
//!   GET    /attestations?signer=X  list by signer
//!   GET    /attestations?subject=X list by subject
//!
//! Refusals return 400 with a message pointing to the spec's shown-never-pulled
//! discipline. They exist so implementers testing conformance find them.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use sworn_verify::{verify, AttestationFields};
use tracing::info;
use uuid::Uuid;

// ─── App state ──────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    pool: Arc<PgPool>,
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
    /// Absolute URI naming the activity type (§2.2).
    activity_type_uri: String,
    /// 32 bytes, base64. Optional — omit or send "" for none.
    #[serde(default)]
    witness_for: Option<String>,
    /// Signer-asserted timestamp (int64, unix seconds). Informational only
    /// per OPEN_QUESTIONS Q2; verifiers MUST NOT use for trust decisions.
    signer_asserted_at: i64,
    /// Retention hint (int64, seconds; -1 = permanent).
    retention_hint: i64,
    /// 32 bytes, base64.
    nonce: String,
    /// 64 bytes, base64.
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
}

#[derive(Debug, Serialize)]
struct AttestationView {
    id: Uuid,
    signer_pubkey: String,
    subject: String,
    activity_type_uri: String,
    activity_hash: String,
    data_hash: String,
    /// Base64. Zero-bytes when no witness endorsement.
    witness_for: String,
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
                ErrorBody { error: "not_found", message: "attestation not found".into(), existing_id: None },
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

    let fields = AttestationFields {
        signer: signer_pubkey,
        subject,
        activity_hash,
        data_hash,
        witness_for,
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
        signer_pubkey: B64.encode(row.fields.signer),
        subject: B64.encode(row.fields.subject),
        activity_type_uri: row.activity_type_uri,
        activity_hash: B64.encode(row.fields.activity_hash),
        data_hash: B64.encode(row.fields.data_hash),
        witness_for: B64.encode(row.fields.witness_for),
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

    let state = AppState { pool: Arc::new(pool) };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/attestations", post(create_attestation).get(refused_list))
        .route("/attestations/:id", get(get_attestation))
        .route("/verify/:id", get(verify_attestation))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    info!("sworn-api listening on {}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}
