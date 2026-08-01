//! sworn-store — Postgres storage layer for SWORN attestations.
//!
//! Append-only by convention: no UPDATE or DELETE paths are exposed here.
//! Reclamation of payload bytes past the retention hint is deferred.
//!
//! The schema mirrors §2.1 (attestation record structure) plus two housekeeping
//! columns (id, notarized_at) that are storage concerns, not signed content.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use sworn_verify::AttestationFields;
use uuid::Uuid;

pub use sqlx::Error as SqlxError;

/// Errors surfaced by store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// An attestation with the same (signer, subject, activity_hash, data_hash, nonce)
    /// already exists. Handler layer decides whether to return 409 with the existing id.
    #[error("duplicate attestation; existing id: {0}")]
    Duplicate(Uuid),
}

/// Full stored form of an attestation. Everything a verifier needs, plus
/// housekeeping (id, notarized_at). The payload lives in a separate column
/// so /disclose can return it without hydrating the full record.
#[derive(Debug, Clone)]
pub struct StoredAttestation {
    pub id: Uuid,
    pub fields: AttestationFields,
    pub signature: [u8; 64],
    pub activity_type_uri: String,
    /// Server-clock timestamp of insertion. This is the trust-relevant timestamp
    /// per OPEN_QUESTIONS Q2. `fields.signer_asserted_at` is informational only.
    pub notarized_at: i64,
}

/// Open a pool. Callers are expected to set connect params via `DATABASE_URL`.
pub async fn connect(database_url: &str) -> Result<PgPool, StoreError> {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await?;
    Ok(pool)
}

/// Run embedded migrations. Idempotent; safe on every start.
pub async fn migrate(pool: &PgPool) -> Result<(), StoreError> {
    sqlx::migrate!("../migrations").run(pool).await
        .map_err(|e| StoreError::Sqlx(sqlx::Error::Migrate(Box::new(e))))?;
    Ok(())
}

/// Insert a new attestation. Returns the new id and notarized_at (server clock, unix seconds).
///
/// Caller MUST have already verified the signature via `sworn_verify::verify(...)`
/// and confirmed `SHA-256(canonicalize(payload)) == fields.data_hash` before calling this.
/// The store trusts what it's handed and only enforces uniqueness at the DB level.
///
/// On duplicate (same signer + subject + activity + data + nonce), returns
/// `StoreError::Duplicate(existing_id)` per SCOPE.md idempotency rule.
pub async fn insert_attestation(
    pool: &PgPool,
    fields: &AttestationFields,
    signature: &[u8; 64],
    activity_type_uri: &str,
    payload_json: Option<&serde_json::Value>,
) -> Result<(Uuid, i64), StoreError> {
    let notarized_at = chrono::Utc::now().timestamp();

    let insert = sqlx::query(
        r#"
        INSERT INTO attestations
            (signer_pubkey, subject, activity_type_uri, activity_hash,
             data_hash, witness_for, signer_asserted_at, notarized_at,
             retention_hint, nonce, signature, payload)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING id
        "#,
    )
    .bind(&fields.signer[..])
    .bind(&fields.subject[..])
    .bind(activity_type_uri)
    .bind(&fields.activity_hash[..])
    .bind(&fields.data_hash[..])
    .bind(&fields.witness_for[..])
    .bind(fields.signer_asserted_at)
    .bind(notarized_at)
    .bind(fields.retention_hint)
    .bind(&fields.nonce[..])
    .bind(&signature[..])
    .bind(payload_json)
    .fetch_one(pool)
    .await;

    match insert {
        Ok(row) => Ok((row.get::<Uuid, _>("id"), notarized_at)),
        Err(sqlx::Error::Database(db)) if db.constraint() == Some("unique_attestation") => {
            let existing_id: Uuid = sqlx::query_scalar(
                r#"
                SELECT id FROM attestations
                WHERE signer_pubkey = $1 AND subject = $2
                  AND activity_hash = $3 AND data_hash = $4 AND nonce = $5
                "#,
            )
            .bind(&fields.signer[..])
            .bind(&fields.subject[..])
            .bind(&fields.activity_hash[..])
            .bind(&fields.data_hash[..])
            .bind(&fields.nonce[..])
            .fetch_one(pool)
            .await?;
            Err(StoreError::Duplicate(existing_id))
        }
        Err(e) => Err(e.into()),
    }
}

/// Fetch metadata for a single attestation by id. Does NOT return the payload
/// (that path goes through /disclose in CP3+).
pub async fn get_attestation(pool: &PgPool, id: Uuid) -> Result<Option<StoredAttestation>, StoreError> {
    let row = sqlx::query(
        r#"
        SELECT id, signer_pubkey, subject, activity_type_uri, activity_hash,
               data_hash, witness_for, signer_asserted_at, notarized_at,
               retention_hint, nonce, signature
        FROM attestations
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else { return Ok(None) };

    let signer: Vec<u8> = row.get("signer_pubkey");
    let subject: Vec<u8> = row.get("subject");
    let activity_hash: Vec<u8> = row.get("activity_hash");
    let data_hash: Vec<u8> = row.get("data_hash");
    let witness_for: Vec<u8> = row.get("witness_for");
    let nonce: Vec<u8> = row.get("nonce");
    let signature: Vec<u8> = row.get("signature");

    let fields = AttestationFields {
        signer: to_32(&signer)?,
        subject: to_32(&subject)?,
        activity_hash: to_32(&activity_hash)?,
        data_hash: to_32(&data_hash)?,
        witness_for: to_32(&witness_for)?,
        signer_asserted_at: row.get::<i64, _>("signer_asserted_at"),
        retention_hint: row.get::<i64, _>("retention_hint"),
        nonce: to_32(&nonce)?,
    };

    Ok(Some(StoredAttestation {
        id: row.get("id"),
        fields,
        signature: to_64(&signature)?,
        activity_type_uri: row.get("activity_type_uri"),
        notarized_at: row.get("notarized_at"),
    }))
}

/// Fetch just the payload for an attestation. Used by `/disclose` after a
/// disclosure token has been redeemed.
///
/// Returns `Ok(None)` if the attestation exists but the payload has been
/// reclaimed (retention hint expired and a reclaim job ran). Returns
/// `Err(NotFound)`-style behavior at the store level by returning `Ok(None)`
/// for both "row missing" and "payload null"; the handler distinguishes.
pub async fn get_payload(pool: &PgPool, id: Uuid) -> Result<Option<serde_json::Value>, StoreError> {
    let row = sqlx::query(r#"SELECT payload FROM attestations WHERE id = $1"#)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(row.get::<Option<serde_json::Value>, _>("payload"))
}

// ─── Disclosure tokens ─────────────────────────────────────────────

/// A minted disclosure token that a subject / verifier can redeem exactly once.
#[derive(Debug, Clone)]
pub struct DisclosureToken {
    pub token: Uuid,
    pub attestation_id: Uuid,
    pub expires_at_unix: i64,
}

/// Result of attempting to redeem a token.
#[derive(Debug)]
pub enum TokenRedemption {
    /// Token valid; caller may serve the payload.
    Granted { attestation_id: Uuid },
    /// Token unknown.
    Unknown,
    /// Token already used or explicitly revoked.
    AlreadyRedeemed,
    /// Token expired before redemption.
    Expired,
}

/// Insert a new disclosure token for `attestation_id`.
///
/// `expires_in_secs` is capped at 7 days to bound the reference implementation's
/// exposure window; real deployments should tune. `issuance_nonce` is the
/// 32-byte anti-replay nonce the signer included in their signed request.
///
/// Returns `StoreError::Duplicate(existing_token_id)` if the same
/// `(attestation_id, issuance_nonce)` was already used to mint a token.
pub async fn create_disclosure_token(
    pool: &PgPool,
    attestation_id: Uuid,
    issuance_nonce: &[u8; 32],
    expires_in_secs: i64,
) -> Result<DisclosureToken, StoreError> {
    let expires_in_secs = expires_in_secs.clamp(60, 7 * 24 * 60 * 60);

    let insert = sqlx::query(
        r#"
        INSERT INTO disclosure_tokens (attestation_id, expires_at, issuance_nonce)
        VALUES ($1, NOW() + make_interval(secs => $2::double precision), $3)
        RETURNING token, expires_at
        "#,
    )
    .bind(attestation_id)
    .bind(expires_in_secs as f64)
    .bind(&issuance_nonce[..])
    .fetch_one(pool)
    .await;

    match insert {
        Ok(row) => {
            let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
            Ok(DisclosureToken {
                token: row.get("token"),
                attestation_id,
                expires_at_unix: expires_at.timestamp(),
            })
        }
        Err(sqlx::Error::Database(db)) if db.constraint() == Some("one_token_per_issuance") => {
            let existing: Uuid = sqlx::query_scalar(
                r#"SELECT token FROM disclosure_tokens WHERE attestation_id = $1 AND issuance_nonce = $2"#,
            )
            .bind(attestation_id)
            .bind(&issuance_nonce[..])
            .fetch_one(pool)
            .await?;
            Err(StoreError::Duplicate(existing))
        }
        Err(e) => Err(e.into()),
    }
}

/// Attempt to redeem a disclosure token atomically.
///
/// If the token is valid and unredeemed, this marks it redeemed and returns
/// `Granted`. All state transitions happen in a single UPDATE so concurrent
/// redemptions of the same token race safely to exactly one winner.
pub async fn redeem_disclosure_token(
    pool: &PgPool,
    token: Uuid,
) -> Result<TokenRedemption, StoreError> {
    let updated = sqlx::query(
        r#"
        UPDATE disclosure_tokens
           SET redeemed_at = NOW()
         WHERE token = $1
           AND redeemed_at IS NULL
           AND expires_at > NOW()
        RETURNING attestation_id
        "#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = updated {
        return Ok(TokenRedemption::Granted { attestation_id: row.get("attestation_id") });
    }

    // Update didn't hit anything; distinguish unknown vs already-redeemed vs expired.
    let existing = sqlx::query(
        r#"SELECT redeemed_at, expires_at FROM disclosure_tokens WHERE token = $1"#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;

    Ok(match existing {
        None => TokenRedemption::Unknown,
        Some(row) => {
            let redeemed_at: Option<chrono::DateTime<chrono::Utc>> = row.get("redeemed_at");
            if redeemed_at.is_some() {
                TokenRedemption::AlreadyRedeemed
            } else {
                TokenRedemption::Expired
            }
        }
    })
}

/// Explicitly refused: listing attestations by signer.
/// Kept as a function so callers see the signature and get a compiler-level
/// nudge that this is not a supported operation.
pub fn list_by_signer_is_refused() {}

/// Explicitly refused: listing attestations by subject.
pub fn list_by_subject_is_refused() {}

fn to_32(v: &[u8]) -> Result<[u8; 32], StoreError> {
    v.try_into().map_err(|_| {
        StoreError::Sqlx(sqlx::Error::Decode(
            format!("expected 32 bytes, got {}", v.len()).into(),
        ))
    })
}

fn to_64(v: &[u8]) -> Result<[u8; 64], StoreError> {
    v.try_into().map_err(|_| {
        StoreError::Sqlx(sqlx::Error::Decode(
            format!("expected 64 bytes, got {}", v.len()).into(),
        ))
    })
}
