//! sworn — command-line client for a running sworn-postgres API.
//!
//! Primary developer surface. Five-line quickstart target:
//!
//!   docker compose up -d
//!   sworn keygen > my.key
//!   sworn attest --key my.key --subject <base64> --activity-type sworn.dev/v1/endorsement --payload hello.json
//!   sworn verify <attestation-id>
//!
//! This CLI wraps the HTTP API. It does NOT talk to Postgres directly. Every
//! command is expressible via curl; the CLI is there so you don't have to.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::PathBuf;
use sworn_verify::{sign, verify, AttestationFields};

const DEFAULT_API_URL: &str = "http://localhost:8080";

#[derive(Parser, Debug)]
#[command(name = "sworn", version, about = "SWORN reference CLI (extol-work/sworn-postgres)")]
struct Cli {
    /// URL of a running sworn-postgres API.
    #[arg(long, env = "SWORN_API_URL", default_value = DEFAULT_API_URL, global = true)]
    api_url: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate an Ed25519 signing key. Prints an encoded key to stdout.
    Keygen,
    /// Sign a payload and submit an attestation to the API.
    Attest {
        /// Path to a keyfile produced by `sworn keygen`.
        #[arg(long)]
        key: PathBuf,
        /// Subject: 32 bytes, base64. If it starts with "sha256:", the rest is
        /// treated as a hex sha256 and converted for you.
        #[arg(long)]
        subject: String,
        /// Activity type URI, e.g. "sworn.dev/v1/endorsement".
        #[arg(long)]
        activity_type: String,
        /// Path to a JSON payload file, or "-" to read stdin.
        #[arg(long)]
        payload: String,
        /// Optional witness_for: 32 bytes, base64.
        #[arg(long)]
        witness_for: Option<String>,
        /// Retention hint in seconds; -1 for permanent (default).
        #[arg(long, default_value_t = -1)]
        retention_hint: i64,
        /// Save the created attestation record locally as JSON. Off by default.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify an attestation by id via the API's /verify endpoint.
    Verify {
        /// Attestation id (UUID) OR a path to a local sworn.json file.
        target: String,
    },
}

// ─── Wire types (mirrors api/src/main.rs; kept minimal here) ─────────

#[derive(Serialize)]
struct CreateReq<'a> {
    signer_pubkey: String,
    subject: String,
    activity_type_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness_for: Option<String>,
    signer_asserted_at: i64,
    retention_hint: i64,
    nonce: String,
    signature: String,
    payload: &'a serde_json::Value,
}

#[derive(Deserialize, Serialize)]
struct CreateResp {
    id: uuid::Uuid,
    notarized_at: i64,
    data_hash: String,
    activity_hash: String,
}

#[derive(Deserialize)]
struct ApiErr {
    #[allow(dead_code)]
    error: String,
    message: String,
    existing_id: Option<uuid::Uuid>,
}

#[derive(Deserialize, Serialize)]
struct VerifyResp {
    valid: bool,
    reason: String,
    attestation_id: uuid::Uuid,
}

/// Local record we save with --out. Includes enough to re-verify offline.
#[derive(Serialize, Deserialize)]
struct LocalRecord {
    id: uuid::Uuid,
    signer_pubkey: String,
    subject: String,
    activity_type_uri: String,
    activity_hash: String,
    data_hash: String,
    witness_for: String,
    signer_asserted_at: i64,
    notarized_at: i64,
    retention_hint: i64,
    nonce: String,
    signature: String,
    payload: serde_json::Value,
}

// ─── Entrypoint ─────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => cmd_keygen(),
        Cmd::Attest {
            key,
            subject,
            activity_type,
            payload,
            witness_for,
            retention_hint,
            out,
        } => {
            cmd_attest(
                &cli.api_url,
                &key,
                &subject,
                &activity_type,
                &payload,
                witness_for.as_deref(),
                retention_hint,
                out.as_deref(),
            )
            .await
        }
        Cmd::Verify { target } => cmd_verify(&cli.api_url, &target).await,
    }
}

// ─── Commands ───────────────────────────────────────────────────────

fn cmd_keygen() -> Result<()> {
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();

    // Line-based format: two labelled base64 lines. Human-inspectable, easy
    // to source-control safely (private line is obviously the private one).
    println!("sworn-key-v1");
    println!("public: {}", B64.encode(pk));
    println!("secret: {}", B64.encode(seed));
    eprintln!(
        "\n# Save this to a file, e.g.:\n#   sworn keygen > my.key\n\
         # Public key (share freely): {}\n",
        B64.encode(pk)
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_attest(
    api_url: &str,
    keyfile: &std::path::Path,
    subject: &str,
    activity_type_uri: &str,
    payload_arg: &str,
    witness_for: Option<&str>,
    retention_hint: i64,
    out: Option<&std::path::Path>,
) -> Result<()> {
    // 1. Load key.
    let (signing_key, pk_bytes) = load_key(keyfile)?;

    // 2. Resolve subject to 32 bytes.
    let subject_bytes = resolve_subject(subject)?;

    // 3. Load payload JSON.
    let payload_val = load_payload(payload_arg)?;

    // 4. Compute activity_hash and data_hash exactly as the server will.
    let activity_hash: [u8; 32] = Sha256::digest(activity_type_uri.as_bytes()).into();
    let canonical = serde_jcs::to_vec(&payload_val).context("JCS-canonicalize payload")?;
    let data_hash: [u8; 32] = Sha256::digest(&canonical).into();

    // 5. Random nonce (CP2). Deterministic derivation per §3.4 is a future add.
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    // 6. Witness_for: zeros unless caller provided one.
    let witness_for_bytes = match witness_for {
        None | Some("") => [0u8; 32],
        Some(s) => b64_32(s).context("--witness-for")?,
    };

    // 7. Signer-asserted timestamp: local clock at signing time. Informational only.
    let signer_asserted_at = chrono_now_secs();

    let fields = AttestationFields {
        signer: pk_bytes,
        subject: subject_bytes,
        activity_hash,
        data_hash,
        witness_for: witness_for_bytes,
        signer_asserted_at,
        retention_hint,
        nonce,
    };

    // 8. Sign.
    let signature = sign(&signing_key, &fields).map_err(|e| anyhow!("sign: {}", e))?;

    // 9. Local sanity check before we ship it: verify our own signature.
    verify(&fields, &signature).map_err(|e| anyhow!("self-verify failed (client bug): {}", e))?;

    // 10. POST /attestations.
    let req = CreateReq {
        signer_pubkey: B64.encode(pk_bytes),
        subject: B64.encode(subject_bytes),
        activity_type_uri: activity_type_uri.to_string(),
        witness_for: if witness_for_bytes == [0u8; 32] {
            None
        } else {
            Some(B64.encode(witness_for_bytes))
        },
        signer_asserted_at,
        retention_hint,
        nonce: B64.encode(nonce),
        signature: B64.encode(signature),
        payload: &payload_val,
    };

    let url = format!("{}/attestations", api_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client.post(&url).json(&req).send().await?;
    let status = resp.status();
    let body_text = resp.text().await?;

    if status.is_success() {
        let ok: CreateResp = serde_json::from_str(&body_text)
            .with_context(|| format!("parse response: {}", body_text))?;
        println!("id:                {}", ok.id);
        println!("notarized_at:      {}", ok.notarized_at);
        println!("data_hash (b64):   {}", ok.data_hash);
        println!("activity_hash (b64): {}", ok.activity_hash);

        if let Some(path) = out {
            let record = LocalRecord {
                id: ok.id,
                signer_pubkey: B64.encode(pk_bytes),
                subject: B64.encode(subject_bytes),
                activity_type_uri: activity_type_uri.to_string(),
                activity_hash: B64.encode(activity_hash),
                data_hash: B64.encode(data_hash),
                witness_for: B64.encode(witness_for_bytes),
                signer_asserted_at,
                notarized_at: ok.notarized_at,
                retention_hint,
                nonce: B64.encode(nonce),
                signature: B64.encode(signature),
                payload: payload_val,
            };
            std::fs::write(path, serde_json::to_string_pretty(&record)?)?;
            eprintln!("wrote {}", path.display());
        }
        Ok(())
    } else if status.as_u16() == 409 {
        let err: ApiErr = serde_json::from_str(&body_text)
            .with_context(|| format!("parse error body: {}", body_text))?;
        eprintln!("duplicate attestation");
        if let Some(id) = err.existing_id {
            println!("existing_id: {}", id);
        }
        eprintln!("{}", err.message);
        std::process::exit(2);
    } else {
        bail!("api returned {}: {}", status, body_text);
    }
}

async fn cmd_verify(api_url: &str, target: &str) -> Result<()> {
    // If target parses as a UUID, hit the API. Otherwise treat as a file path.
    if let Ok(id) = uuid::Uuid::parse_str(target) {
        let url = format!("{}/verify/{}", api_url.trim_end_matches('/'), id);
        let resp = reqwest::get(&url).await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("api returned {}: {}", status, text);
        }
        let v: VerifyResp = serde_json::from_str(&text)?;
        println!("valid:  {}", v.valid);
        println!("reason: {}", v.reason);
        println!("id:     {}", v.attestation_id);
        if !v.valid {
            std::process::exit(3);
        }
        Ok(())
    } else {
        // Local file: verify signature offline, no API call.
        let record_bytes = std::fs::read(target)
            .with_context(|| format!("read record file: {}", target))?;
        let record: LocalRecord = serde_json::from_slice(&record_bytes)?;

        let fields = AttestationFields {
            signer: b64_32(&record.signer_pubkey)?,
            subject: b64_32(&record.subject)?,
            activity_hash: b64_32(&record.activity_hash)?,
            data_hash: b64_32(&record.data_hash)?,
            witness_for: b64_32(&record.witness_for)?,
            signer_asserted_at: record.signer_asserted_at,
            retention_hint: record.retention_hint,
            nonce: b64_32(&record.nonce)?,
        };
        let signature = b64_64(&record.signature)?;

        // Also confirm the payload still matches data_hash.
        let canonical = serde_jcs::to_vec(&record.payload).context("re-canonicalize payload")?;
        let recomputed: [u8; 32] = Sha256::digest(&canonical).into();
        if recomputed != fields.data_hash {
            println!("valid:  false");
            println!("reason: payload_hash_mismatch");
            std::process::exit(3);
        }

        match verify(&fields, &signature) {
            Ok(()) => {
                println!("valid:  true");
                println!("reason: signature_verified");
                println!("id:     {}", record.id);
                Ok(())
            }
            Err(e) => {
                println!("valid:  false");
                println!("reason: {}", e);
                std::process::exit(3);
            }
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

fn load_key(path: &std::path::Path) -> Result<(SigningKey, [u8; 32])> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read key file: {}", path.display()))?;
    let mut secret_line: Option<String> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("secret:") {
            secret_line = Some(rest.trim().to_string());
        }
    }
    let secret_b64 = secret_line.ok_or_else(|| anyhow!("keyfile missing 'secret:' line"))?;
    let seed_vec = B64.decode(&secret_b64).context("decode secret")?;
    let seed: [u8; SECRET_KEY_LENGTH] = seed_vec
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("secret: expected {} bytes, got {}", SECRET_KEY_LENGTH, v.len()))?;
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    Ok((sk, pk))
}

fn resolve_subject(input: &str) -> Result<[u8; 32]> {
    if let Some(hex_part) = input.strip_prefix("sha256:") {
        let bytes = hex::decode_32(hex_part)?;
        return Ok(bytes);
    }
    b64_32(input).context("--subject not base64-32 (also accepts 'sha256:<hex>')")
}

fn load_payload(arg: &str) -> Result<serde_json::Value> {
    let raw = if arg == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(arg).with_context(|| format!("read payload: {}", arg))?
    };
    let val: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse payload as JSON: {}", arg))?;
    Ok(val)
}

fn b64_32(s: &str) -> Result<[u8; 32]> {
    let bytes = B64.decode(s).context("base64 decode")?;
    bytes.try_into().map_err(|v: Vec<u8>| anyhow!("expected 32 bytes, got {}", v.len()))
}

fn b64_64(s: &str) -> Result<[u8; 64]> {
    let bytes = B64.decode(s).context("base64 decode")?;
    bytes.try_into().map_err(|v: Vec<u8>| anyhow!("expected 64 bytes, got {}", v.len()))
}

fn chrono_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch?")
        .as_secs() as i64
}

// Tiny inline hex decoder (avoid another dep for one call site).
mod hex {
    use super::*;
    pub fn decode_32(s: &str) -> Result<[u8; 32]> {
        let s = s.trim();
        if s.len() != 64 {
            bail!("hex sha256 must be 64 chars, got {}", s.len());
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .context("invalid hex digit")?;
        }
        Ok(out)
    }
}
