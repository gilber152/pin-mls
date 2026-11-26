use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Firma canónica Nivel 2 (`ed25519-http-v1`), idéntica a `backend/src/plugins/ed25519Auth.ts`.
pub fn sign_canonical_http(
    sk_32: &[u8; 32],
    method: &str,
    path_with_query: &str,
    timestamp_unix_sec: u64,
    nonce_uuid: &str,
    raw_body: &[u8],
) -> [u8; 64] {
    let body_hash = sha256_hex(raw_body);
    let canonical = format!(
        "ed25519-http-v1\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_with_query,
        timestamp_unix_sec,
        nonce_uuid,
        body_hash
    );
    SigningKey::from_bytes(sk_32)
        .sign(canonical.as_bytes())
        .to_bytes()
}
