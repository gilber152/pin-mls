use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::auth::sha256_hex;
use crate::identity::derive_seed_from_mnemonic;
use crate::{random_bytes, CoreError};

pub const SAFE_NONCE_LEN: usize = 24;
pub const SAFE_BUCKET_BYTES: usize = 16_384;
pub const SAFE_AEAD_TAG_LEN: usize = 16;
pub const SAFE_MAX_BUCKETS: usize = 32; // 512 KiB max

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SafeBackupKeys {
    pub backup_id: [u8; 32],
    pub enc_key: [u8; 32],
    pub sk_safe_auth: [u8; 32],
    pub pk_safe_auth: [u8; 32],
}

pub fn derive_safe_keys_from_mnemonic(phrase: &str) -> Result<SafeBackupKeys, CoreError> {
    let mut seed = derive_seed_from_mnemonic(phrase)?;
    let hk = Hkdf::<Sha256>::new(Some(b"pin-mls-v1-safe"), &seed);

    let mut backup_id = [0u8; 32];
    let mut enc_key = [0u8; 32];
    let mut sk_safe_auth = [0u8; 32];

    hk.expand(b"safe-backup-id-v1", &mut backup_id)
        .map_err(|e| CoreError::Safe(e.to_string()))?;
    hk.expand(b"safe-xchacha-enc-v1", &mut enc_key)
        .map_err(|e| CoreError::Safe(e.to_string()))?;
    hk.expand(b"safe-ed25519-auth-v1", &mut sk_safe_auth)
        .map_err(|e| CoreError::Safe(e.to_string()))?;
    seed.zeroize();

    let pk_safe_auth = SigningKey::from_bytes(&sk_safe_auth)
        .verifying_key()
        .to_bytes();

    Ok(SafeBackupKeys {
        backup_id,
        enc_key,
        sk_safe_auth,
        pk_safe_auth,
    })
}

fn build_safe_aad(backup_id: &[u8; 32], revision: u64) -> [u8; 52] {
    let mut aad = [0u8; 52];
    aad[0..12].copy_from_slice(b"safe-blob-v1");
    aad[12..44].copy_from_slice(backup_id);
    aad[44..52].copy_from_slice(&revision.to_be_bytes());
    aad
}

/// Cifra en cubetas exactas de 16 KiB: wire = [24B XNonce][k * 16384B ciphertext+tag].
pub fn seal_safe_backup(
    keys: &SafeBackupKeys,
    revision: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if revision == 0 {
        return Err(CoreError::Safe("revision debe ser >= 1".into()));
    }
    let min_needed = 4 + plaintext.len() + SAFE_AEAD_TAG_LEN;
    let buckets = min_needed.div_ceil(SAFE_BUCKET_BYTES).max(1);
    if buckets > SAFE_MAX_BUCKETS {
        return Err(CoreError::Safe("snapshot excede límite de 512 KiB".into()));
    }

    let padded_plain_len = buckets * SAFE_BUCKET_BYTES - SAFE_AEAD_TAG_LEN;
    let mut framed = vec![0u8; padded_plain_len];
    framed[0..4].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
    framed[4..4 + plaintext.len()].copy_from_slice(plaintext);

    let nonce_bytes = random_bytes::<SAFE_NONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.enc_key)
        .map_err(|e| CoreError::Safe(e.to_string()))?;
    let aad = build_safe_aad(&keys.backup_id, revision);

    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: &framed,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::Safe("fallo cifrando Safe Backup".into()))?;
    framed.zeroize();

    let mut wire = Vec::with_capacity(SAFE_NONCE_LEN + ct.len());
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ct);
    Ok(wire)
}

pub fn open_safe_backup(
    keys: &SafeBackupKeys,
    server_revision: u64,
    wire_blob: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if server_revision == 0 {
        return Err(CoreError::Safe("server_revision debe ser >= 1".into()));
    }
    if wire_blob.len() < SAFE_NONCE_LEN + SAFE_BUCKET_BYTES
        || (wire_blob.len() - SAFE_NONCE_LEN) % SAFE_BUCKET_BYTES != 0
    {
        return Err(CoreError::Safe("longitud de cubeta Safe inválida".into()));
    }

    let nonce_bytes = &wire_blob[0..SAFE_NONCE_LEN];
    let ct = &wire_blob[SAFE_NONCE_LEN..];
    let aad = build_safe_aad(&keys.backup_id, server_revision);

    let cipher = XChaCha20Poly1305::new_from_slice(&keys.enc_key)
        .map_err(|e| CoreError::Safe(e.to_string()))?;
    let mut framed = cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload { msg: ct, aad: &aad },
        )
        .map_err(|_| CoreError::Safe("descifrado o AAD de Safe Backup inválido".into()))?;

    if framed.len() < 4 {
        framed.zeroize();
        return Err(CoreError::Safe("framing truncado".into()));
    }
    let plain_len = u32::from_be_bytes(framed[0..4].try_into().unwrap()) as usize;
    if 4 + plain_len > framed.len() {
        framed.zeroize();
        return Err(CoreError::Safe("longitud interna de Safe Backup corrupta".into()));
    }
    let out = framed[4..4 + plain_len].to_vec();
    framed.zeroize();
    Ok(out)
}

/// Firma canónica `safe-http-v1`, idéntica a `backend/src/modules/safe/routes.ts`.
pub fn sign_safe_http_request(
    keys: &SafeBackupKeys,
    method: &str,
    path_with_query: &str,
    revision: u64,
    timestamp_unix_sec: u64,
    nonce_uuid: &str,
    raw_body: &[u8],
) -> [u8; 64] {
    let canonical = format!(
        "safe-http-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_with_query,
        revision,
        timestamp_unix_sec,
        nonce_uuid,
        sha256_hex(raw_body)
    );
    SigningKey::from_bytes(&keys.sk_safe_auth)
        .sign(canonical.as_bytes())
        .to_bytes()
}
