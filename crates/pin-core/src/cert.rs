use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

use crate::identity::validate_crockford_pin;
use crate::{is_uuid_v4_bytes, CoreError};

pub const DEVICE_CERT_VERSION: u8 = 1;
pub const DEVICE_CERT_LEN: usize = 169;
pub const KP_GRANT_VERSION: u8 = 1;
pub const KP_GRANT_LEN: usize = 121;
pub const REV_MANIFEST_VERSION: u8 = 1;
pub const MAX_REVOKED_DEVICES: usize = 256;

const DOMAIN_DEVICECERT: &[u8] = b"devicecert-v1";
const DOMAIN_KPGRANT: &[u8] = b"kpgrant-v1";
const DOMAIN_REVMANIFEST: &[u8] = b"revmanifest-v1";

#[derive(Debug, Clone)]
pub struct SignedRevocationManifest {
    pub pin: String,
    pub seq_num: u64,
    pub manifest_raw: Vec<u8>,
    pub sig_root: [u8; 64],
    pub wire_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VerifiedRevocationManifest {
    pub version: u8,
    pub pin: String,
    pub seq_num: u64,
    pub revoked_device_ids: Vec<String>,
}

/// Construye y firma un DeviceCert de 169B (idéntico a `backend/src/infra/deviceCert.ts`).
pub fn build_and_sign_device_cert(
    pin: &str,
    pk_root: &[u8; 32],
    device_id: &[u8; 16],
    pk_dev: &[u8; 32],
    issued_at_sec: u64,
    expires_at_sec: u64,
    sk_root: &[u8; 32],
) -> Result<[u8; DEVICE_CERT_LEN], CoreError> {
    validate_crockford_pin(pin)?;
    if !is_uuid_v4_bytes(device_id) {
        return Err(CoreError::InvalidBinary("device_id no es UUIDv4".into()));
    }
    if expires_at_sec <= issued_at_sec {
        return Err(CoreError::InvalidBinary("expires_at debe ser > issued_at".into()));
    }

    let mut out = [0u8; DEVICE_CERT_LEN];
    out[0] = DEVICE_CERT_VERSION;
    out[1..9].copy_from_slice(pin.as_bytes());
    out[9..41].copy_from_slice(pk_root);
    out[41..57].copy_from_slice(device_id);
    out[57..89].copy_from_slice(pk_dev);
    out[89..97].copy_from_slice(&issued_at_sec.to_be_bytes());
    out[97..105].copy_from_slice(&expires_at_sec.to_be_bytes());

    let mut msg = Vec::with_capacity(DOMAIN_DEVICECERT.len() + 105);
    msg.extend_from_slice(DOMAIN_DEVICECERT);
    msg.extend_from_slice(&out[0..105]);
    let sig = SigningKey::from_bytes(sk_root).sign(&msg).to_bytes();
    out[105..DEVICE_CERT_LEN].copy_from_slice(&sig);

    Ok(out)
}

/// Construye y firma un KeyPackageGrant de 121B (idéntico a `backend/src/infra/keyPackageGrant.ts`).
pub fn build_and_sign_keypackage_grant(
    grant_id: &[u8; 16],
    target_pin: &str,
    requester_pin: &str,
    signer_device_id: &[u8; 16],
    expires_at_sec: u64,
    sk_dev: &[u8; 32],
) -> Result<[u8; KP_GRANT_LEN], CoreError> {
    validate_crockford_pin(target_pin)?;
    validate_crockford_pin(requester_pin)?;
    if !is_uuid_v4_bytes(grant_id) || !is_uuid_v4_bytes(signer_device_id) {
        return Err(CoreError::InvalidBinary("grant_id o signer_device_id no es UUIDv4".into()));
    }

    let mut out = [0u8; KP_GRANT_LEN];
    out[0] = KP_GRANT_VERSION;
    out[1..17].copy_from_slice(grant_id);
    out[17..25].copy_from_slice(target_pin.as_bytes());
    out[25..33].copy_from_slice(requester_pin.as_bytes());
    out[33..49].copy_from_slice(signer_device_id);
    out[49..57].copy_from_slice(&expires_at_sec.to_be_bytes());

    let mut msg = Vec::with_capacity(DOMAIN_KPGRANT.len() + 57);
    msg.extend_from_slice(DOMAIN_KPGRANT);
    msg.extend_from_slice(&out[0..57]);
    let sig = SigningKey::from_bytes(sk_dev).sign(&msg).to_bytes();
    out[57..KP_GRANT_LEN].copy_from_slice(&sig);

    Ok(out)
}

/// Construye y firma un manifiesto acumulativo `revmanifest-v1` (ordena y deduplica UUIDs).
pub fn build_and_sign_revocation_manifest(
    pin: &str,
    seq_num: u64,
    device_ids: &[[u8; 16]],
    sk_root: &[u8; 32],
) -> Result<SignedRevocationManifest, CoreError> {
    validate_crockford_pin(pin)?;
    if seq_num == 0 {
        return Err(CoreError::InvalidBinary("seq_num debe ser > 0".into()));
    }
    if device_ids.is_empty() {
        return Err(CoreError::InvalidBinary("lista de dispositivos vacía".into()));
    }

    let mut sorted: Vec<[u8; 16]> = Vec::with_capacity(device_ids.len());
    for id in device_ids {
        if !is_uuid_v4_bytes(id) {
            return Err(CoreError::InvalidBinary("UUID no v4 en manifiesto".into()));
        }
        sorted.push(*id);
    }
    sorted.sort();
    sorted.dedup();

    if sorted.len() > MAX_REVOKED_DEVICES {
        return Err(CoreError::InvalidBinary("excede MAX_REVOKED_DEVICES".into()));
    }

    let mut manifest_raw = Vec::with_capacity(19 + sorted.len() * 16);
    manifest_raw.push(REV_MANIFEST_VERSION);
    manifest_raw.extend_from_slice(pin.as_bytes());
    manifest_raw.extend_from_slice(&seq_num.to_be_bytes());
    manifest_raw.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for id in &sorted {
        manifest_raw.extend_from_slice(id);
    }

    let mut msg = Vec::with_capacity(DOMAIN_REVMANIFEST.len() + manifest_raw.len());
    msg.extend_from_slice(DOMAIN_REVMANIFEST);
    msg.extend_from_slice(&manifest_raw);
    let sig_root = SigningKey::from_bytes(sk_root).sign(&msg).to_bytes();

    let mut wire_bytes = Vec::with_capacity(manifest_raw.len() + 64);
    wire_bytes.extend_from_slice(&manifest_raw);
    wire_bytes.extend_from_slice(&sig_root);

    Ok(SignedRevocationManifest {
        pin: pin.to_string(),
        seq_num,
        manifest_raw,
        sig_root,
        wire_bytes,
    })
}

pub fn parse_and_verify_revocation_manifest(
    wire: &[u8],
    expected_pin: &str,
    pk_root: &[u8; 32],
) -> Result<VerifiedRevocationManifest, CoreError> {
    validate_crockford_pin(expected_pin)?;
    if wire.len() < 19 + 16 + 64 {
        return Err(CoreError::InvalidBinary("manifiesto demasiado corto".into()));
    }

    let split_at = wire.len() - 64;
    let manifest_raw = &wire[..split_at];
    let sig_bytes: [u8; 64] = wire[split_at..]
        .try_into()
        .map_err(|_| CoreError::InvalidBinary("firma inválida".into()))?;

    let version = manifest_raw[0];
    if version != REV_MANIFEST_VERSION {
        return Err(CoreError::InvalidBinary("versión de manifiesto no soportada".into()));
    }

    let pin = std::str::from_utf8(&manifest_raw[1..9])
        .map_err(|_| CoreError::InvalidBinary("PIN no UTF-8".into()))?;
    if pin != expected_pin {
        return Err(CoreError::InvalidBinary("PIN de manifiesto no coincide".into()));
    }

    let seq_num = u64::from_be_bytes(manifest_raw[9..17].try_into().unwrap());
    if seq_num == 0 {
        return Err(CoreError::InvalidBinary("seq_num == 0".into()));
    }

    let count = u16::from_be_bytes(manifest_raw[17..19].try_into().unwrap()) as usize;
    if count == 0 || count > MAX_REVOKED_DEVICES || manifest_raw.len() != 19 + count * 16 {
        return Err(CoreError::InvalidBinary("count o longitud de manifiesto inválida".into()));
    }

    let mut revoked_device_ids = Vec::with_capacity(count);
    let mut prev: Option<[u8; 16]> = None;
    for i in 0..count {
        let start = 19 + i * 16;
        let uuid_b: [u8; 16] = manifest_raw[start..start + 16].try_into().unwrap();
        if !is_uuid_v4_bytes(&uuid_b) {
            return Err(CoreError::InvalidBinary("UUID no v4 en manifiesto".into()));
        }
        if let Some(p) = prev {
            if uuid_b <= p {
                return Err(CoreError::InvalidBinary("UUIDs desordenados o duplicados".into()));
            }
        }
        prev = Some(uuid_b);
        revoked_device_ids.push(Uuid::from_bytes(uuid_b).to_string());
    }

    let mut msg = Vec::with_capacity(DOMAIN_REVMANIFEST.len() + manifest_raw.len());
    msg.extend_from_slice(DOMAIN_REVMANIFEST);
    msg.extend_from_slice(manifest_raw);
    let vk = VerifyingKey::from_bytes(pk_root).map_err(|e| CoreError::Crypto(e.to_string()))?;
    vk.verify(&msg, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| CoreError::Crypto("firma revmanifest-v1 inválida".into()))?;

    Ok(VerifiedRevocationManifest {
        version,
        pin: pin.to_string(),
        seq_num,
        revoked_device_ids,
    })
}
