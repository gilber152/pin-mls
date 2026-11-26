use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::{is_uuid_v4_bytes, random_bytes, CoreError};

const KP_VERSION: u8 = 1;
const KP_LEN: usize = 145; // 1B ver + 16B dev_id + 32B pk_dev + 32B pk_kp_x25519 + 64B sig_dev
const DOMAIN_KP: &[u8] = b"pin-kp-v1";
const DOMAIN_WELCOME: &[u8] = b"pin-welcome-v1";
const DOMAIN_GROUP_MSG: &[u8] = b"pin-group-msg-v1";
const DOMAIN_GROUP_COMMIT: &[u8] = b"pin-group-commit-v1";
const WELCOME_MULTI_MAGIC: &[u8] = b"PINW2:";

#[derive(Debug, Clone)]
pub struct GeneratedKeyPackage {
    pub kp_ref: [u8; 32],
    pub kp_raw: Vec<u8>,
    pub sk_kp_x25519: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ParsedKeyPackage {
    pub device_id: String,
    pub pk_dev: [u8; 32],
    pub pk_kp_x25519: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomePayload {
    pub group_id_b64: String,
    pub epoch: u64,
    pub epoch_secret_hex: String,
    pub creator_pin: String,
    pub peer_pin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MultiWelcomeEntry {
    pk_kp_hex: String,
    box_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MultiWelcomeEnvelope {
    entries: Vec<MultiWelcomeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitPayload {
    pub new_epoch: u64,
    pub new_epoch_secret_hex: String,
    pub action: String,
    pub target_device_id: Option<String>,
}

/// Genera un KeyPackage autenticado con `SK_dev` y clave efímera X25519 para recibir Welcomes.
pub fn generate_signed_key_package(
    device_id: &[u8; 16],
    pk_dev: &[u8; 32],
    sk_dev: &[u8; 32],
) -> Result<GeneratedKeyPackage, CoreError> {
    if !is_uuid_v4_bytes(device_id) {
        return Err(CoreError::InvalidBinary("device_id no es UUIDv4".into()));
    }
    let sk_kp_x25519 = random_bytes::<32>()?;
    let pk_kp = X25519PublicKey::from(&X25519Secret::from(sk_kp_x25519)).to_bytes();

    let mut kp_raw = vec![0u8; KP_LEN];
    kp_raw[0] = KP_VERSION;
    kp_raw[1..17].copy_from_slice(device_id);
    kp_raw[17..49].copy_from_slice(pk_dev);
    kp_raw[49..81].copy_from_slice(&pk_kp);

    let mut msg = Vec::with_capacity(DOMAIN_KP.len() + 81);
    msg.extend_from_slice(DOMAIN_KP);
    msg.extend_from_slice(&kp_raw[0..81]);
    let sig = SigningKey::from_bytes(sk_dev).sign(&msg).to_bytes();
    kp_raw[81..KP_LEN].copy_from_slice(&sig);

    let kp_ref: [u8; 32] = Sha256::digest(&kp_raw).into();
    Ok(GeneratedKeyPackage {
        kp_ref,
        kp_raw,
        sk_kp_x25519,
    })
}

pub fn parse_and_verify_key_package(kp_raw: &[u8]) -> Result<ParsedKeyPackage, CoreError> {
    if kp_raw.len() != KP_LEN || kp_raw[0] != KP_VERSION {
        return Err(CoreError::InvalidBinary("KeyPackage malformado".into()));
    }
    let dev_bytes: [u8; 16] = kp_raw[1..17].try_into().unwrap();
    let pk_dev: [u8; 32] = kp_raw[17..49].try_into().unwrap();
    let pk_kp_x25519: [u8; 32] = kp_raw[49..81].try_into().unwrap();
    let sig_bytes: [u8; 64] = kp_raw[81..KP_LEN].try_into().unwrap();

    let mut msg = Vec::with_capacity(DOMAIN_KP.len() + 81);
    msg.extend_from_slice(DOMAIN_KP);
    msg.extend_from_slice(&kp_raw[0..81]);

    let vk = VerifyingKey::from_bytes(&pk_dev).map_err(|e| CoreError::Crypto(e.to_string()))?;
    vk.verify(&msg, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| CoreError::Crypto("firma de KeyPackage inválida".into()))?;

    Ok(ParsedKeyPackage {
        device_id: Uuid::from_bytes(dev_bytes).to_string(),
        pk_dev,
        pk_kp_x25519,
    })
}

/// Cifra un Welcome dirigido a 1 destinatario: [eph_pk:32][nonce:24][ct+tag].
pub fn seal_group_welcome(
    recipient_pk_kp_x25519: &[u8; 32],
    group_id: &[u8; 32],
    welcome: &WelcomePayload,
) -> Result<Vec<u8>, CoreError> {
    let mut eph_sk_bytes = random_bytes::<32>()?;
    let eph_sk = X25519Secret::from(eph_sk_bytes);
    let eph_pk = X25519PublicKey::from(&eph_sk).to_bytes();
    let shared = eph_sk.diffie_hellman(&X25519PublicKey::from(*recipient_pk_kp_x25519));
    eph_sk_bytes.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(&eph_pk), shared.as_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(DOMAIN_WELCOME, &mut aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let plain = serde_json::to_vec(welcome).map_err(|e| CoreError::Crypto(e.to_string()))?;
    let nonce_bytes = random_bytes::<24>()?;

    let mut aad = Vec::with_capacity(DOMAIN_WELCOME.len() + 64);
    aad.extend_from_slice(DOMAIN_WELCOME);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(recipient_pk_kp_x25519);

    let cipher = XChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::Crypto("fallo cifrando Welcome".into()))?;
    aead_key.zeroize();

    let mut wire = Vec::with_capacity(32 + 24 + ct.len());
    wire.extend_from_slice(&eph_pk);
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ct);
    Ok(wire)
}

/// Cifra un Welcome multi-destinatario (`PINW2:...`) para añadir 1 o N dispositivos en un solo Commit.
pub fn seal_group_welcome_multi(
    recipient_pks_kp_x25519: &[[u8; 32]],
    group_id: &[u8; 32],
    welcome: &WelcomePayload,
) -> Result<Vec<u8>, CoreError> {
    if recipient_pks_kp_x25519.is_empty() {
        return Err(CoreError::Crypto("lista de destinatarios Welcome vacía".into()));
    }
    if recipient_pks_kp_x25519.len() == 1 {
        return seal_group_welcome(&recipient_pks_kp_x25519[0], group_id, welcome);
    }

    let mut entries = Vec::with_capacity(recipient_pks_kp_x25519.len());
    for pk in recipient_pks_kp_x25519 {
        let single = seal_group_welcome(pk, group_id, welcome)?;
        entries.push(MultiWelcomeEntry {
            pk_kp_hex: hex::encode(pk),
            box_b64: STANDARD.encode(single),
        });
    }

    let json = serde_json::to_vec(&MultiWelcomeEnvelope { entries })
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let mut wire = Vec::with_capacity(WELCOME_MULTI_MAGIC.len() + json.len());
    wire.extend_from_slice(WELCOME_MULTI_MAGIC);
    wire.extend_from_slice(&json);
    Ok(wire)
}

fn open_single_welcome_box(
    sk_kp_x25519: &[u8; 32],
    group_id: &[u8; 32],
    wire: &[u8],
) -> Result<WelcomePayload, CoreError> {
    if wire.len() < 32 + 24 + 16 {
        return Err(CoreError::Crypto("Welcome truncado".into()));
    }
    let eph_pk: [u8; 32] = wire[0..32].try_into().unwrap();
    let nonce_bytes = &wire[32..56];
    let ct = &wire[56..];

    let sk = X25519Secret::from(*sk_kp_x25519);
    let my_pk = X25519PublicKey::from(&sk).to_bytes();
    let shared = sk.diffie_hellman(&X25519PublicKey::from(eph_pk));

    let hk = Hkdf::<Sha256>::new(Some(&eph_pk), shared.as_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(DOMAIN_WELCOME, &mut aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let mut aad = Vec::with_capacity(DOMAIN_WELCOME.len() + 64);
    aad.extend_from_slice(DOMAIN_WELCOME);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(&my_pk);

    let cipher = XChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce_bytes), Payload { msg: ct, aad: &aad })
        .map_err(|_| CoreError::Crypto("fallo descifrando Welcome".into()))?;
    aead_key.zeroize();

    serde_json::from_slice(&plain).map_err(|e| CoreError::Crypto(e.to_string()))
}

pub fn open_group_welcome(
    sk_kp_x25519: &[u8; 32],
    group_id: &[u8; 32],
    wire: &[u8],
) -> Result<WelcomePayload, CoreError> {
    if let Some(json_part) = wire.strip_prefix(WELCOME_MULTI_MAGIC) {
        let env: MultiWelcomeEnvelope =
            serde_json::from_slice(json_part).map_err(|e| CoreError::Crypto(e.to_string()))?;
        let my_pk = X25519PublicKey::from(&X25519Secret::from(*sk_kp_x25519)).to_bytes();
        let my_pk_hex = hex::encode(my_pk);
        let entry = env
            .entries
            .iter()
            .find(|e| e.pk_kp_hex == my_pk_hex)
            .ok_or_else(|| CoreError::Crypto("este dispositivo no está en el Welcome PINW2".into()))?;
        let single_box = STANDARD
            .decode(&entry.box_b64)
            .map_err(|e| CoreError::Crypto(e.to_string()))?;
        return open_single_welcome_box(sk_kp_x25519, group_id, &single_box);
    }

    open_single_welcome_box(sk_kp_x25519, group_id, wire)
}

fn derive_epoch_key(
    domain: &[u8],
    epoch_secret: &[u8; 32],
    group_id: &[u8; 32],
    epoch: u64,
) -> Result<[u8; 32], CoreError> {
    let hk = Hkdf::<Sha256>::new(Some(group_id), epoch_secret);
    let mut info = Vec::with_capacity(domain.len() + 8);
    info.extend_from_slice(domain);
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    Ok(key)
}

pub fn encrypt_group_message(
    epoch_secret: &[u8; 32],
    group_id: &[u8; 32],
    epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut key = derive_epoch_key(DOMAIN_GROUP_MSG, epoch_secret, group_id, epoch)?;
    let nonce_bytes = random_bytes::<24>()?;

    let mut aad = Vec::with_capacity(DOMAIN_GROUP_MSG.len() + 40);
    aad.extend_from_slice(DOMAIN_GROUP_MSG);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(&epoch.to_be_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::Crypto("fallo cifrando mensaje de grupo".into()))?;
    key.zeroize();

    let mut wire = Vec::with_capacity(24 + ct.len());
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ct);
    Ok(wire)
}

pub fn decrypt_group_message(
    epoch_secret: &[u8; 32],
    group_id: &[u8; 32],
    epoch: u64,
    wire: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if wire.len() < 24 + 16 {
        return Err(CoreError::Crypto("mensaje cifrado truncado".into()));
    }
    let nonce_bytes = &wire[0..24];
    let ct = &wire[24..];

    let mut key = derive_epoch_key(DOMAIN_GROUP_MSG, epoch_secret, group_id, epoch)?;
    let mut aad = Vec::with_capacity(DOMAIN_GROUP_MSG.len() + 40);
    aad.extend_from_slice(DOMAIN_GROUP_MSG);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(&epoch.to_be_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce_bytes), Payload { msg: ct, aad: &aad })
        .map_err(|_| CoreError::Crypto("fallo descifrando mensaje de grupo".into()))?;
    key.zeroize();
    Ok(plain)
}

/// Cifra un Commit de transición de época (`base_epoch` -> `base_epoch + 1`) para miembros actuales.
pub fn encrypt_group_commit(
    current_epoch_secret: &[u8; 32],
    group_id: &[u8; 32],
    base_epoch: u64,
    commit: &CommitPayload,
) -> Result<Vec<u8>, CoreError> {
    let mut key = derive_epoch_key(DOMAIN_GROUP_COMMIT, current_epoch_secret, group_id, base_epoch)?;
    let nonce_bytes = random_bytes::<24>()?;
    let plain = serde_json::to_vec(commit).map_err(|e| CoreError::Crypto(e.to_string()))?;

    let mut aad = Vec::with_capacity(DOMAIN_GROUP_COMMIT.len() + 40);
    aad.extend_from_slice(DOMAIN_GROUP_COMMIT);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(&base_epoch.to_be_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::Crypto("fallo cifrando Commit".into()))?;
    key.zeroize();

    let mut wire = Vec::with_capacity(24 + ct.len());
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ct);
    Ok(wire)
}

pub fn decrypt_group_commit(
    current_epoch_secret: &[u8; 32],
    group_id: &[u8; 32],
    base_epoch: u64,
    wire: &[u8],
) -> Result<CommitPayload, CoreError> {
    if wire.len() < 24 + 16 {
        return Err(CoreError::Crypto("Commit cifrado truncado".into()));
    }
    let nonce_bytes = &wire[0..24];
    let ct = &wire[24..];

    let mut key = derive_epoch_key(DOMAIN_GROUP_COMMIT, current_epoch_secret, group_id, base_epoch)?;
    let mut aad = Vec::with_capacity(DOMAIN_GROUP_COMMIT.len() + 40);
    aad.extend_from_slice(DOMAIN_GROUP_COMMIT);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(&base_epoch.to_be_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce_bytes), Payload { msg: ct, aad: &aad })
        .map_err(|_| CoreError::Crypto("fallo descifrando Commit".into()))?;
    key.zeroize();

    let payload: CommitPayload =
        serde_json::from_slice(&plain).map_err(|e| CoreError::Crypto(e.to_string()))?;
    if payload.new_epoch != base_epoch + 1 {
        return Err(CoreError::Crypto("new_epoch inconsistente en Commit".into()));
    }
    Ok(payload)
}
