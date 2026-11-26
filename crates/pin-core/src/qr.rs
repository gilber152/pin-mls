use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::{is_uuid_v4_bytes, random_bytes, CoreError};

const LINK_SESSION_DOMAIN: &[u8] = b"pin-link-session-v1";
const LINK_BUNDLE_DOMAIN: &[u8] = b"pin-link-bundle-v1";
const LINK_QR_PREFIX: &str = "pinapp://v1/link?";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkQr {
    pub session_id_32: [u8; 32],
    pub device_id: [u8; 16],
    pub pk_dev_32: [u8; 32],
    pub pk_link_eph_32: [u8; 32],
}

pub fn derive_link_session_id(read_secret_32: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LINK_SESSION_DOMAIN);
    hasher.update(read_secret_32);
    hasher.finalize().into()
}

pub fn encode_link_qr(qr: &LinkQr) -> String {
    format!(
        "{LINK_QR_PREFIX}s={}&d={}&pk={}&ek={}",
        URL_SAFE_NO_PAD.encode(qr.session_id_32),
        URL_SAFE_NO_PAD.encode(qr.device_id),
        URL_SAFE_NO_PAD.encode(qr.pk_dev_32),
        URL_SAFE_NO_PAD.encode(qr.pk_link_eph_32),
    )
}

pub fn parse_link_qr(uri: &str) -> Result<LinkQr, CoreError> {
    let query = uri
        .trim()
        .strip_prefix(LINK_QR_PREFIX)
        .ok_or_else(|| CoreError::InvalidQr("prefijo debe ser pinapp://v1/link?".into()))?;

    let mut s_val: Option<&str> = None;
    let mut d_val: Option<&str> = None;
    let mut pk_val: Option<&str> = None;
    let mut ek_val: Option<&str> = None;

    for pair in query.split('&') {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| CoreError::InvalidQr("parámetro malformado".into()))?;
        match k {
            "s" => s_val = Some(v),
            "d" => d_val = Some(v),
            "pk" => pk_val = Some(v),
            "ek" => ek_val = Some(v),
            _ => {}
        }
    }

    let dec32 = |raw: Option<&str>, name: &str| -> Result<[u8; 32], CoreError> {
        let txt = raw.ok_or_else(|| CoreError::InvalidQr(format!("falta {name}")))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(txt)
            .map_err(|_| CoreError::InvalidQr(format!("{name} base64url inválido")))?;
        bytes
            .try_into()
            .map_err(|_| CoreError::InvalidQr(format!("{name} debe medir 32B")))
    };

    let d_txt = d_val.ok_or_else(|| CoreError::InvalidQr("falta d".into()))?;
    let device_id: [u8; 16] = URL_SAFE_NO_PAD
        .decode(d_txt)
        .map_err(|_| CoreError::InvalidQr("d base64url inválido".into()))?
        .try_into()
        .map_err(|_| CoreError::InvalidQr("d debe medir 16B".into()))?;

    if !is_uuid_v4_bytes(&device_id) {
        return Err(CoreError::InvalidQr("device_id no es UUIDv4".into()));
    }

    Ok(LinkQr {
        session_id_32: dec32(s_val, "s")?,
        device_id,
        pk_dev_32: dec32(pk_val, "pk")?,
        pk_link_eph_32: dec32(ek_val, "ek")?,
    })
}

/// Cifra el LinkBundle para el dispositivo secundario usando su `pk_link_eph_32` (X25519 + XChaCha20-Poly1305).
/// Wire: [eph_pk:32][nonce:24][ciphertext+tag]
pub fn seal_link_bundle(
    recipient_pk_link_eph: &[u8; 32],
    session_id_32: &[u8; 32],
    device_id: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut eph_sk_bytes = random_bytes::<32>()?;
    let eph_sk = X25519Secret::from(eph_sk_bytes);
    let eph_pk = X25519PublicKey::from(&eph_sk).to_bytes();
    let shared = eph_sk.diffie_hellman(&X25519PublicKey::from(*recipient_pk_link_eph));
    eph_sk_bytes.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(&eph_pk), shared.as_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(LINK_BUNDLE_DOMAIN, &mut aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let nonce_bytes = random_bytes::<24>()?;
    let mut aad = Vec::with_capacity(LINK_BUNDLE_DOMAIN.len() + 32 + 16 + 32);
    aad.extend_from_slice(LINK_BUNDLE_DOMAIN);
    aad.extend_from_slice(session_id_32);
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(recipient_pk_link_eph);

    let cipher = XChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::Crypto("fallo cifrando LinkBundle".into()))?;
    aead_key.zeroize();

    let mut wire = Vec::with_capacity(32 + 24 + ct.len());
    wire.extend_from_slice(&eph_pk);
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ct);
    Ok(wire)
}

pub fn open_link_bundle(
    sk_link_eph: &[u8; 32],
    session_id_32: &[u8; 32],
    device_id: &[u8; 16],
    wire: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if wire.len() < 32 + 24 + 16 {
        return Err(CoreError::Crypto("LinkBundle truncado".into()));
    }
    let eph_pk: [u8; 32] = wire[0..32].try_into().unwrap();
    let nonce_bytes = &wire[32..56];
    let ct = &wire[56..];

    let sk = X25519Secret::from(*sk_link_eph);
    let my_pk = X25519PublicKey::from(&sk).to_bytes();
    let shared = sk.diffie_hellman(&X25519PublicKey::from(eph_pk));

    let hk = Hkdf::<Sha256>::new(Some(&eph_pk), shared.as_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(LINK_BUNDLE_DOMAIN, &mut aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let mut aad = Vec::with_capacity(LINK_BUNDLE_DOMAIN.len() + 32 + 16 + 32);
    aad.extend_from_slice(LINK_BUNDLE_DOMAIN);
    aad.extend_from_slice(session_id_32);
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(&my_pk);

    let cipher = XChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce_bytes), Payload { msg: ct, aad: &aad })
        .map_err(|_| CoreError::Crypto("fallo descifrando LinkBundle".into()))?;
    aead_key.zeroize();
    Ok(plain)
}

pub fn generate_link_ephemeral_keypair() -> Result<([u8; 32], [u8; 32]), CoreError> {
    let sk = random_bytes::<32>()?;
    let pk = X25519PublicKey::from(&X25519Secret::from(sk)).to_bytes();
    Ok((sk, pk))
}
