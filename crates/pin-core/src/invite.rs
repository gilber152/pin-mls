use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::{random_bytes, CoreError};

const INVITE_AAD_PREFIX: &[u8] = b"pin-invite-box-v1";

/// Sella un sobre de invitación cifrado (X25519 efímero + HKDF-SHA256 + XChaCha20-Poly1305):
///   wire = [ephemeral_pk:32][nonce:24][ciphertext+tag]
pub fn seal_invite_box(
    recipient_pk_invite: &[u8; 32],
    target_pin: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut eph_sk_bytes = random_bytes::<32>()?;
    let eph_sk = X25519Secret::from(eph_sk_bytes);
    let eph_pk = X25519PublicKey::from(&eph_sk).to_bytes();
    let shared = eph_sk.diffie_hellman(&X25519PublicKey::from(*recipient_pk_invite));
    eph_sk_bytes.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(&eph_pk), shared.as_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(b"pin-invite-xchacha-v1", &mut aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let nonce_bytes = random_bytes::<24>()?;
    let mut aad = Vec::with_capacity(INVITE_AAD_PREFIX.len() + target_pin.len() + 32);
    aad.extend_from_slice(INVITE_AAD_PREFIX);
    aad.extend_from_slice(target_pin.as_bytes());
    aad.extend_from_slice(recipient_pk_invite);

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
        .map_err(|_| CoreError::Crypto("fallo cifrando invitación".into()))?;
    aead_key.zeroize();

    let mut out = Vec::with_capacity(32 + 24 + ct.len());
    out.extend_from_slice(&eph_pk);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_invite_box(
    recipient_sk_invite: &[u8; 32],
    recipient_pk_invite: &[u8; 32],
    my_pin: &str,
    wire: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if wire.len() < 32 + 24 + 16 {
        return Err(CoreError::Crypto("sobre de invitación truncado".into()));
    }
    let eph_pk: [u8; 32] = wire[0..32].try_into().unwrap();
    let nonce_bytes = &wire[32..56];
    let ct = &wire[56..];

    let sk = X25519Secret::from(*recipient_sk_invite);
    let shared = sk.diffie_hellman(&X25519PublicKey::from(eph_pk));

    let hk = Hkdf::<Sha256>::new(Some(&eph_pk), shared.as_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(b"pin-invite-xchacha-v1", &mut aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let mut aad = Vec::with_capacity(INVITE_AAD_PREFIX.len() + my_pin.len() + 32);
    aad.extend_from_slice(INVITE_AAD_PREFIX);
    aad.extend_from_slice(my_pin.as_bytes());
    aad.extend_from_slice(recipient_pk_invite);

    let cipher = XChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce_bytes), Payload { msg: ct, aad: &aad })
        .map_err(|_| CoreError::Crypto("fallo descifrando invitación".into()))?;
    aead_key.zeroize();
    Ok(plain)
}
