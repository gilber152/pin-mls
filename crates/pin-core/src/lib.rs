pub mod auth;
pub mod cert;
pub mod group_e2ee;
pub mod identity;
pub mod invite;
pub mod mls_engine;
pub mod pow;
pub mod qr;
pub mod safe;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("mnemónico BIP-39 inválido: {0}")]
    InvalidMnemonic(String),
    #[error("PIN Crockford inválido: {0}")]
    InvalidPin(String),
    #[error("certificado o manifiesto inválido: {0}")]
    InvalidBinary(String),
    #[error("error criptográfico: {0}")]
    Crypto(String),
    #[error("QR inválido: {0}")]
    InvalidQr(String),
    #[error("PoW inválido: {0}")]
    Pow(String),
    #[error("Safe Backup inválido: {0}")]
    Safe(String),
    #[error("error MLS: {0}")]
    Mls(String),
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], CoreError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| CoreError::Crypto(e.to_string()))?;
    Ok(buf)
}

pub fn is_uuid_v4_bytes(b: &[u8; 16]) -> bool {
    (b[6] & 0xf0) == 0x40 && (b[8] & 0xc0) == 0x80
}
