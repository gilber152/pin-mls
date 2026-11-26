use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{random_bytes, CoreError};

const CROCKFORD_CHARS: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DOMAIN_INVITE_KEY: &[u8] = b"pin-invite-key-v1";
const DOMAIN_REGISTER_POP: &[u8] = b"pin-register-pop-v1";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootIdentity {
    pub sk_root: [u8; 32],
    pub pk_root: [u8; 32],
    pub sk_invite: [u8; 32],
    pub pk_invite: [u8; 32],
    pub sig_invite: [u8; 64],
    pub proof_of_possession: [u8; 64],
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DeviceKeyPair {
    pub sk_dev: [u8; 32],
    pub pk_dev: [u8; 32],
}

pub fn validate_crockford_pin(pin: &str) -> Result<(), CoreError> {
    let bytes = pin.as_bytes();
    if bytes.len() != 8 || !bytes.iter().all(|b| CROCKFORD_CHARS.contains(b)) {
        return Err(CoreError::InvalidPin(pin.to_string()));
    }
    Ok(())
}

pub fn generate_mnemonic_12_words() -> Result<String, CoreError> {
    let entropy = random_bytes::<16>()?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| CoreError::InvalidMnemonic(e.to_string()))?;
    Ok(mnemonic.to_string())
}

pub fn derive_seed_from_mnemonic(phrase: &str) -> Result<[u8; 64], CoreError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|e| CoreError::InvalidMnemonic(e.to_string()))?;
    Ok(mnemonic.to_seed(""))
}

pub fn derive_root_from_mnemonic(phrase: &str) -> Result<RootIdentity, CoreError> {
    let mut seed = derive_seed_from_mnemonic(phrase)?;
    let hk = Hkdf::<Sha256>::new(Some(b"pin-mls-v1-root"), &seed);

    let mut sk_root = [0u8; 32];
    hk.expand(b"ed25519-root-v1", &mut sk_root)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let mut sk_invite = [0u8; 32];
    hk.expand(b"x25519-invite-v1", &mut sk_invite)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    seed.zeroize();

    let signing_key = SigningKey::from_bytes(&sk_root);
    let pk_root = signing_key.verifying_key().to_bytes();

    let invite_secret = X25519Secret::from(sk_invite);
    let pk_invite = X25519PublicKey::from(&invite_secret).to_bytes();

    let mut invite_msg = Vec::with_capacity(DOMAIN_INVITE_KEY.len() + 32);
    invite_msg.extend_from_slice(DOMAIN_INVITE_KEY);
    invite_msg.extend_from_slice(&pk_invite);
    let sig_invite = signing_key.sign(&invite_msg).to_bytes();

    let mut pop_msg = Vec::with_capacity(DOMAIN_REGISTER_POP.len() + 64);
    pop_msg.extend_from_slice(DOMAIN_REGISTER_POP);
    pop_msg.extend_from_slice(&pk_root);
    pop_msg.extend_from_slice(&pk_invite);
    let proof_of_possession = signing_key.sign(&pop_msg).to_bytes();

    Ok(RootIdentity {
        sk_root,
        pk_root,
        sk_invite,
        pk_invite,
        sig_invite,
        proof_of_possession,
    })
}

pub fn generate_device_keypair() -> Result<DeviceKeyPair, CoreError> {
    let sk_dev = random_bytes::<32>()?;
    let pk_dev = SigningKey::from_bytes(&sk_dev).verifying_key().to_bytes();
    Ok(DeviceKeyPair { sk_dev, pk_dev })
}

pub fn verify_invite_key_binding(
    pk_root: &[u8; 32],
    pk_invite: &[u8; 32],
    sig_invite: &[u8; 64],
) -> Result<(), CoreError> {
    let vk = VerifyingKey::from_bytes(pk_root).map_err(|e| CoreError::Crypto(e.to_string()))?;
    let mut msg = Vec::with_capacity(DOMAIN_INVITE_KEY.len() + 32);
    msg.extend_from_slice(DOMAIN_INVITE_KEY);
    msg.extend_from_slice(pk_invite);
    let sig = Signature::from_bytes(sig_invite);
    vk.verify(&msg, &sig)
        .map_err(|_| CoreError::Crypto("sig_invite inválida contra pk_root".into()))
}
