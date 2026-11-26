use argon2::{Algorithm, Argon2, Params, Version};

use crate::CoreError;

pub const POW_MEMORY_KIB: u32 = 16_384;
pub const POW_TIME_COST: u32 = 2; // Alineado con argon2 ^0.41.1 en backend/src/infra/pow.ts
pub const POW_PARALLELISM: u32 = 1;
pub const POW_HASH_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct PowSolution {
    pub nonce: [u8; 8],
    pub hash: [u8; 32],
    pub attempts: u64,
}

pub fn count_leading_zero_bits(buf: &[u8]) -> u8 {
    let mut zeros: u32 = 0;
    for &b in buf {
        if b == 0 {
            zeros += 8;
        } else {
            zeros += b.leading_zeros();
            break;
        }
    }
    zeros.min(255) as u8
}

pub fn argon2id_pow_hash(
    challenge_payload_raw: &[u8],
    challenge_id_16: &[u8; 16],
    subject_bytes: &[u8],
    nonce: &[u8; 8],
) -> Result<[u8; 32], CoreError> {
    let params = Params::new(POW_MEMORY_KIB, POW_TIME_COST, POW_PARALLELISM, Some(POW_HASH_LEN))
        .map_err(|e| CoreError::Pow(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut input = Vec::with_capacity(challenge_payload_raw.len() + subject_bytes.len() + 8);
    input.extend_from_slice(challenge_payload_raw);
    input.extend_from_slice(subject_bytes);
    input.extend_from_slice(nonce);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(&input, challenge_id_16, &mut out)
        .map_err(|e| CoreError::Pow(e.to_string()))?;
    Ok(out)
}

pub fn solve_argon2id(
    challenge_payload_raw: &[u8],
    challenge_id_16: &[u8; 16],
    subject_bytes: &[u8],
    difficulty_bits: u8,
) -> Result<PowSolution, CoreError> {
    if difficulty_bits > 28 {
        return Err(CoreError::Pow("difficulty_bits demasiado alta".into()));
    }
    for counter in 0u64..1_000_000u64 {
        let nonce = counter.to_be_bytes();
        let hash = argon2id_pow_hash(challenge_payload_raw, challenge_id_16, subject_bytes, &nonce)?;
        if count_leading_zero_bits(&hash) >= difficulty_bits {
            return Ok(PowSolution {
                nonce,
                hash,
                attempts: counter + 1,
            });
        }
    }
    Err(CoreError::Pow("límite de intentos PoW excedido".into()))
}
