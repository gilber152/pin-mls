import { createHash, createHmac, createPublicKey, verify } from 'node:crypto';

// Prefijo DER SPKI estándar para clave pública Ed25519 cruda de 32 bytes (RFC 8410)
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function sha256(data: Uint8Array): Buffer {
  return createHash('sha256').update(data).digest();
}

export function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

export function verifyEd25519(
  publicKey32: Uint8Array,
  message: Uint8Array,
  signature64: Uint8Array,
): boolean {
  if (publicKey32.byteLength !== 32 || signature64.byteLength !== 64) {
    return false;
  }
  try {
    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey32)]);
    const keyObj = createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    return verify(null, message, keyObj, signature64);
  } catch {
    return false;
  }
}
