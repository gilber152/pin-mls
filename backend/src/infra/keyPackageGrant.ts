import { verifyEd25519 } from './crypto.js';

export const KP_GRANT_VERSION = 1;
export const KP_GRANT_LEN = 121; // 1 + 16 + 8 + 8 + 16 + 8 + 64
const KP_GRANT_BODY_LEN = 57;
const DOMAIN_KPGRANT = Buffer.from('kpgrant-v1', 'ascii');
const PIN_CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]{8}$/;

export interface ParsedKeyPackageGrant {
  version: number;
  grantId: string;
  targetPin: string;
  requesterPin: string;
  signerDeviceId: string;
  expiresAtSec: number;
  body: Buffer;
  sigDev: Buffer;
}

export class KeyPackageGrantError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'KeyPackageGrantError';
  }
}

function isUuidV4Bytes(b: Uint8Array): boolean {
  return b.byteLength === 16 && (b[6] & 0xf0) === 0x40 && (b[8] & 0xc0) === 0x80;
}

function formatUuidLower(buf: Buffer): string {
  const h = buf.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/**
 * Parsea un KeyPackageGrant de 121 bytes sin verificar firma aún (permite resolver pk_dev en DB):
 *   [ver:1][grant_id:16][target_pin:8][requester_pin:8][signer_device_id:16][expires_at:8 BE][sig_dev:64]
 */
export function parseKeyPackageGrant(raw: Buffer, nowUnixSec: number): ParsedKeyPackageGrant {
  if (raw.length !== KP_GRANT_LEN) {
    throw new KeyPackageGrantError('INVALID_GRANT_LENGTH', `Grant debe medir ${KP_GRANT_LEN} bytes`);
  }
  const version = raw[0];
  if (version !== KP_GRANT_VERSION) {
    throw new KeyPackageGrantError('UNSUPPORTED_GRANT_VERSION', `Versión no soportada: ${version}`);
  }

  const grantIdBytes = raw.subarray(1, 17);
  if (!isUuidV4Bytes(grantIdBytes)) {
    throw new KeyPackageGrantError('INVALID_GRANT_ID', 'grant_id no es UUIDv4 válido');
  }

  const targetPin = raw.subarray(17, 25).toString('ascii');
  const requesterPin = raw.subarray(25, 33).toString('ascii');
  if (!PIN_CROCKFORD_RE.test(targetPin) || !PIN_CROCKFORD_RE.test(requesterPin)) {
    throw new KeyPackageGrantError('INVALID_GRANT_PIN', 'PIN inválido en KeyPackageGrant');
  }

  const signerDeviceBytes = raw.subarray(33, 49);
  if (!isUuidV4Bytes(signerDeviceBytes)) {
    throw new KeyPackageGrantError('INVALID_GRANT_SIGNER_UUID', 'signer_device_id no es UUIDv4');
  }

  const expiresAtSec = Number(raw.readBigUInt64BE(49));
  if (expiresAtSec <= nowUnixSec) {
    throw new KeyPackageGrantError('GRANT_EXPIRED', 'KeyPackageGrant expirado');
  }

  return {
    version,
    grantId: formatUuidLower(grantIdBytes),
    targetPin,
    requesterPin,
    signerDeviceId: formatUuidLower(signerDeviceBytes),
    expiresAtSec,
    body: raw.subarray(0, KP_GRANT_BODY_LEN),
    sigDev: raw.subarray(KP_GRANT_BODY_LEN, KP_GRANT_LEN),
  };
}

export function verifyKeyPackageGrantSignature(
  grant: ParsedKeyPackageGrant,
  signerPkDev32: Uint8Array,
): boolean {
  const signedMsg = Buffer.concat([DOMAIN_KPGRANT, grant.body]);
  return verifyEd25519(signerPkDev32, signedMsg, grant.sigDev);
}
