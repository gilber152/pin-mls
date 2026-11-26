import { verifyEd25519 } from './crypto.js';

export const DEVICE_CERT_VERSION = 1;
export const DEVICE_CERT_LEN = 169; // 1 + 8 + 32 + 16 + 32 + 8 + 8 + 64
const DEVICE_CERT_BODY_LEN = 105;
const DOMAIN_DEVICECERT = Buffer.from('devicecert-v1', 'ascii');
const PIN_CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]{8}$/;

export interface ParsedDeviceCert {
  version: number;
  pin: string;
  pkRoot: Buffer;
  deviceId: string;
  deviceIdBytes: Buffer;
  pkDev: Buffer;
  issuedAtSec: number;
  expiresAtSec: number;
  sigRoot: Buffer;
}

export class DeviceCertError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'DeviceCertError';
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
 * Parsea y verifica criptográficamente un DeviceCert binario de 169 bytes:
 *   [ver:1][pin:8][pk_root:32][device_id:16][pk_dev:32][issued_at:8 BE][expires_at:8 BE][sig_root:64]
 */
export function parseAndVerifyDeviceCert(
  raw: Buffer,
  nowUnixSec: number,
  expectedPin?: string,
  expectedPkRoot?: Uint8Array,
): ParsedDeviceCert {
  if (raw.length !== DEVICE_CERT_LEN) {
    throw new DeviceCertError('INVALID_CERT_LENGTH', `DeviceCert debe medir ${DEVICE_CERT_LEN} bytes`);
  }

  const version = raw[0];
  if (version !== DEVICE_CERT_VERSION) {
    throw new DeviceCertError('UNSUPPORTED_CERT_VERSION', `Versión no soportada: ${version}`);
  }

  const pin = raw.subarray(1, 9).toString('ascii');
  if (!PIN_CROCKFORD_RE.test(pin)) {
    throw new DeviceCertError('INVALID_CERT_PIN', 'PIN inválido en DeviceCert');
  }
  if (expectedPin && pin !== expectedPin) {
    throw new DeviceCertError('CERT_PIN_MISMATCH', 'PIN de DeviceCert no coincide');
  }

  const pkRoot = raw.subarray(9, 41);
  if (expectedPkRoot && Buffer.compare(pkRoot, Buffer.from(expectedPkRoot)) !== 0) {
    throw new DeviceCertError('CERT_PK_ROOT_MISMATCH', 'pk_root de DeviceCert no coincide');
  }

  const deviceIdBytes = raw.subarray(41, 57);
  if (!isUuidV4Bytes(deviceIdBytes)) {
    throw new DeviceCertError('INVALID_CERT_DEVICE_UUID', 'device_id no es UUIDv4 válido');
  }

  const pkDev = raw.subarray(57, 89);
  const issuedAtSec = Number(raw.readBigUInt64BE(89));
  const expiresAtSec = Number(raw.readBigUInt64BE(97));

  if (expiresAtSec <= issuedAtSec) {
    throw new DeviceCertError('INVALID_CERT_TIMESTAMPS', 'expires_at debe ser mayor que issued_at');
  }
  if (issuedAtSec > nowUnixSec + 300) {
    throw new DeviceCertError('CERT_ISSUED_IN_FUTURE', 'DeviceCert emitido en el futuro');
  }
  if (expiresAtSec <= nowUnixSec) {
    throw new DeviceCertError('CERT_EXPIRED', 'DeviceCert expirado');
  }

  const body = raw.subarray(0, DEVICE_CERT_BODY_LEN);
  const sigRoot = raw.subarray(DEVICE_CERT_BODY_LEN, DEVICE_CERT_LEN);
  const signedMsg = Buffer.concat([DOMAIN_DEVICECERT, body]);

  if (!verifyEd25519(pkRoot, signedMsg, sigRoot)) {
    throw new DeviceCertError('INVALID_CERT_SIGNATURE', 'Firma Ed25519 de DeviceCert inválida');
  }

  return {
    version,
    pin,
    pkRoot,
    deviceId: formatUuidLower(deviceIdBytes),
    deviceIdBytes,
    pkDev,
    issuedAtSec,
    expiresAtSec,
    sigRoot,
  };
}
