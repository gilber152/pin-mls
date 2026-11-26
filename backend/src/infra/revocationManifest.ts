import { verifyEd25519 } from './crypto.js';

export const REVOCATION_MANIFEST_VERSION = 1;
export const REVOCATION_MANIFEST_HEADER_LEN = 19;
export const REVOCATION_MANIFEST_SIG_LEN = 64;
export const MAX_REVOKED_DEVICES_PER_MANIFEST = 256;

const DOMAIN_REVMANIFEST = Buffer.from('revmanifest-v1', 'ascii');
const PIN_CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]{8}$/;

export interface ParsedRevocationManifest {
  version: number;
  pin: string;
  seqNum: bigint;
  revokedDeviceIds: string[];
  manifestRaw: Buffer;
  sigRoot: Buffer;
}

export class RevocationManifestError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'RevocationManifestError';
  }
}

function isUuidV4Bytes(buf: Uint8Array): boolean {
  return buf.byteLength === 16 && (buf[6] & 0xf0) === 0x40 && (buf[8] & 0xc0) === 0x80;
}

function formatUuidLower(buf: Buffer): string {
  const h = buf.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export function parseAndVerifyRevocationManifest(
  wire: Buffer,
  expectedPin: string,
  pkRoot32: Uint8Array,
): ParsedRevocationManifest {
  if (!PIN_CROCKFORD_RE.test(expectedPin)) {
    throw new RevocationManifestError('INVALID_EXPECTED_PIN', 'PIN esperado inválido');
  }
  if (pkRoot32.byteLength !== 32) {
    throw new RevocationManifestError('INVALID_PK_ROOT', 'pk_root debe medir exactamente 32 bytes');
  }

  const minLen = REVOCATION_MANIFEST_HEADER_LEN + 16 + REVOCATION_MANIFEST_SIG_LEN;
  const maxLen =
    REVOCATION_MANIFEST_HEADER_LEN +
    MAX_REVOKED_DEVICES_PER_MANIFEST * 16 +
    REVOCATION_MANIFEST_SIG_LEN;

  if (wire.length < minLen || wire.length > maxLen) {
    throw new RevocationManifestError(
      'INVALID_MANIFEST_LENGTH',
      `Longitud de manifiesto fuera de rango: ${wire.length}`,
    );
  }

  const splitAt = wire.length - REVOCATION_MANIFEST_SIG_LEN;
  const manifestRaw = wire.subarray(0, splitAt);
  const sigRoot = wire.subarray(splitAt);

  const version = manifestRaw[0];
  if (version !== REVOCATION_MANIFEST_VERSION) {
    throw new RevocationManifestError(
      'UNSUPPORTED_MANIFEST_VERSION',
      `Versión no soportada: ${version}`,
    );
  }

  const pin = manifestRaw.subarray(1, 9).toString('ascii');
  if (!PIN_CROCKFORD_RE.test(pin) || pin !== expectedPin) {
    throw new RevocationManifestError('MANIFEST_PIN_MISMATCH', 'El PIN del manifiesto no coincide');
  }

  const seqNum = manifestRaw.readBigUInt64BE(9);
  if (seqNum <= 0n) {
    throw new RevocationManifestError('INVALID_MANIFEST_SEQ', 'seq_num debe ser mayor que 0');
  }

  const count = manifestRaw.readUInt16BE(17);
  if (count === 0 || count > MAX_REVOKED_DEVICES_PER_MANIFEST) {
    throw new RevocationManifestError(
      'INVALID_MANIFEST_COUNT',
      `Cantidad de dispositivos fuera de rango: ${count}`,
    );
  }

  const expectedBodyLen = REVOCATION_MANIFEST_HEADER_LEN + count * 16;
  if (manifestRaw.length !== expectedBodyLen) {
    throw new RevocationManifestError(
      'MANIFEST_BODY_LENGTH_MISMATCH',
      `Cuerpo mide ${manifestRaw.length}B, esperado ${expectedBodyLen}B`,
    );
  }

  const revokedDeviceIds: string[] = [];
  let prevUuid: Buffer | null = null;

  for (let i = 0; i < count; i += 1) {
    const start = REVOCATION_MANIFEST_HEADER_LEN + i * 16;
    const uuidBuf = manifestRaw.subarray(start, start + 16);

    if (!isUuidV4Bytes(uuidBuf)) {
      throw new RevocationManifestError(
        'INVALID_REVOKED_UUID_V4',
        `El elemento ${i} no es un UUIDv4 válido`,
      );
    }

    if (prevUuid !== null && Buffer.compare(prevUuid, uuidBuf) >= 0) {
      throw new RevocationManifestError(
        'UNSORTED_OR_DUPLICATE_UUIDS',
        'Los UUIDs deben estar estrictamente ordenados lexicográficamente sin duplicados',
      );
    }

    prevUuid = uuidBuf;
    revokedDeviceIds.push(formatUuidLower(uuidBuf));
  }

  const signedMsg = Buffer.concat([DOMAIN_REVMANIFEST, manifestRaw]);
  if (!verifyEd25519(pkRoot32, signedMsg, sigRoot)) {
    throw new RevocationManifestError(
      'INVALID_MANIFEST_SIGNATURE',
      'Firma Ed25519 revmanifest-v1 inválida',
    );
  }

  return {
    version,
    pin,
    seqNum,
    revokedDeviceIds,
    manifestRaw,
    sigRoot,
  };
}
