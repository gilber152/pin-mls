import { createHash, timingSafeEqual } from 'node:crypto';

export const LINK_SESSION_DOMAIN = Buffer.from('pin-link-session-v1', 'ascii');
export const SESSION_ID_HEX_RE = /^[0-9a-f]{64}$/;
export const B64URL_32B_RE = /^[A-Za-z0-9_-]{43}$/;
const B64URL_16B_RE = /^[A-Za-z0-9_-]{22}$/;

export interface ParsedLinkQr {
  sessionId32: Buffer;
  sessionIdHex: string;
  deviceId16: Buffer;
  deviceIdUuid: string;
  pkDev32: Buffer;
  pkLinkEph32: Buffer;
}

export class LinkQrError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'LinkQrError';
  }
}

function isUuidV4Bytes(buf: Uint8Array): boolean {
  return buf.byteLength === 16 && (buf[6] & 0xf0) === 0x40 && (buf[8] & 0xc0) === 0x80;
}

function formatUuidLower(buf: Buffer): string {
  const h = buf.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export function deriveLinkSessionIdBytes(readSecret32: Uint8Array): Buffer {
  if (readSecret32.byteLength !== 32) {
    throw new LinkQrError('INVALID_READ_SECRET_LENGTH', 'read_secret debe medir exactamente 32 bytes');
  }
  return createHash('sha256')
    .update(LINK_SESSION_DOMAIN)
    .update(readSecret32)
    .digest();
}

export function verifyLinkReadSecret(sessionIdHex: string, secretB64Url: string): boolean {
  if (!SESSION_ID_HEX_RE.test(sessionIdHex)) return false;
  if (!B64URL_32B_RE.test(secretB64Url)) return false;

  const readSecret32 = Buffer.from(secretB64Url, 'base64url');
  if (readSecret32.length !== 32) return false;

  const expectedId = deriveLinkSessionIdBytes(readSecret32);
  const suppliedId = Buffer.from(sessionIdHex, 'hex');
  return timingSafeEqual(expectedId, suppliedId);
}

export function parseLinkQrUri(uri: string): ParsedLinkQr {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new LinkQrError('INVALID_LINK_QR_URL', 'URI LinkQr malformada');
  }

  if (parsed.protocol !== 'pinapp:' || parsed.hostname !== 'v1' || parsed.pathname !== '/link') {
    throw new LinkQrError('INVALID_LINK_QR_PREFIX', 'Prefijo debe ser pinapp://v1/link');
  }

  const s = parsed.searchParams.get('s') ?? '';
  const d = parsed.searchParams.get('d') ?? '';
  const pk = parsed.searchParams.get('pk') ?? '';
  const ek = parsed.searchParams.get('ek') ?? '';

  if (!B64URL_32B_RE.test(s)) throw new LinkQrError('INVALID_SESSION_ID_PARAM', 'Parámetro s inválido');
  if (!B64URL_16B_RE.test(d)) throw new LinkQrError('INVALID_DEVICE_ID_PARAM', 'Parámetro d inválido');
  if (!B64URL_32B_RE.test(pk)) throw new LinkQrError('INVALID_PK_DEV_PARAM', 'Parámetro pk inválido');
  if (!B64URL_32B_RE.test(ek)) throw new LinkQrError('INVALID_PK_LINK_EPH_PARAM', 'Parámetro ek inválido');

  const sessionId32 = Buffer.from(s, 'base64url');
  const deviceId16 = Buffer.from(d, 'base64url');
  const pkDev32 = Buffer.from(pk, 'base64url');
  const pkLinkEph32 = Buffer.from(ek, 'base64url');

  if (
    sessionId32.length !== 32 ||
    deviceId16.length !== 16 ||
    pkDev32.length !== 32 ||
    pkLinkEph32.length !== 32
  ) {
    throw new LinkQrError('INVALID_LINK_QR_BYTE_LENGTH', 'Longitud binaria inválida en LinkQr');
  }
  if (!isUuidV4Bytes(deviceId16)) {
    throw new LinkQrError('INVALID_DEVICE_UUID_V4', 'device_id en LinkQr no es UUIDv4 válido');
  }

  return {
    sessionId32,
    sessionIdHex: sessionId32.toString('hex'),
    deviceId16,
    deviceIdUuid: formatUuidLower(deviceId16),
    pkDev32,
    pkLinkEph32,
  };
}
