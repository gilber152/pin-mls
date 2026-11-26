import type { IncomingMessage } from 'node:http';
import { importSPKI, type KeyLike } from 'jose';
import { env } from '../../config/env.js';
import { cmdRedis } from '../../infra/redis.js';
import { verifyAccessJwt } from '../../plugins/jwtAuth.js';

export const WS_TICKET_PREFIX = 'ws:ticket:';
export const WS_TICKET_TTL_SEC = 15;

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PIN_CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]{8}$/;
const WS_TICKET_RE = /^[A-Za-z0-9_-]{32,128}$/;

export type WsAuthResult =
  | {
      ok: true;
      deviceId: string;
      pin: string;
      authMethod: 'bearer' | 'ticket';
      origin: string | null;
    }
  | {
      ok: false;
      statusCode: 400 | 401 | 403;
      error: string;
    };

interface StoredWsTicket {
  deviceId: string;
  pin: string;
}

function parseAllowedOrigins(raw: string | readonly string[]): Set<string> {
  const items = typeof raw === 'string' ? raw.split(',') : raw;
  const origins = new Set<string>();
  for (const item of items) {
    const trimmed = item.trim();
    if (!trimmed) continue;
    try {
      origins.add(new URL(trimmed).origin);
    } catch {
      // ignore invalid origin config
    }
  }
  return origins;
}

function getSingleHeader(req: IncomingMessage, name: string): string | null {
  const value = req.headers[name];
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function extractBearerToken(req: IncomingMessage): string | null {
  const header = getSingleHeader(req, 'authorization');
  if (!header) return null;
  const spaceIdx = header.indexOf(' ');
  if (spaceIdx === -1) return null;
  const scheme = header.slice(0, spaceIdx);
  const token = header.slice(spaceIdx + 1).trim();
  if (scheme.toLowerCase() !== 'bearer' || token.length < 20) return null;
  return token;
}

export async function createWsUpgradeAuthenticator(): Promise<
  (req: IncomingMessage) => Promise<WsAuthResult>
> {
  const jwtPublicKey: KeyLike = await importSPKI(env.JWT_PUBLIC_KEY_PEM, 'EdDSA');
  const allowedOrigins = parseAllowedOrigins(env.ALLOWED_WEB_ORIGINS);

  return async function authenticateWsUpgrade(req: IncomingMessage): Promise<WsAuthResult> {
    const rawOrigin = req.headers.origin;
    if (Array.isArray(rawOrigin)) {
      return { ok: false, statusCode: 400, error: 'DUPLICATE_ORIGIN_HEADER' };
    }

    let normalizedOrigin: string | null = null;
    if (typeof rawOrigin === 'string') {
      const trimmedOrigin = rawOrigin.trim();
      if (!trimmedOrigin || trimmedOrigin.toLowerCase() === 'null') {
        return { ok: false, statusCode: 403, error: 'ORIGIN_NOT_ALLOWED' };
      }
      try {
        normalizedOrigin = new URL(trimmedOrigin).origin;
      } catch {
        return { ok: false, statusCode: 403, error: 'INVALID_ORIGIN_HEADER' };
      }
      if (!allowedOrigins.has(normalizedOrigin)) {
        return { ok: false, statusCode: 403, error: 'ORIGIN_NOT_ALLOWED' };
      }
    }

    const bearerToken = extractBearerToken(req);
    if (bearerToken) {
      const claims = await verifyAccessJwt(bearerToken, jwtPublicKey);
      if (!claims) {
        return { ok: false, statusCode: 401, error: 'INVALID_OR_REVOKED_JWT' };
      }
      return {
        ok: true,
        deviceId: claims.deviceId.toLowerCase(),
        pin: claims.pin,
        authMethod: 'bearer',
        origin: normalizedOrigin,
      };
    }

    let ticket: string | null = null;
    try {
      const parsedUrl = new URL(req.url ?? '/', 'http://localhost');
      ticket = parsedUrl.searchParams.get('ticket');
    } catch {
      return { ok: false, statusCode: 400, error: 'INVALID_REQUEST_URL' };
    }

    if (!ticket) return { ok: false, statusCode: 401, error: 'MISSING_WS_CREDENTIALS' };
    if (!WS_TICKET_RE.test(ticket)) return { ok: false, statusCode: 401, error: 'INVALID_WS_TICKET_FORMAT' };

    const rawTicketPayload = await cmdRedis.getdel(`${WS_TICKET_PREFIX}${ticket}`);
    if (!rawTicketPayload) return { ok: false, statusCode: 401, error: 'INVALID_OR_EXPIRED_WS_TICKET' };

    let parsedTicket: StoredWsTicket;
    try {
      parsedTicket = JSON.parse(rawTicketPayload) as StoredWsTicket;
    } catch {
      return { ok: false, statusCode: 401, error: 'CORRUPT_WS_TICKET' };
    }

    const deviceId = typeof parsedTicket.deviceId === 'string' ? parsedTicket.deviceId.toLowerCase() : '';
    const pin = typeof parsedTicket.pin === 'string' ? parsedTicket.pin.toUpperCase() : '';
    if (!UUID_V4_RE.test(deviceId) || !PIN_CROCKFORD_RE.test(pin)) {
      return { ok: false, statusCode: 401, error: 'INVALID_WS_TICKET_CLAIMS' };
    }

    const isRevoked = await cmdRedis.exists(`revoked:dev:${deviceId}`);
    if (isRevoked === 1) {
      return { ok: false, statusCode: 401, error: 'DEVICE_REVOKED' };
    }

    return { ok: true, deviceId, pin, authMethod: 'ticket', origin: normalizedOrigin };
  };
}
