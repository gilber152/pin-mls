import fp from 'fastify-plugin';
import type { FastifyPluginAsync, FastifyReply, FastifyRequest, preHandlerHookHandler } from 'fastify';
import { pool } from '../infra/db.js';
import { cmdRedis } from '../infra/redis.js';
import { sha256Hex, verifyEd25519 } from '../infra/crypto.js';
import type { VerifyEd25519Options } from './authTypes.js';
import './authTypes.js';

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PIN_CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]{8}$/;

const MAX_CLOCK_SKEW_SEC = 300;
const NONCE_REPLAY_TTL_SEC = 360;
const DEVICE_PK_CACHE_TTL_SEC = 60;

interface CachedDeviceKey {
  pin: string;
  pkDevHex: string;
  certExpiresAtSec: number;
}

function getSingleHeader(req: FastifyRequest, name: string): string | null {
  const value = req.headers[name];
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function buildCanonicalPayload(
  method: string,
  url: string,
  timestampStr: string,
  nonce: string,
  rawBody: Buffer,
): Buffer {
  const bodyHashHex = sha256Hex(rawBody);
  return Buffer.from(
    `ed25519-http-v1\n${method.toUpperCase()}\n${url}\n${timestampStr}\n${nonce}\n${bodyHashHex}`,
    'utf8',
  );
}

async function resolveActiveDeviceKey(
  deviceId: string,
  nowSec: number,
): Promise<{ pin: string; pkDev: Buffer } | null> {
  const cacheKey = `pk:device:${deviceId}`;

  const cachedRaw = await cmdRedis.get(cacheKey);
  if (cachedRaw) {
    try {
      const parsed = JSON.parse(cachedRaw) as CachedDeviceKey;
      if (parsed.certExpiresAtSec > nowSec) {
        return {
          pin: parsed.pin,
          pkDev: Buffer.from(parsed.pkDevHex, 'hex'),
        };
      }
      await cmdRedis.del(cacheKey);
      return null;
    } catch {
      await cmdRedis.del(cacheKey);
    }
  }

  const { rows } = await pool.query<{
    pin: string;
    pk_dev: Buffer;
    cert_expires_at: Date;
  }>(
    `SELECT pin, pk_dev, cert_expires_at
     FROM devices
     WHERE device_id = $1
       AND status = 'active'
       AND cert_expires_at > NOW()`,
    [deviceId],
  );

  if (rows.length === 0) return null;

  const row = rows[0];
  const certExpiresAtSec = Math.floor(row.cert_expires_at.getTime() / 1000);
  if (certExpiresAtSec <= nowSec) return null;

  const cacheTtl = Math.min(DEVICE_PK_CACHE_TTL_SEC, Math.max(1, certExpiresAtSec - nowSec));
  const payload: CachedDeviceKey = {
    pin: row.pin,
    pkDevHex: row.pk_dev.toString('hex'),
    certExpiresAtSec,
  };
  await cmdRedis.set(cacheKey, JSON.stringify(payload), 'EX', cacheTtl);

  return { pin: row.pin, pkDev: row.pk_dev };
}

async function resolveRootKey(pin: string): Promise<Buffer | null> {
  const { rows } = await pool.query<{ pk_root: Buffer }>(
    `SELECT pk_root FROM identities WHERE pin = $1`,
    [pin],
  );
  return rows.length > 0 ? rows[0].pk_root : null;
}

const ed25519AuthPlugin: FastifyPluginAsync = async (fastify) => {
  if (!fastify.hasRequestDecorator('auth')) {
    fastify.decorateRequest('auth', undefined);
  }

  function createVerifier(opts: VerifyEd25519Options): preHandlerHookHandler {
    return async function verifyEd25519Handler(
      req: FastifyRequest,
      reply: FastifyReply,
    ): Promise<void> {
      const tsStr = getSingleHeader(req, 'x-timestamp');
      const nonce = getSingleHeader(req, 'x-nonce');
      const sigB64Url = getSingleHeader(req, 'x-signature');

      if (!tsStr || !nonce || !sigB64Url) {
        return reply.code(401).send({ error: 'MISSING_ED25519_AUTH_HEADERS' });
      }
      if (!/^\d{10,12}$/.test(tsStr)) {
        return reply.code(401).send({ error: 'INVALID_TIMESTAMP_FORMAT' });
      }
      if (!UUID_V4_RE.test(nonce)) {
        return reply.code(401).send({ error: 'INVALID_NONCE_UUID' });
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const reqTs = Number.parseInt(tsStr, 10);
      if (Math.abs(nowSec - reqTs) > MAX_CLOCK_SKEW_SEC) {
        return reply.code(401).send({ error: 'TIMESTAMP_OUT_OF_WINDOW' });
      }

      const signature64 = Buffer.from(sigB64Url, 'base64url');
      if (signature64.length !== 64) {
        return reply.code(401).send({ error: 'INVALID_SIGNATURE_LENGTH' });
      }

      const rawBody = Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.alloc(0);
      const canonical = buildCanonicalPayload(req.method, req.url, tsStr, nonce, rawBody);

      if (opts.keyType === 'root') {
        const pinHeader = getSingleHeader(req, 'x-pin')?.toUpperCase();
        if (!pinHeader || !PIN_CROCKFORD_RE.test(pinHeader)) {
          return reply.code(401).send({ error: 'INVALID_X_PIN_HEADER' });
        }

        const pkRoot = await resolveRootKey(pinHeader);
        if (!pkRoot) {
          return reply.code(401).send({ error: 'UNKNOWN_IDENTITY' });
        }

        if (!verifyEd25519(pkRoot, canonical, signature64)) {
          return reply.code(401).send({ error: 'INVALID_ROOT_SIGNATURE' });
        }

        const nonceKey = `nonce:ed25519:root:${pinHeader}:${nonce.toLowerCase()}`;
        const claimed = await cmdRedis.set(nonceKey, '1', 'EX', NONCE_REPLAY_TTL_SEC, 'NX');
        if (claimed !== 'OK') {
          return reply.code(401).send({ error: 'REPLAYED_NONCE' });
        }

        req.auth = { authType: 'ed25519_root', pin: pinHeader };
        return;
      }

      const deviceId = getSingleHeader(req, 'x-device-id')?.toLowerCase();
      if (!deviceId || !UUID_V4_RE.test(deviceId)) {
        return reply.code(401).send({ error: 'INVALID_X_DEVICE_ID_HEADER' });
      }

      const resolved = await resolveActiveDeviceKey(deviceId, nowSec);
      if (!resolved) {
        return reply.code(401).send({ error: 'DEVICE_REVOKED' });
      }

      if (!verifyEd25519(resolved.pkDev, canonical, signature64)) {
        return reply.code(401).send({ error: 'INVALID_DEVICE_SIGNATURE' });
      }

      const nonceKey = `nonce:ed25519:dev:${deviceId}:${nonce.toLowerCase()}`;
      const claimed = await cmdRedis.set(nonceKey, '1', 'EX', NONCE_REPLAY_TTL_SEC, 'NX');
      if (claimed !== 'OK') {
        return reply.code(401).send({ error: 'REPLAYED_NONCE' });
      }

      req.auth = { authType: 'ed25519_device', pin: resolved.pin, deviceId };
    };
  }

  fastify.decorate('verifyEd25519', createVerifier);
};

export default fp(ed25519AuthPlugin, {
  name: 'pin-ed25519-auth',
  fastify: '5.x',
  dependencies: ['pin-raw-body'],
});
