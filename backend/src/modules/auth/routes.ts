import { randomBytes } from 'node:crypto';
import { importPKCS8, SignJWT, type KeyLike } from 'jose';
import type { FastifyInstance } from 'fastify';
import { env } from '../../config/env.js';
import { pool } from '../../infra/db.js';
import { cmdRedis } from '../../infra/redis.js';
import { WS_TICKET_PREFIX, WS_TICKET_TTL_SEC } from '../ws/auth.js';

const JWT_ISSUER = 'pin-mls-ds';
const JWT_AUDIENCE = 'pin-mls-client';
const JWT_TTL_SEC = 15 * 60;
const CERT_RENEW_NOTICE_WINDOW_SEC = 30 * 24 * 3600;

const TOKEN_RL_MAX = 20;
const TOKEN_RL_WINDOW_SEC = 600;
const TICKET_RL_MAX = 30;
const TICKET_RL_WINDOW_SEC = 60;

export async function registerAuthRoutes(fastify: FastifyInstance): Promise<void> {
  const jwtPrivateKey: KeyLike = await importPKCS8(env.JWT_PRIVATE_KEY_PEM, 'EdDSA');

  fastify.post(
    '/v1/auth/token',
    { preHandler: [fastify.verifyEd25519({ keyType: 'device' })] },
    async (req, reply) => {
      const deviceId = req.auth!.deviceId!;
      const pin = req.auth!.pin;

      const rlKey = `rl:auth_token:${deviceId}`;
      const hits = await cmdRedis.incr(rlKey);
      if (hits === 1) await cmdRedis.expire(rlKey, TOKEN_RL_WINDOW_SEC);
      if (hits > TOKEN_RL_MAX) {
        return reply
          .code(429)
          .header('Retry-After', String(TOKEN_RL_WINDOW_SEC))
          .send({ error: 'AUTH_TOKEN_RATE_LIMITED' });
      }

      const { rows } = await pool.query<{
        pin: string;
        status: 'active' | 'revoked';
        cert_expires_at: Date;
      }>(
        `SELECT pin, status, cert_expires_at FROM devices WHERE device_id = $1`,
        [deviceId],
      );

      if (rows.length === 0) return reply.code(401).send({ error: 'DEVICE_NOT_FOUND' });

      const device = rows[0];
      if (device.status !== 'active' || device.pin !== pin) {
        return reply.code(401).send({ error: 'DEVICE_REVOKED' });
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const certExpiresAtSec = Math.floor(device.cert_expires_at.getTime() / 1000);
      if (certExpiresAtSec <= nowSec) {
        return reply.code(401).send({ error: 'DEVICE_CERT_EXPIRED' });
      }

      const expiresAtSec = Math.min(nowSec + JWT_TTL_SEC, certExpiresAtSec);
      const renewCertRecommended = certExpiresAtSec - nowSec <= CERT_RENEW_NOTICE_WINDOW_SEC;

      const accessToken = await new SignJWT({ pin: device.pin })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: env.JWT_KEY_ID })
        .setIssuer(JWT_ISSUER)
        .setAudience(JWT_AUDIENCE)
        .setSubject(deviceId)
        .setIssuedAt(nowSec)
        .setExpirationTime(expiresAtSec)
        .sign(jwtPrivateKey);

      return reply
        .code(200)
        .header('Cache-Control', 'no-store')
        .send({
          accessToken,
          expiresAtSec,
          expiresInSec: Math.max(1, expiresAtSec - nowSec),
          renewCertRecommended,
        });
    },
  );

  fastify.post(
    '/v1/auth/ws-ticket',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const deviceId = req.auth!.deviceId!;
      const pin = req.auth!.pin;

      const rlKey = `rl:ws_ticket:${deviceId}`;
      const hits = await cmdRedis.incr(rlKey);
      if (hits === 1) await cmdRedis.expire(rlKey, TICKET_RL_WINDOW_SEC);
      if (hits > TICKET_RL_MAX) {
        return reply
          .code(429)
          .header('Retry-After', String(TICKET_RL_WINDOW_SEC))
          .send({ error: 'WS_TICKET_RATE_LIMITED' });
      }

      const ticket = randomBytes(32).toString('base64url');
      await cmdRedis.set(
        `${WS_TICKET_PREFIX}${ticket}`,
        JSON.stringify({ deviceId, pin }),
        'EX',
        WS_TICKET_TTL_SEC,
      );

      return reply
        .code(201)
        .header('Cache-Control', 'no-store')
        .send({ ticket, expiresInSec: WS_TICKET_TTL_SEC });
    },
  );
}
